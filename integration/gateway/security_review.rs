//! `security_review` tool: run the frozen vulnscan reviewer over a local git repository.
//!
//! Read tier, local only: it calls the vulnscan CLI (local vLLM, no network egress) as a subprocess with an
//! argument vector (no shell). The repository must be a git checkout under an allowed root. The report quotes
//! code from that repository, which may be third-party and may contain prompt-injection text, so the manifest
//! marks this tool `accepts_untrusted_input` (a call taints the session to read-only, like web_fetch).
//! vulnscan itself never executes code from the reviewed repository and hardens its git calls.
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const VULNSCAN_ROOT: &str = "/srv/gateway/vulnscan";
const ALLOWED_ROOTS: &[&str] = &["/home/adamrel", "/srv/gateway"];
const MAX_BATCHES: usize = 8;
const REPORT_CAP: usize = 20_000;
const TIMEOUT: Duration = Duration::from_secs(90 * 60);

/// Absolute, existing, a git checkout, and inside an allowed root (after resolving symlinks).
pub fn validate_repo(raw: &str) -> Result<PathBuf> {
    let p = Path::new(raw.trim());
    if !p.is_absolute() {
        bail!("security_review: repo must be an absolute path");
    }
    let real = std::fs::canonicalize(p).with_context(|| format!("security_review: no such path {raw}"))?;
    if !ALLOWED_ROOTS.iter().any(|r| real.starts_with(r)) {
        bail!("security_review: repo must be under {}", ALLOWED_ROOTS.join(" or "));
    }
    if !real.join(".git").exists() {
        bail!("security_review: {} is not a git checkout", real.display());
    }
    Ok(real)
}

/// Commit ranges like `main..feature` or `abc123..HEAD`: refname characters only, so nothing reaches git as an option.
pub fn validate_range(r: &str) -> Result<String> {
    let r = r.trim();
    let ok = !r.is_empty() && !r.starts_with('-') && r.len() <= 200
        && r.chars().all(|c| c.is_ascii_alphanumeric() || "._/-~^@".contains(c));
    if !ok {
        bail!("security_review: range must look like base..head (refnames only)");
    }
    Ok(r.to_string())
}

fn cli_args(repo: &Path, args: &Value) -> Result<Vec<String>> {
    let mut v = vec![format!("{VULNSCAN_ROOT}/scripts/vulnscan.py"), "review".into(), repo.display().to_string()];
    let all = args.get("all").and_then(|x| x.as_bool()).unwrap_or(false);
    match args.get("range").and_then(|x| x.as_str()).filter(|s| !s.trim().is_empty()) {
        Some(r) if !all => v.push(validate_range(r)?),
        _ if all => v.push("--all".into()),
        _ => bail!("security_review: give range (e.g. main..feature) or all=true"),
    }
    if let Some(paths) = args.get("paths").and_then(|x| x.as_array()) {
        for p in paths.iter().filter_map(|x| x.as_str()).take(10) {
            if p.starts_with('-') || p.contains("..") {
                bail!("security_review: invalid path filter {p}");
            }
            v.push("--path".into());
            v.push(p.to_string());
        }
    }
    Ok(v)
}

async fn vulnscan(argv: &[String]) -> Result<std::process::Output> {
    let fut = tokio::process::Command::new(format!("{VULNSCAN_ROOT}/.venv/bin/python"))
        .arg("-I")
        .args(argv)
        .current_dir(VULNSCAN_ROOT)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/home/adamrel")
        .kill_on_drop(true)
        .output();
    tokio::time::timeout(TIMEOUT, fut).await.context("security_review: timed out")?.context("spawn vulnscan")
}

pub async fn run(args: &Value) -> Result<String> {
    let repo = validate_repo(args.get("repo").and_then(|x| x.as_str()).unwrap_or(""))?;
    let mut argv = cli_args(&repo, args)?;
    // Size check first: refuse reviews that would take hours.
    let mut dry = argv.clone();
    dry.push("--dry-run".into());
    let out = vulnscan(&dry).await?;
    if !out.status.success() {
        bail!("security_review: {}", String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("dry run failed"));
    }
    let batches = String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.starts_with("review:")).count();
    if batches == 0 {
        return Ok("security_review: no reviewable source changes in that range.".into());
    }
    if batches > MAX_BATCHES {
        bail!("security_review: {batches} batches is too large (max {MAX_BATCHES}); narrow it with paths=[...] or a smaller range");
    }
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let outdir = format!("{VULNSCAN_ROOT}/results/gateway-reviews/{stamp}");
    argv.push("--out".into());
    argv.push(outdir.clone());
    let out = vulnscan(&argv).await?;
    if !out.status.success() {
        bail!("security_review failed: {}", String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or(""));
    }
    let mut report = std::fs::read_to_string(format!("{outdir}/report.md")).context("read report")?;
    if report.len() > REPORT_CAP {
        let cut = (0..=REPORT_CAP).rev().find(|&i| report.is_char_boundary(i)).unwrap_or(0);
        report.truncate(cut);
        report.push_str(&format!("\n\n[truncated; full report and JSON at {outdir}]"));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_validation() {
        assert!(validate_range("main..feature").is_ok());
        assert!(validate_range("abc123..HEAD~2").is_ok());
        assert!(validate_range("--output=/tmp/x").is_err());
        assert!(validate_range("a..b; rm -rf /").is_err());
        assert!(validate_range("").is_err());
    }

    #[test]
    fn repo_validation() {
        assert!(validate_repo("relative/path").is_err());
        assert!(validate_repo("/etc").is_err());
        assert!(validate_repo("/srv/gateway/gateway").is_ok());
    }

    #[test]
    fn args_need_range_or_all() {
        let repo = Path::new("/srv/gateway/gateway");
        assert!(cli_args(repo, &serde_json::json!({})).is_err());
        assert!(cli_args(repo, &serde_json::json!({"all": true})).unwrap().contains(&"--all".to_string()));
        assert!(cli_args(repo, &serde_json::json!({"range": "a..b", "paths": ["../x"]})).is_err());
    }
}

#[cfg(test)]
mod e2e {
    /// Opt-in: `cargo test -p gateway-core security_review_e2e -- --ignored` (needs local vLLM; minutes).
    #[tokio::test]
    #[ignore]
    async fn security_review_e2e() {
        let r = super::run(&serde_json::json!({"repo": "/srv/gateway/vulnscan", "range": "HEAD~1..HEAD"})).await;
        let text = r.expect("review ran");
        assert!(text.contains("Security review") || text.contains("no reviewable source changes"), "{text}");
    }
}
