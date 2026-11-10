//! vs-sandbox: run ONE command (a model-written PoC) confined by gateway-exec's `confine()`.
//!
//!   vs-sandbox --rw <workspace> [--ro <path>]... [--cpu-s 60] [--mem-mb 4096] [--nproc 64]
//!              [--fsize-mb 64] [--wall-s 120] [--env K=V]... --status <file> -- <cmd> [args...]
//!
//! Process-count and total-memory caps belong to a cgroup: callers wrap this in
//! `systemd-run --user --scope -p TasksMax=.. -p MemoryMax=..` (RLIMIT_NPROC is per-UID, so it would count the
//! user's other processes; RLIMIT_AS breaks V8). --mem-mb/--nproc stay available but default to off.
//! The child: new process group, rlimits, cleared environment (only --env), chdir to the workspace, then
//! Landlock (ro/rw paths only) + no_new_privs + seccomp (no inet sockets, no ptrace/mount/...), then execve.
//! The parent enforces the wall clock (SIGKILL to the whole group) and writes one JSON status line to --status:
//!   {"exit": <code|null>, "signal": <n|null>, "timed_out": bool, "wall_ms": n}
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

struct Args {
    ro: Vec<PathBuf>,
    rw: Vec<PathBuf>,
    cpu_s: u64,
    mem_mb: u64,
    nproc: u64,
    fsize_mb: u64,
    wall_s: u64,
    env: Vec<String>,
    status: PathBuf,
    cmd: Vec<String>,
}

fn parse() -> Result<Args> {
    let mut a = Args { ro: vec![], rw: vec![], cpu_s: 60, mem_mb: 0, nproc: 0, fsize_mb: 64, wall_s: 120,
                       env: vec![], status: PathBuf::new(), cmd: vec![] };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().with_context(|| format!("{k} needs a value"));
        match k.as_str() {
            "--ro" => a.ro.push(val()?.into()),
            "--rw" => a.rw.push(val()?.into()),
            "--cpu-s" => a.cpu_s = val()?.parse()?,
            "--mem-mb" => a.mem_mb = val()?.parse()?,
            "--nproc" => a.nproc = val()?.parse()?,
            "--fsize-mb" => a.fsize_mb = val()?.parse()?,
            "--wall-s" => a.wall_s = val()?.parse()?,
            "--env" => a.env.push(val()?),
            "--status" => a.status = val()?.into(),
            "--" => { a.cmd = it.collect(); break; }
            other => bail!("unknown argument {other}"),
        }
    }
    if a.rw.is_empty() || a.cmd.is_empty() || a.status.as_os_str().is_empty() {
        bail!("need --rw <workspace>, --status <file> and -- <cmd>");
    }
    Ok(a)
}

fn rlimit(res: libc::__rlimit_resource_t, v: u64) {
    let r = libc::rlimit { rlim_cur: v as libc::rlim_t, rlim_max: v as libc::rlim_t };
    unsafe { libc::setrlimit(res, &r) };
}

fn child(a: &Args) -> ! {
    unsafe { libc::setpgid(0, 0) };
    rlimit(libc::RLIMIT_CPU, a.cpu_s);
    if a.mem_mb > 0 { rlimit(libc::RLIMIT_AS, a.mem_mb << 20); }
    if a.nproc > 0 { rlimit(libc::RLIMIT_NPROC, a.nproc); } // per-UID: off by default, use a cgroup
    rlimit(libc::RLIMIT_FSIZE, a.fsize_mb << 20);
    rlimit(libc::RLIMIT_CORE, 0);
    if std::env::set_current_dir(&a.rw[0]).is_err() { std::process::exit(126); }
    let spec = gateway_exec::SandboxSpec { ro_paths: a.ro.clone(), rw_paths: a.rw.clone() };
    if let Err(e) = gateway_exec::confine(&spec) {
        eprintln!("vs-sandbox: confinement failed: {e:#}");
        std::process::exit(125);
    }
    let prog = CString::new(a.cmd[0].clone()).unwrap();
    let argv: Vec<CString> = a.cmd.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
    let envp: Vec<CString> = a.env.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
    let mut argv_p: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let mut envp_p: Vec<*const libc::c_char> = envp.iter().map(|c| c.as_ptr()).collect();
    envp_p.push(std::ptr::null());
    unsafe { libc::execve(prog.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr()) };
    eprintln!("vs-sandbox: execve {} failed: {}", a.cmd[0], std::io::Error::last_os_error());
    std::process::exit(127);
}

fn main() -> Result<()> {
    let a = parse()?;
    let start = Instant::now();
    let pid = unsafe { libc::fork() };
    if pid < 0 { bail!("fork failed"); }
    if pid == 0 { child(&a); }
    unsafe { libc::setpgid(pid, pid) };
    let deadline = Duration::from_secs(a.wall_s);
    let (mut exit, mut signal, mut timed_out) = (None, None, false);
    loop {
        let mut st: libc::c_int = 0;
        let r = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
        if r == pid {
            if libc::WIFEXITED(st) { exit = Some(libc::WEXITSTATUS(st)); }
            if libc::WIFSIGNALED(st) { signal = Some(libc::WTERMSIG(st)); }
            break;
        }
        if start.elapsed() > deadline {
            timed_out = true;
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            unsafe { libc::waitpid(pid, &mut st, 0) };
            signal = Some(libc::SIGKILL);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    unsafe { libc::kill(-pid, libc::SIGKILL) }; // reap stragglers in the group
    let status = serde_json::json!({"exit": exit, "signal": signal, "timed_out": timed_out,
                                    "wall_ms": start.elapsed().as_millis() as u64});
    std::fs::write(&a.status, format!("{status}\n")).context("write status")?;
    Ok(())
}
