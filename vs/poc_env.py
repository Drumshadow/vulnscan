"""H15 V2: per-(repo, commit) environments for PoC runs, cached under data/poc-envs/.

Built OUTSIDE the sandbox (needs the package registries), with no install-time code execution:
  Python: uv venv + `uv pip install --only-binary :all:` per declared dependency (wheels only; a dependency
          without a wheel is skipped and logged). The project itself is never built: its source is on PYTHONPATH.
  JS/TS:  `npm install --ignore-scripts --omit=dev` with the bundled node. TS runs via Node 22 type stripping.
The PoC later runs INSIDE vs-sandbox with these paths read-only.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import tomllib

from .bench import ROOT, repo_dir

ENVS = ROOT / "data" / "poc-envs"
UV = pathlib.Path.home() / ".local" / "bin" / "uv"
NODE_BIN = ROOT / "tools" / "node" / "bin"
PYTHON = "3.12"


def _key(item) -> str:
    return f"{item['repo'].strip('/').replace('/', '__')}@{item['head'][:16]}"


def _run(cmd, cwd=None, timeout=600, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)


def _py_deps(src: pathlib.Path) -> list[str]:
    deps: list[str] = []
    pp = src / "pyproject.toml"
    if pp.exists():
        try:
            data = tomllib.loads(pp.read_text())
            deps += data.get("project", {}).get("dependencies", []) or []
            poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
            deps += [k for k in poetry if k.lower() != "python"]  # names only; uv picks a wheel
        except (tomllib.TOMLDecodeError, AttributeError):
            pass
    for req in ("requirements.txt", "requirements/base.txt", "requirements/prod.txt"):
        f = src / req
        if f.exists():
            for line in f.read_text(errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                if line and not line.startswith(("-", "git+", "http")):
                    deps.append(line)
    # strip environment markers / extras-only syntax that uv handles anyway; dedupe by name
    seen, out = set(), []
    for d in deps:
        name = re.split(r"[\s<>=!~;\[]", d, 1)[0].lower()
        if name and name not in seen:
            seen.add(name); out.append(d)
    return out[:80]


def _py_paths(src: pathlib.Path) -> list[str]:
    paths = [str(src)]
    if (src / "src").is_dir():
        paths.insert(0, str(src / "src"))
    return paths


def ensure_env(item, rebuild: bool = False) -> dict:
    """Return {"lang", "src", "ro", "env", "python"|"node", "notes"}; builds and caches on first use."""
    d = ENVS / _key(item)
    meta_f = d / "env.json"
    if meta_f.exists() and not rebuild:
        return json.loads(meta_f.read_text())
    d.mkdir(parents=True, exist_ok=True)
    src = d / "src"
    if not src.exists():
        src.mkdir()
        arch = subprocess.run(["git", "-C", str(repo_dir(item["repo"])), "archive", item["head"]],
                              capture_output=True, timeout=1800)
        subprocess.run(["tar", "-x", "-C", str(src)], input=arch.stdout, check=True, timeout=600)
    py = any(f.endswith(".py") for f in item["files"])
    notes: list[str] = []
    if py:
        venv = d / "venv"
        if not venv.exists():
            r = _run([str(UV), "venv", "-q", "--python", PYTHON, str(venv)])
            if r.returncode != 0:
                notes.append(f"venv failed: {r.stderr[-200:]}")
        ok, skipped = [], []
        for dep in _py_deps(src):
            r = _run([str(UV), "pip", "install", "-q", "--python", str(venv / "bin" / "python"),
                      "--only-binary", ":all:", dep], timeout=300)
            (ok if r.returncode == 0 else skipped).append(dep)
        notes.append(f"python deps installed {len(ok)}, skipped {len(skipped)} (no wheel or unresolvable): {skipped[:10]}")
        meta = {"lang": "python", "src": str(src), "python": str(venv / "bin" / "python"),
                "ro": [str(src), str(venv), "/usr", "/lib", "/etc/ld.so.cache", "/etc/ssl", "/etc/localtime",
                       str(pathlib.Path.home() / ".local" / "share" / "uv" / "python")],
                "env": {"PYTHONPATH": ":".join(_py_paths(src)), "PYTHONDONTWRITEBYTECODE": "1",
                        "PATH": f"{venv / 'bin'}:/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"},
                "notes": notes}
    else:
        if (src / "package.json").exists() and not (src / "node_modules").exists():
            env = {"PATH": f"{NODE_BIN}:/usr/bin:/bin", "HOME": str(d), "npm_config_cache": str(d / ".npm")}
            r = _run([str(NODE_BIN / "npm"), "install", "--ignore-scripts", "--omit=dev", "--no-audit", "--no-fund",
                      "--loglevel=error"], cwd=src, timeout=900, env=env)
            notes.append("npm install ok" if r.returncode == 0 else f"npm install failed: {r.stderr[-300:]}")
        meta = {"lang": "javascript", "src": str(src), "node": str(NODE_BIN / "node"),
                "ro": [str(src), str(ROOT / "tools" / "node"), "/usr", "/lib", "/etc/ld.so.cache", "/etc/ssl",
                       "/etc/localtime"],
                "env": {"PATH": f"{NODE_BIN}:/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8",
                        "NODE_OPTIONS": "--max-old-space-size=2048", "NODE_PATH": str(src / "node_modules")},
                "notes": notes}
    meta_f.write_text(json.dumps(meta, indent=1))
    return meta
