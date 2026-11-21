"""User-aware path resolution, atomic writes, and privilege helpers for ai-proxy."""

import os
import pwd
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def get_real_user_info() -> Tuple[str, int, int, Path]:
    """Resolve the invoking non-root user's name, uid, gid, and home directory."""
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    if sudo_user and sudo_user != "root":
        try:
            pw = pwd.getpwnam(sudo_user)
            return pw.pw_name, pw.pw_uid, pw.pw_gid, Path(pw.pw_dir)
        except KeyError:
            pass
    pw = pwd.getpwuid(os.getuid())
    return pw.pw_name, pw.pw_uid, pw.pw_gid, Path(pw.pw_dir)


def chown_to_real_user(path: Path, uid: int, gid: int) -> None:
    if os.geteuid() == 0 and uid != 0:
        try:
            os.chown(path, uid, gid)
        except OSError:
            pass


def ensure_dir(path: Path, mode: int = 0o755, chown_user: bool = False) -> Path:
    """Create directory (and missing parents) cleanly, preserving real user ownership if requested."""
    if path.exists():
        return path

    missing: List[Path] = []
    cur = path
    while not cur.exists() and cur != cur.parent:
        missing.append(cur)
        cur = cur.parent

    path.mkdir(parents=True, exist_ok=True)
    _, uid, gid, _ = get_real_user_info()
    for created in reversed(missing):
        try:
            os.chmod(created, mode)
        except OSError:
            pass
        if chown_user:
            chown_to_real_user(created, uid, gid)
    return path


def atomic_write_text(
    path: Path,
    content: str,
    mode: int,
    uid: int = 0,
    gid: int = 0,
) -> None:
    tmp_path = path.with_name(f".{path.name}.ai-proxy.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    try:
        os.chmod(tmp_path, mode)
    except OSError:
        pass
    if uid != 0:
        chown_to_real_user(tmp_path, uid, gid)
    os.replace(tmp_path, path)


def get_config_path() -> Path:
    override = os.environ.get("AI_PROXY_CONFIG", "").strip()
    if override:
        return Path(override).expanduser()
    _, _, _, real_home = get_real_user_info()
    return real_home / ".config" / "ai-proxy" / "config.json"


def get_state_dir() -> Path:
    override = os.environ.get("AI_PROXY_STATE_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    _, _, _, real_home = get_real_user_info()
    return real_home / "Library" / "Application Support" / "ai-proxy"


def _resolve_argv0() -> Optional[Path]:
    raw = sys.argv[0] if sys.argv else ""
    if not raw:
        return None
    p = Path(raw)
    if p.exists():
        return p
    found = shutil.which(raw)
    return Path(found) if found else None


def build_self_command(extra_args: List[str]) -> Tuple[List[str], Dict[str, str]]:
    """Build a command + env dict to re-invoke ai-proxy (either `python -m` or standalone zipapp)."""
    env = os.environ.copy()
    argv0 = _resolve_argv0()
    if argv0 is not None:
        resolved = argv0.resolve()
        if resolved.name == "__main__.py":
            src_root = str(Path(__file__).resolve().parent.parent)
            existing_pp = env.get("PYTHONPATH", "")
            pp_parts = [p for p in existing_pp.split(os.pathsep) if p]
            if src_root not in pp_parts:
                pp_parts.insert(0, src_root)
            env["PYTHONPATH"] = os.pathsep.join(pp_parts)
            return [sys.executable, "-m", "ai_proxy", *extra_args], env
        return [sys.executable, str(resolved), *extra_args], env

    src_root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = src_root
    return [sys.executable, "-m", "ai_proxy", *extra_args], env


def get_standalone_executable() -> Optional[Path]:
    """Return the invoked executable path if running as a standalone zipapp/binary, else None."""
    argv0 = _resolve_argv0()
    if argv0 is None:
        return None
    resolved = argv0.resolve()
    if resolved.name == "__main__.py" or resolved.suffix == ".py":
        return None
    if argv0.exists() or argv0.is_symlink():
        return argv0.absolute()
    return None


def require_root(
    reason: Optional[str] = None,
) -> None:
    if os.geteuid() != 0:
        print(
            reason or "需要管理员权限以配置 /etc/resolver 并监听 443 端口，正在请求 sudo 授权..."
        )
        cmd, env = build_self_command(sys.argv[1:])
        env_prefix: List[str] = []
        preserved_keys = (
            "PYTHONPATH",
            "AI_PROXY_CONFIG",
            "AI_PROXY_STATE_DIR",
            "AI_PROXY_REPO",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "https_proxy",
            "http_proxy",
            "all_proxy",
            "no_proxy",
        )
        for key in preserved_keys:
            val = env.get(key)
            if val:
                env_prefix.append(f"{key}={val}")
        sudo_cmd = ["sudo", *(["env", *env_prefix] if env_prefix else []), *cmd]
        os.execvp("sudo", sudo_cmd)
