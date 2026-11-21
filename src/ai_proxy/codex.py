"""Reversible Codex ~/.codex/.env and macOS GUI launchctl environment management."""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from ai_proxy.config import build_http_proxy_url
from ai_proxy.paths import (
    atomic_write_text,
    chown_to_real_user,
    ensure_dir,
    get_real_user_info,
    get_state_dir,
)

START_MARKER = "# >>> ai-proxy managed start >>>"
END_MARKER = "# <<< ai-proxy managed end <<<"

NO_PROXY_VALUE = "localhost,127.0.0.1,::1,.local"
LAUNCHCTL_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
)


def strip_managed_block(text: str) -> str:
    """Idempotently remove the ai-proxy managed marker block from text."""
    pattern = re.compile(
        r"\n?" + re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER) + r"\n?",
        re.DOTALL,
    )
    cleaned = pattern.sub("\n", text)
    stripped = cleaned.strip("\n")
    return (stripped + "\n") if stripped else ""


def has_managed_markers(text: str) -> bool:
    return START_MARKER in text and END_MARKER in text


def write_codex_env(
    upstream_url: str,
    home_dir: Optional[Path] = None,
    state_dir: Optional[Path] = None,
    user_ids: Optional[Tuple[int, int]] = None,
) -> Tuple[Path, str]:
    if home_dir is None or user_ids is None:
        _, real_uid, real_gid, real_home = get_real_user_info()
    else:
        real_home = home_dir
        real_uid, real_gid = user_ids

    sdir = ensure_dir(state_dir or get_state_dir(), mode=0o755, chown_user=True)
    chown_to_real_user(sdir, real_uid, real_gid)

    codex_dir = real_home / ".codex"
    if not codex_dir.exists():
        codex_dir.mkdir(parents=True, exist_ok=True)
        chown_to_real_user(codex_dir, real_uid, real_gid)

    env_path = codex_dir / ".env"
    meta_file = sdir / "codex.meta.json"
    bak_file = sdir / "codex.env.original.bak"

    original = ""
    file_mode = 0o600
    has_user_content = False
    if env_path.exists():
        original = env_path.read_text(encoding="utf-8")
        has_user_content = bool(strip_managed_block(original).strip())
        try:
            file_mode = env_path.stat().st_mode & 0o777
        except OSError:
            file_mode = 0o600
        if has_user_content and not bak_file.exists():
            atomic_write_text(bak_file, original, mode=0o600, uid=real_uid, gid=real_gid)

    if not meta_file.exists():
        atomic_write_text(
            meta_file,
            json.dumps({"existed_before": has_user_content}, indent=2) + "\n",
            mode=0o644,
            uid=real_uid,
            gid=real_gid,
        )

    http_url = build_http_proxy_url(upstream_url)
    cleaned = strip_managed_block(original)
    block_lines = [
        START_MARKER,
        f"HTTP_PROXY={http_url}",
        f"HTTPS_PROXY={http_url}",
        f"http_proxy={http_url}",
        f"https_proxy={http_url}",
        f"NO_PROXY={NO_PROXY_VALUE}",
        f"no_proxy={NO_PROXY_VALUE}",
        END_MARKER,
    ]
    prefix = (cleaned.rstrip("\n") + "\n\n") if cleaned.strip() else ""
    new_content = prefix + "\n".join(block_lines) + "\n"

    atomic_write_text(env_path, new_content, file_mode, real_uid, real_gid)
    return env_path, http_url


def remove_codex_env(
    home_dir: Optional[Path] = None,
    state_dir: Optional[Path] = None,
    user_ids: Optional[Tuple[int, int]] = None,
) -> bool:
    if home_dir is None or user_ids is None:
        _, real_uid, real_gid, real_home = get_real_user_info()
    else:
        real_home = home_dir
        real_uid, real_gid = user_ids

    sdir = state_dir or get_state_dir()
    env_path = real_home / ".codex" / ".env"
    meta_file = sdir / "codex.meta.json"

    existed_before = True
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            existed_before = bool(meta.get("existed_before", True))
        except (ValueError, OSError):
            existed_before = True

    removed = False
    if env_path.exists():
        original = env_path.read_text(encoding="utf-8")
        if has_managed_markers(original):
            cleaned = strip_managed_block(original)
            if not existed_before and not cleaned.strip():
                env_path.unlink()
            else:
                try:
                    file_mode = env_path.stat().st_mode & 0o777
                except OSError:
                    file_mode = 0o600
                atomic_write_text(env_path, cleaned, file_mode, real_uid, real_gid)
            removed = True

    if meta_file.exists():
        try:
            meta_file.unlink()
        except OSError:
            pass
    return removed


def has_codex_env(home_dir: Optional[Path] = None) -> bool:
    if home_dir is None:
        _, _, _, real_home = get_real_user_info()
    else:
        real_home = home_dir
    env_path = real_home / ".codex" / ".env"
    if not env_path.exists():
        return False
    try:
        content = env_path.read_text(encoding="utf-8")
    except OSError:
        return False
    return has_managed_markers(content)


def _run_user_launchctl(args: List[str]) -> subprocess.CompletedProcess:
    _, real_uid, _, _ = get_real_user_info()
    if os.geteuid() == 0 and real_uid != 0:
        cmd = ["launchctl", "asuser", str(real_uid), "launchctl", *args]
    else:
        cmd = ["launchctl", *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def apply_launchctl_env(
    upstream_url: str,
    state_dir: Optional[Path] = None,
) -> Tuple[bool, str]:
    sdir = ensure_dir(state_dir or get_state_dir(), mode=0o755, chown_user=True)
    _, real_uid, real_gid, _ = get_real_user_info()
    http_url = build_http_proxy_url(upstream_url)
    pairs = {
        "HTTP_PROXY": http_url,
        "HTTPS_PROXY": http_url,
        "http_proxy": http_url,
        "https_proxy": http_url,
        "NO_PROXY": NO_PROXY_VALUE,
        "no_proxy": NO_PROXY_VALUE,
    }
    for k, v in pairs.items():
        res = _run_user_launchctl(["setenv", k, v])
        if res.returncode != 0:
            err = (res.stderr or res.stdout or f"exit {res.returncode}").strip()
            return False, err

    lc_file = sdir / "launchctl.json"
    atomic_write_text(
        lc_file,
        json.dumps({"keys": list(pairs.keys()), "proxy": http_url}, indent=2) + "\n",
        mode=0o644,
        uid=real_uid,
        gid=real_gid,
    )
    return True, http_url


def clear_launchctl_env(state_dir: Optional[Path] = None) -> bool:
    sdir = state_dir or get_state_dir()
    lc_file = sdir / "launchctl.json"
    if not lc_file.exists():
        return False
    keys = list(LAUNCHCTL_KEYS)
    try:
        data = json.loads(lc_file.read_text(encoding="utf-8"))
        if isinstance(data.get("keys"), list):
            keys = [str(k) for k in data["keys"]]
    except (ValueError, OSError):
        pass

    for k in keys:
        _run_user_launchctl(["unsetenv", k])

    try:
        lc_file.unlink()
    except OSError:
        pass
    return True


def has_launchctl_env(state_dir: Optional[Path] = None) -> bool:
    sdir = state_dir or get_state_dir()
    return (sdir / "launchctl.json").exists()
