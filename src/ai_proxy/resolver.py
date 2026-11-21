"""macOS /etc/resolver/ split-DNS file management."""

import os
import re
import subprocess
from pathlib import Path
from typing import List, Tuple

from ai_proxy.paths import atomic_write_text

RESOLVER_DIR = Path("/etc/resolver")
RESOLVER_MARKER = "# managed by ai-proxy"
RESOLVER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")


def is_valid_resolver_name(name: str) -> bool:
    norm = name.strip().lower()
    return bool(norm and ".." not in norm and RESOLVER_NAME_RE.match(norm))


def list_managed_resolver_files(resolver_dir: Path = RESOLVER_DIR) -> List[str]:
    if not resolver_dir.exists() or not resolver_dir.is_dir():
        return []
    managed: List[str] = []
    for entry in resolver_dir.iterdir():
        if entry.is_symlink() or not entry.is_file():
            continue
        try:
            content = entry.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if RESOLVER_MARKER in content:
            managed.append(entry.name)
    return sorted(managed)


def remove_resolver_files(resolver_dir: Path = RESOLVER_DIR) -> int:
    if not resolver_dir.exists() or not resolver_dir.is_dir():
        return 0
    removed = 0
    for name in list_managed_resolver_files(resolver_dir):
        target = resolver_dir / name
        try:
            target.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def write_resolver_files(
    domains: List[str],
    dns_port: int,
    resolver_dir: Path = RESOLVER_DIR,
) -> Tuple[int, List[str]]:
    remove_resolver_files(resolver_dir)
    resolver_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(resolver_dir, 0o755)
    except OSError:
        pass

    written = 0
    skipped: List[str] = []
    seen = set()

    for raw in domains:
        domain = str(raw).strip().lower()
        if not domain or domain in seen:
            continue
        seen.add(domain)
        if not is_valid_resolver_name(domain):
            skipped.append(domain)
            continue

        target = resolver_dir / domain
        if target.exists() or target.is_symlink():
            is_managed = False
            if target.is_file() and not target.is_symlink():
                try:
                    is_managed = RESOLVER_MARKER in target.read_text(
                        encoding="utf-8", errors="ignore"
                    )
                except OSError:
                    is_managed = False
            if not is_managed:
                skipped.append(domain)
                continue

        content = (
            f"{RESOLVER_MARKER}\n"
            "nameserver 127.0.0.1\n"
            f"port {dns_port}\n"
        )
        atomic_write_text(target, content, 0o644)
        written += 1

    return written, skipped


def flush_dns_cache() -> None:
    subprocess.run(["dscacheutil", "-flushcache"], check=False)
    subprocess.run(["killall", "-HUP", "mDNSResponder"], check=False)
