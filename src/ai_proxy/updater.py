"""GitHub Release version checking, SHA256 verification, and atomic self-upgrade."""

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ai_proxy import __version__
from ai_proxy.config import parse_upstream
from ai_proxy.daemon import tcp_reachable

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")
_SHA256_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(.+?)$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def parse_semver(raw: str) -> Tuple[int, int, int, int, str]:
    """Parse SemVer string into a sortable tuple; raises ValueError if invalid."""
    text = raw.strip()
    if text.startswith(("v", "V")):
        text = text[1:]
    text = text.split("+", 1)[0]
    match = _SEMVER_RE.fullmatch(text)
    if not match:
        raise ValueError(f"无效的版本号格式: {raw!r}")
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    prerelease = match.group(4) or ""
    stability = 0 if prerelease else 1
    return (major, minor, patch, stability, prerelease)


def is_newer_version(remote: str, local: str) -> bool:
    """Return True if remote SemVer is strictly newer than local SemVer."""
    return parse_semver(remote) > parse_semver(local)


def normalize_tag(version: str) -> str:
    """Normalize a version string to a leading-lowercase `v` release tag."""
    text = version.strip()
    if not text:
        raise ValueError("版本号不能为空")
    # Validate SemVer so malformed flags fail early before forming URLs.
    parse_semver(text)
    if text.startswith(("v", "V")):
        return f"v{text[1:]}"
    return f"v{text}"


def build_curl_proxy_url(upstream: Optional[str]) -> Optional[str]:
    """Return a curl-compatible proxy URL if upstream is configured and reachable."""
    if not upstream:
        return None
    try:
        scheme, host, port = parse_upstream(upstream)
    except ValueError:
        return None
    if not tcp_reachable(host, port, timeout=1.0):
        return None

    parsed = urlparse(upstream)
    auth = ""
    if parsed.username is not None:
        pwd_part = f":{parsed.password}" if parsed.password is not None else ""
        auth = f"{parsed.username}{pwd_part}@"

    if scheme in ("socks5", "socks5h"):
        return f"socks5h://{auth}{host}:{port}"
    return f"http://{auth}{host}:{port}"


def _run_curl(
    args: List[str],
    upstream: Optional[str] = None,
    timeout: int = 15,
) -> subprocess.CompletedProcess:
    base_cmd = [
        "curl",
        "-fsSL",
        "--max-time",
        str(timeout),
        "-H",
        f"User-Agent: ai-proxy/{__version__}",
    ]
    proxy_url = build_curl_proxy_url(upstream)
    last_error = ""

    if proxy_url:
        try:
            res = subprocess.run(
                [*base_cmd, "-x", proxy_url, *args],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                return res
            last_error = (res.stderr or "").strip() or f"curl 退出码 {res.returncode}"
        except (OSError, subprocess.SubprocessError) as exc:
            last_error = str(exc)

    try:
        res = subprocess.run(
            [*base_cmd, *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0:
            return res
        direct_err = (res.stderr or "").strip() or f"curl 退出码 {res.returncode}"
        raise RuntimeError(direct_err if not last_error else f"{direct_err}（代理尝试: {last_error}）")
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(str(exc)) from exc


def fetch_release_info(
    repo: str,
    version: Optional[str] = None,
    upstream: Optional[str] = None,
) -> Dict:
    """Fetch GitHub Release metadata for latest or a specific tag."""
    repo_clean = repo.strip()
    if not _REPO_RE.fullmatch(repo_clean):
        raise ValueError(f"无效的仓库名称（应为 owner/repo）: {repo!r}")

    if version:
        tag = normalize_tag(version)
        url = f"https://api.github.com/repos/{repo_clean}/releases/tags/{tag}"
    else:
        url = f"https://api.github.com/repos/{repo_clean}/releases/latest"

    res = _run_curl(
        ["-H", "Accept: application/vnd.github+json", url],
        upstream=upstream,
        timeout=15,
    )

    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"GitHub Release 响应 JSON 解析失败: {exc}") from exc

    if not isinstance(data, dict) or not data.get("tag_name"):
        msg = data.get("message") if isinstance(data, dict) else None
        raise RuntimeError(f"GitHub Release 响应缺少 tag_name{f': {msg}' if msg else ''}")

    tag_name = str(data["tag_name"]).strip()
    ver = tag_name[1:] if tag_name.startswith(("v", "V")) else tag_name

    assets: Dict[str, str] = {}
    raw_assets = data.get("assets")
    if isinstance(raw_assets, list):
        for item in raw_assets:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            dl_url = item.get("browser_download_url")
            if isinstance(name, str) and isinstance(dl_url, str) and name and dl_url:
                assets[name] = dl_url

    return {
        "tag_name": tag_name,
        "version": ver,
        "html_url": str(data.get("html_url") or f"https://github.com/{repo_clean}/releases/tag/{tag_name}"),
        "published_at": str(data.get("published_at") or ""),
        "assets": assets,
    }


def parse_sha256sums(content: str) -> Dict[str, str]:
    """Parse shasum -a 256 output into {filename: sha256_hex_lower}."""
    sums: Dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _SHA256_LINE_RE.fullmatch(stripped)
        if match:
            digest = match.group(1).lower()
            filename = match.group(2).strip()
            if filename.startswith("./"):
                filename = filename[2:]
            sums[filename] = digest
    return sums


def compute_file_sha256(path: Path) -> str:
    """Compute SHA256 hex digest of a file in streaming chunks."""
    hasher = hashlib.sha256()
    with open(path, "rb") as fp:
        while True:
            chunk = fp.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_file_sha256(path: Path, sums_content: str, asset_name: str = "ai-proxy") -> str:
    """Verify file SHA256 against parsed SHA256SUMS content; returns verified digest."""
    sums = parse_sha256sums(sums_content)
    expected = sums.get(asset_name)
    if not expected:
        raise ValueError(f"SHA256SUMS 中未找到 {asset_name} 的校验值")
    actual = compute_file_sha256(path)
    if actual != expected:
        raise ValueError(f"{asset_name} SHA256 校验失败: 期望 {expected}, 实际 {actual}")
    return actual


def download_file(
    url: str,
    dest: Path,
    upstream: Optional[str] = None,
    timeout: int = 60,
) -> None:
    """Download a file via curl (preferring upstream proxy if reachable, falling back to direct)."""
    if dest.exists():
        dest.unlink()
    _run_curl(["-o", str(dest), url], upstream=upstream, timeout=timeout)
    if not dest.exists() or dest.stat().st_size == 0:
        raise RuntimeError(f"下载文件为空或未写入: {dest}")


def atomic_replace_binary(src: Path, dest: Path) -> None:
    """Atomically install src over dest (including over dangling symlinks) with mode 0755."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dest.with_name(f".{dest.name}.upgrade.tmp")
    try:
        shutil.copyfile(src, tmp_path)
        os.chmod(tmp_path, 0o755)
        os.replace(tmp_path, dest)
    except Exception:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise


def smoke_test_binary(bin_path: Path, expected_version: Optional[str] = None) -> str:
    """Run `<bin> --version` and validate output before replacing installed binary."""
    try:
        res = subprocess.run(
            [str(bin_path), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"新版本可执行文件冒烟测试失败: {exc}") from exc

    out = (res.stdout or "").strip()
    if res.returncode != 0 or not out.startswith("ai-proxy "):
        err = (res.stderr or out or f"退出码 {res.returncode}").strip()
        raise RuntimeError(f"新版本可执行文件校验失败: {err}")

    if expected_version:
        clean_expected = expected_version.strip().lstrip("vV")
        if clean_expected not in out:
            raise RuntimeError(
                f"新版本输出不匹配: 期望包含 {clean_expected}, 实际为 {out!r}"
            )
    return out
