"""Configuration schema, auto-initialization, and upstream URL helpers."""

import copy
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ai_proxy.paths import (
    atomic_write_text,
    ensure_dir,
    get_config_path,
    get_real_user_info,
)

SCHEMA_VERSION = 1

DEFAULT_CONFIG: Dict = {
    "schema_version": SCHEMA_VERSION,
    "upstream": "socks5://127.0.0.1:7890",
    "listen_port": 443,
    "dns_port": 15353,
    "connect_timeout": 10,
    "services": {
        "antigravity": {
            "enabled": True,
            "domains": [
                "googleapis.com",
                "antigravity.google",
                "accounts.google.com",
                "dl.google.com",
                "lh3.googleusercontent.com",
                "edgedl.me.gvt1.com",
                "redirector.gvt1.com",
            ],
        },
        "codex": {
            "enabled": True,
            "manage_env": True,
            "manage_launchctl": True,
            "domains": [
                "openai.com",
                "chatgpt.com",
                "oaistatic.com",
                "oaiusercontent.com",
            ],
        },
    },
}


def merge_defaults(cfg: Dict) -> Tuple[Dict, bool]:
    """Non-destructively fill missing schema_version and top-level defaults."""
    merged = copy.deepcopy(cfg) if isinstance(cfg, dict) else {}
    changed = False

    if merged.get("schema_version") != SCHEMA_VERSION:
        merged["schema_version"] = SCHEMA_VERSION
        changed = True

    for key in ("upstream", "listen_port", "dns_port", "connect_timeout"):
        if key not in merged:
            merged[key] = copy.deepcopy(DEFAULT_CONFIG[key])
            changed = True

    if not isinstance(merged.get("services"), dict):
        merged["services"] = copy.deepcopy(DEFAULT_CONFIG["services"])
        changed = True
    else:
        services = merged["services"]
        for svc_name, svc_default in DEFAULT_CONFIG["services"].items():
            if svc_name not in services or not isinstance(services[svc_name], dict):
                services[svc_name] = copy.deepcopy(svc_default)
                changed = True
            else:
                svc = services[svc_name]
                for sub_key, sub_val in svc_default.items():
                    if sub_key not in svc:
                        svc[sub_key] = copy.deepcopy(sub_val)
                        changed = True

    return merged, changed


def save_config(cfg: Dict, config_path: Optional[Path] = None) -> None:
    path = config_path or get_config_path()
    _, real_uid, real_gid, _ = get_real_user_info()
    ensure_dir(path.parent, mode=0o755, chown_user=True)
    atomic_write_text(
        path,
        json.dumps(cfg, indent=2, ensure_ascii=False) + "\n",
        mode=0o644,
        uid=real_uid,
        gid=real_gid,
    )


def load_config(config_path: Optional[Path] = None, auto_init: bool = True) -> Dict:
    path = config_path or get_config_path()
    if not path.exists():
        if not auto_init:
            print(f"[错误] 找不到配置文件: {path}", file=sys.stderr)
            sys.exit(1)
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        save_config(cfg, path)
        return cfg

    raw = json.loads(path.read_text(encoding="utf-8"))
    merged, changed = merge_defaults(raw)
    if changed:
        save_config(merged, path)
    return merged


def get_services(cfg: Dict) -> Dict[str, Dict]:
    services = cfg.get("services")
    return services if isinstance(services, dict) else {}


def get_enabled_domains(cfg: Dict) -> List[str]:
    services = get_services(cfg)
    seen = set()
    result: List[str] = []
    for svc in services.values():
        if not isinstance(svc, dict) or not svc.get("enabled", True):
            continue
        for raw in svc.get("domains", []):
            d = str(raw).strip().lower()
            if d and d not in seen:
                seen.add(d)
                result.append(d)
    return result


def is_service_enabled(cfg: Dict, name: str) -> bool:
    svc = get_services(cfg).get(name)
    return isinstance(svc, dict) and bool(svc.get("enabled", False))


def parse_upstream(upstream_url: str) -> Tuple[str, str, int]:
    parsed = urlparse(upstream_url)
    scheme = (parsed.scheme or "socks5").lower()
    if scheme not in ("socks5", "socks5h", "http", "https"):
        raise ValueError(f"不支持的代理协议: {scheme}（仅支持 socks5 / http）")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port
    if port is None:
        raise ValueError(f"代理地址缺少端口: {upstream_url}")
    return scheme, host, port


def build_http_proxy_url(upstream_url: str) -> str:
    _, host, port = parse_upstream(upstream_url)
    parsed = urlparse(upstream_url)
    if parsed.username is not None:
        pwd_part = f":{parsed.password}" if parsed.password is not None else ""
        return f"http://{parsed.username}{pwd_part}@{host}:{port}"
    return f"http://{host}:{port}"
