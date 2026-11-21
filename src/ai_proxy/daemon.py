"""Network probes and background relay daemon lifecycle helpers."""

import json
import os
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from ai_proxy.config import parse_upstream
from ai_proxy.paths import (
    build_self_command,
    chown_to_real_user,
    ensure_dir,
    get_config_path,
    get_real_user_info,
    get_state_dir,
)


def tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def dns_responder_reachable(dns_port: int, timeout: float = 1.0) -> bool:
    """Send a minimal UDP DNS A query for check.local and verify 127.0.0.1 answer."""
    if dns_port <= 0:
        return False
    query = (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + b"\x05check\x05local\x00"
        + struct.pack("!HH", 1, 1)
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query, ("127.0.0.1", dns_port))
        resp, _ = sock.recvfrom(512)
        if len(resp) < 12 or resp[:2] != b"\x12\x34":
            return False
        flags = struct.unpack("!H", resp[2:4])[0]
        if (flags & 0x800F) != 0x8000:
            return False
        return resp.endswith(b"\x7f\x00\x00\x01")
    except OSError:
        return False
    finally:
        sock.close()


def test_tls_endpoint(
    host: str, port: int = 443, connect_host: Optional[str] = None
) -> Tuple[bool, str, int]:
    """Perform a TLS handshake to host and return (ok, detail, elapsed_ms)."""
    ctx = ssl.create_default_context()
    target = connect_host or host
    t0 = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=8.0) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
                ms = int((time.monotonic() - t0) * 1000)
                return True, f"{tls_sock.version()} ({ms}ms)", ms
    except Exception as exc:
        ms = int((time.monotonic() - t0) * 1000)
        return False, f"{exc} ({ms}ms)", ms


def probe_egress_via_upstream(upstream: str) -> Tuple[bool, str, Optional[str]]:
    """Query actual AI proxy egress IP and country via chatgpt trace, falling back to geoip APIs."""
    scheme, host, port = parse_upstream(upstream)
    proxy_arg = f"socks5h://{host}:{port}" if scheme in ("socks5", "socks5h") else f"http://{host}:{port}"
    last_err = ""

    try:
        res = subprocess.run(
            ["curl", "-fsS", "--max-time", "6", "-x", proxy_arg, "https://chatgpt.com/cdn-cgi/trace"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            kv: Dict[str, str] = {}
            for line in res.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    kv[k.strip()] = v.strip()
            ip = kv.get("ip")
            loc = kv.get("loc", "").upper()
            colo = kv.get("colo", "")
            if ip and loc:
                detail = f"{ip} ({loc}" + (f" / {colo}" if colo else "") + ")"
                return True, detail, loc
        last_err = (res.stderr or f"exit {res.returncode}").strip()
    except Exception as exc:
        last_err = str(exc)

    endpoints = (
        ("https://ipinfo.io/json", "ip", "country", "city"),
        ("https://api.ip.sb/geoip", "ip", "country_code", "city"),
    )
    for url, ip_k, cc_k, city_k in endpoints:
        try:
            res = subprocess.run(
                ["curl", "-fsS", "--max-time", "6", "-x", proxy_arg, url],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                ip = data.get(ip_k, "?")
                cc = str(data.get(cc_k, "?")).upper()
                city = data.get(city_k, "")
                loc = f"{cc}" + (f" / {city}" if city else "")
                return True, f"{ip} ({loc})", cc
            last_err = (res.stderr or f"exit {res.returncode}").strip()
        except Exception as exc:
            last_err = str(exc)
    return False, last_err or "请求超时", None


def read_pid(state_dir: Optional[Path] = None) -> Optional[int]:
    sdir = state_dir or get_state_dir()
    pid_file = sdir / "relay.pid"
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
        return pid if pid > 0 else None
    except (ValueError, OSError):
        return None


def is_pid_running(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        res = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            check=False,
        )
        return "_relay" in res.stdout or "relay.py" in res.stdout
    except OSError:
        return True


def check_port_owner(port: int, proto: str = "TCP") -> str:
    res = subprocess.run(
        ["lsof", "-nP", f"-i{proto}:{port}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return res.stdout.strip()


def stop_relay(state_dir: Optional[Path] = None) -> bool:
    sdir = state_dir or get_state_dir()
    pid_file = sdir / "relay.pid"
    pid = read_pid(sdir)
    stopped = False
    if pid and is_pid_running(pid):
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(25):
                if not is_pid_running(pid):
                    break
                time.sleep(0.1)
            if is_pid_running(pid):
                os.kill(pid, signal.SIGKILL)
            stopped = True
        except OSError:
            pass
    if pid_file.exists():
        try:
            pid_file.unlink()
        except OSError:
            pass
    return stopped


def start_relay(
    listen_port: int,
    dns_port: int,
    config_path: Optional[Path] = None,
    state_dir: Optional[Path] = None,
) -> int:
    sdir = ensure_dir(state_dir or get_state_dir(), mode=0o755, chown_user=True)
    cfg_path = config_path or get_config_path()
    pid_file = sdir / "relay.pid"
    log_file = sdir / "relay.log"
    _, real_uid, real_gid, _ = get_real_user_info()

    stop_relay(sdir)

    if tcp_reachable("127.0.0.1", listen_port, timeout=0.5):
        owner = check_port_owner(listen_port, "TCP")
        print(f"[错误] 本地端口 {listen_port} 已被其他进程占用，未修改 /etc/resolver。", file=sys.stderr)
        if owner:
            print(owner, file=sys.stderr)
        sys.exit(1)

    cmd, env = build_self_command(
        ["_relay", "--config", str(cfg_path), "--log", str(log_file)]
    )

    with open(log_file, "a", encoding="utf-8") as log_fp:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_fp,
            stderr=log_fp,
            start_new_session=True,
        )

    pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")
    for p in (pid_file, log_file):
        try:
            os.chmod(p, 0o644)
        except OSError:
            pass
        chown_to_real_user(p, real_uid, real_gid)

    for _ in range(30):
        tcp_ok = tcp_reachable("127.0.0.1", listen_port, timeout=0.2)
        dns_ok = dns_port <= 0 or dns_responder_reachable(dns_port, timeout=0.2)
        if tcp_ok and dns_ok:
            return proc.pid
        if proc.poll() is not None:
            break
        time.sleep(0.1)

    stop_relay(sdir)
    print(f"[错误] SNI + DNS 转发服务启动失败，请查看日志: {log_file}", file=sys.stderr)
    sys.exit(1)
