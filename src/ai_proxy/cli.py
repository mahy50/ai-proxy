"""CLI entrypoint and subcommand handlers for ai-proxy."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from ai_proxy import DEFAULT_REPO, __version__
from ai_proxy.codex import (
    apply_launchctl_env,
    clear_launchctl_env,
    has_codex_env,
    has_launchctl_env,
    remove_codex_env,
    write_codex_env,
)
from ai_proxy.config import (
    get_enabled_domains,
    get_services,
    is_service_enabled,
    load_config,
    parse_upstream,
    save_config,
)
from ai_proxy.daemon import (
    check_port_owner,
    dns_responder_reachable,
    is_pid_running,
    probe_egress_via_upstream,
    read_pid,
    start_relay,
    stop_relay,
    tcp_reachable,
    test_tls_endpoint,
)
from ai_proxy.paths import (
    get_config_path,
    get_real_user_info,
    get_standalone_executable,
    get_state_dir,
    require_root,
)
from ai_proxy.relay import run_relay_cli
from ai_proxy.resolver import (
    flush_dns_cache,
    is_valid_resolver_name,
    list_managed_resolver_files,
    remove_resolver_files,
    write_resolver_files,
)
from ai_proxy.updater import (
    atomic_replace_binary,
    download_file,
    fetch_release_info,
    is_newer_version,
    smoke_test_binary,
    verify_file_sha256,
)


def _perform_full_cleanup() -> Tuple[int, bool, bool, bool]:
    removed_resolvers = remove_resolver_files()
    flush_dns_cache()
    stopped_relay = stop_relay()
    removed_codex = remove_codex_env()
    cleared_lc = clear_launchctl_env()
    return removed_resolvers, stopped_relay, removed_codex, cleared_lc


def cmd_on(_args: argparse.Namespace) -> None:
    require_root()
    cfg = load_config()
    upstream = cfg.get("upstream", "socks5://127.0.0.1:7890")
    listen_port = int(cfg.get("listen_port", 443))
    dns_port = int(cfg.get("dns_port", 15353))
    services = get_services(cfg)
    domains = get_enabled_domains(cfg)

    try:
        _, up_host, up_port = parse_upstream(upstream)
    except ValueError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        sys.exit(1)

    if not tcp_reachable(up_host, up_port, timeout=2.0):
        print(
            f"[错误] 无法连接到上游代理 {upstream}。\n"
            f"请确认 FlClash 正在运行，或检查端口是否正确（可用 ai-proxy config --proxy socks5://127.0.0.1:<端口> 修改）。",
            file=sys.stderr,
        )
        sys.exit(1)

    agy_enabled = is_service_enabled(cfg, "antigravity")
    codex_svc = services.get("codex", {}) if isinstance(services.get("codex"), dict) else {}
    codex_enabled = bool(codex_svc.get("enabled", False))

    pid = None
    written_zones = 0
    skipped_zones: List[str] = []

    if domains:
        pid = start_relay(listen_port, dns_port)
        written_zones, skipped_zones = write_resolver_files(domains, dns_port)
        flush_dns_cache()
    else:
        stop_relay()
        remove_resolver_files()
        flush_dns_cache()

    codex_env_msg = "未启用"
    launchctl_msg = "未启用"
    if codex_enabled:
        if codex_svc.get("manage_env", True):
            env_path, http_url = write_codex_env(upstream)
            codex_env_msg = f"已写入 {env_path} ({http_url})"
        else:
            remove_codex_env()
            codex_env_msg = "已按配置跳过 (manage_env=false)"

        if codex_svc.get("manage_launchctl", True):
            ok_lc, detail_lc = apply_launchctl_env(upstream)
            launchctl_msg = f"已设置 GUI 会话代理 ({detail_lc})" if ok_lc else f"设置失败 ({detail_lc})"
        else:
            clear_launchctl_env()
            launchctl_msg = "已按配置跳过 (manage_launchctl=false)"
    else:
        remove_codex_env()
        clear_launchctl_env()

    enabled_names = [
        name for name, svc in services.items() if isinstance(svc, dict) and svc.get("enabled", True)
    ]
    print(f"[OK] ai-proxy v{__version__} 已开启（FlClash 保持默认配置，无需开 TUN）")
    print(f"  - 启用服务:       {', '.join(enabled_names) if enabled_names else '无'}")
    if pid is not None:
        print(f"  - SNI + DNS 转发: 127.0.0.1:{listen_port} + UDP:{dns_port} (PID {pid}) -> {upstream}")
        print(f"  - /etc/resolver:  已写入 {written_zones} 个分域解析文件（自动覆盖泛域名）")
        if skipped_zones:
            print(f"  - [WARN] 跳过非托管或无效域名: {', '.join(skipped_zones)}")
    if codex_enabled:
        print(f"  - Codex .env:     {codex_env_msg}")
        print(f"  - launchctl Env:  {launchctl_msg}")

    if pid is not None:
        self_tests = []
        if agy_enabled:
            self_tests.append(("Antigravity", "daily-cloudcode-pa.googleapis.com"))
        if codex_enabled:
            self_tests.append(("Codex", "api.openai.com"))
        any_failed = False
        for label, host in self_tests:
            ok, detail, _ = test_tls_endpoint(host, listen_port, connect_host="127.0.0.1")
            status_str = f"通过 ({host}: {detail})" if ok else f"失败 ({host}: {detail})"
            print(f"  - 自检[{label}]: {status_str}")
            if not ok:
                any_failed = True
        if any_failed:
            print("    提示: 请运行 ai-proxy check / ai-proxy logs -n 30 查看详情，或确认 FlClash 代理节点可用。")

    if codex_enabled:
        print("  - 提示: 如 Codex (ChatGPT.app / com.openai.codex) 已在运行，请 Cmd+Q 完全退出后重新打开使新代理变量生效。")


def cmd_off(_args: argparse.Namespace) -> None:
    require_root()
    removed_resolvers, stopped_relay, removed_codex, cleared_lc = _perform_full_cleanup()

    print("[OK] ai-proxy 已关闭并完全撤回")
    print(f"  - /etc/resolver 清理: {f'已移除 {removed_resolvers} 个托管文件' if removed_resolvers else '本来就无托管文件'}")
    print(f"  - SNI + DNS 服务:     {'已停止' if stopped_relay else '未在运行'}")
    print(f"  - Codex .env 清理:    {'已移除托管条目' if removed_codex else '本来就无托管条目'}")
    print(f"  - launchctl 环境变量: {'已清除' if cleared_lc else '本来就未设置'}")
    print("  - macOS DNS 缓存:     已刷新")


def cmd_restart(args: argparse.Namespace) -> None:
    require_root()
    cmd_off(args)
    cmd_on(args)


def cmd_status(_args: argparse.Namespace) -> None:
    cfg = load_config()
    cfg_path = get_config_path()
    sdir = get_state_dir()
    log_file = sdir / "relay.log"

    upstream = cfg.get("upstream", "socks5://127.0.0.1:7890")
    listen_port = int(cfg.get("listen_port", 443))
    dns_port = int(cfg.get("dns_port", 15353))
    _, up_host, up_port = parse_upstream(upstream)
    services = get_services(cfg)

    pid = read_pid(sdir)
    running = is_pid_running(pid)
    port_open = tcp_reachable("127.0.0.1", listen_port, timeout=0.5)
    dns_open = dns_port > 0 and dns_responder_reachable(dns_port, timeout=0.5)
    managed_zones = list_managed_resolver_files()
    codex_env_on = has_codex_env()
    lc_on = has_launchctl_env(sdir)
    up_ok = tcp_reachable(up_host, up_port, timeout=1.5)

    any_active = running or bool(managed_zones) or codex_env_on or lc_on
    if running and bool(managed_zones):
        overall = "已开启 (ACTIVE)"
    elif any_active:
        overall = "部分开启 / 状态不一致"
    else:
        overall = "已关闭 (INACTIVE)"

    svc_summary = ", ".join(
        f"{k}:{'on' if (isinstance(v, dict) and v.get('enabled', True)) else 'off'}"
        for k, v in services.items()
    )
    _, _, _, real_home = get_real_user_info()

    print(f"ai-proxy v{__version__} 状态: {overall}")
    print(f"  - 服务配置:       {svc_summary}")
    print(
        f"  - SNI + DNS 进程: {'运行中 (PID ' + str(pid) + ')' if running else '未运行'}"
        f" | TCP:{listen_port} {'监听中' if port_open else '未监听'}"
        f" | UDP:{dns_port} {'正常' if dns_open else '未响应'}"
    )
    print(f"  - /etc/resolver:  {'已启用 (' + str(len(managed_zones)) + ' 个域名区域)' if managed_zones else '未写入（干净）'}")
    print(f"  - Codex .env:     {'已托管 (' + str(real_home / '.codex' / '.env') + ')' if codex_env_on else '未写入（干净）'}")
    print(f"  - launchctl:      {'已设置 GUI 会话代理' if lc_on else '未设置（干净）'}")
    print(f"  - 上游代理:       {upstream} ({'连通' if up_ok else '不可达！请检查 FlClash'})")
    print(f"  - 配置文件:       {cfg_path}")
    print(f"  - 运行状态目录:   {sdir}")
    print(f"  - 日志文件:       {log_file}")


def cmd_config(args: argparse.Namespace) -> None:
    cfg = load_config()
    services = cfg.setdefault("services", {})
    agy_svc = services.setdefault("antigravity", {"enabled": True, "domains": []})
    codex_svc = services.setdefault(
        "codex", {"enabled": True, "manage_env": True, "manage_launchctl": True, "domains": []}
    )

    changed = False
    if args.proxy:
        try:
            parse_upstream(args.proxy)
        except ValueError as exc:
            print(f"[错误] {exc}", file=sys.stderr)
            sys.exit(1)
        cfg["upstream"] = args.proxy
        changed = True
        print(f"[OK] 已更新上游代理为: {args.proxy}")

    if args.enable_agy:
        agy_svc["enabled"] = True
        changed = True
        print("[OK] 已启用 Antigravity (agy) 服务")
    elif args.disable_agy:
        agy_svc["enabled"] = False
        changed = True
        print("[OK] 已禁用 Antigravity (agy) 服务")

    if args.enable_codex:
        codex_svc["enabled"] = True
        changed = True
        print("[OK] 已启用 Codex 服务")
    elif args.disable_codex:
        codex_svc["enabled"] = False
        changed = True
        print("[OK] 已禁用 Codex 服务")

    if args.enable_launchctl:
        codex_svc["manage_launchctl"] = True
        changed = True
        print("[OK] 已开启 Codex GUI launchctl 环境变量管理")
    elif args.disable_launchctl:
        codex_svc["manage_launchctl"] = False
        changed = True
        print("[OK] 已关闭 Codex GUI launchctl 环境变量管理")

    if changed:
        save_config(cfg)
        if is_pid_running(read_pid()) or bool(list_managed_resolver_files()) or has_codex_env():
            print("提示: 请执行 ai-proxy restart 使新配置生效。")
    else:
        print(json.dumps(cfg, indent=2, ensure_ascii=False))


def cmd_domains(args: argparse.Namespace) -> None:
    cfg = load_config()
    services = get_services(cfg)
    action = args.action or "list"

    if action == "list":
        for name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            state_tag = "enabled" if svc.get("enabled", True) else "disabled"
            print(f"[{name}] ({state_tag}):")
            for d in svc.get("domains", []):
                print(f"  - {d}")
        return

    if not args.domain:
        print(f"[错误] 请指定域名，例如: ai-proxy domains {action} example.com", file=sys.stderr)
        sys.exit(1)

    target = args.domain.strip().lower()
    if action == "add":
        if not is_valid_resolver_name(target):
            print(f"[错误] 无效域名格式: {target}", file=sys.stderr)
            sys.exit(1)
        svc_name = args.service or "antigravity"
        svc = services.setdefault(svc_name, {"enabled": True, "domains": []})
        doms: List[str] = svc.setdefault("domains", [])
        if target in doms:
            print(f"域名已存在于 [{svc_name}]: {target}")
            return
        doms.append(target)
        cfg["services"] = services
        save_config(cfg)
        print(f"[OK] 已添加域名到 [{svc_name}]: {target}")
    elif action == "remove":
        removed_from: List[str] = []
        for name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            doms = svc.get("domains", [])
            if target in doms:
                svc["domains"] = [d for d in doms if d != target]
                removed_from.append(name)
        if not removed_from:
            print(f"域名不在任何服务列表中: {target}")
            return
        cfg["services"] = services
        save_config(cfg)
        print(f"[OK] 已从 [{', '.join(removed_from)}] 移除域名: {target}")

    if is_pid_running(read_pid()) or bool(list_managed_resolver_files()):
        print("提示: 请执行 ai-proxy restart 将域名变更同步到 /etc/resolver。")


def cmd_logs(args: argparse.Namespace) -> None:
    log_file = get_state_dir() / "relay.log"
    if not log_file.exists():
        print(f"暂无日志文件: {log_file}")
        return
    cmd = ["tail", "-n", str(args.lines)]
    if args.follow:
        cmd.append("-f")
    cmd.append(str(log_file))
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        pass


def cmd_check(_args: argparse.Namespace) -> None:
    cfg = load_config()
    sdir = get_state_dir()
    upstream = cfg.get("upstream", "socks5://127.0.0.1:7890")
    listen_port = int(cfg.get("listen_port", 443))
    dns_port = int(cfg.get("dns_port", 15353))
    _, up_host, up_port = parse_upstream(upstream)

    agy_enabled = is_service_enabled(cfg, "antigravity")
    codex_enabled = is_service_enabled(cfg, "codex")

    print(f"=== ai-proxy v{__version__} 全面检测 ===")
    issues: List[str] = []

    up_ok = tcp_reachable(up_host, up_port, timeout=2.0)
    print(f"1. FlClash 上游 ({upstream}): {'[OK] 端口可达' if up_ok else '[FAIL] 不可达'}")
    if not up_ok:
        issues.append(f"无法连接上游代理 {upstream}，请确认 FlClash 已运行且混合端口一致。")

    if up_ok:
        eg_ok, eg_info, cc = probe_egress_via_upstream(upstream)
        if eg_ok:
            blocked_regions = {"CN", "HK", "MO", "RU", "IR", "KP", "BY"}
            warn = "  <-- [WARN] 受限地区，Antigravity/Codex 均可能拒绝服务！" if cc in blocked_regions else ""
            print(f"2. AI 规则出口 IP / 地区: [OK] {eg_info}{warn}")
            if cc in blocked_regions:
                issues.append(f"当前 AI 代理出口地区为 {cc}，Antigravity 与 Codex 均不支持该地区，请切至 US/JP/SG/TW 等节点。")
        else:
            print(f"2. AI 规则出口 IP / 地区: [WARN] 探测失败 ({eg_info})")
    else:
        print("2. AI 规则出口 IP / 地区: [SKIP] 上游不可达")

    pid = read_pid(sdir)
    running = is_pid_running(pid)
    port_open = tcp_reachable("127.0.0.1", listen_port, timeout=0.5)
    dns_open = dns_port <= 0 or dns_responder_reachable(dns_port, timeout=0.8)
    if running and port_open and dns_open:
        print(f"3. 本地 :{listen_port} SNI + UDP:{dns_port} DNS: [OK] 运行中 (PID {pid})")
    elif port_open and not running:
        print(f"3. 本地 :{listen_port} SNI 转发: [FAIL] 端口被非 ai-proxy 进程占用")
        owner = check_port_owner(listen_port, "TCP")
        if owner:
            print(owner)
        issues.append(f"本地 {listen_port} 端口被其他程序占用。")
    elif running and port_open and not dns_open:
        print(f"3. 本地 :{listen_port} SNI + UDP:{dns_port} DNS: [FAIL] SNI 运行中但本地 DNS UDP:{dns_port} 无响应")
        issues.append(f"本地 DNS 应答器 (UDP:{dns_port}) 未响应，请执行 sudo ai-proxy restart。")
    else:
        print(f"3. 本地 :{listen_port} SNI + UDP:{dns_port} DNS: [INFO] 未启动（执行 sudo ai-proxy on 开启）")
        issues.append("SNI + DNS 转发服务未启动。")

    managed_zones = list_managed_resolver_files()
    print(f"4. /etc/resolver 分域解析: {'[OK] 已启用 (' + str(len(managed_zones)) + ' 个区域)' if managed_zones else '[INFO] 未启用（干净）'}")
    if managed_zones:
        verify_hosts = []
        if agy_enabled:
            verify_hosts.append("daily-cloudcode-pa.googleapis.com")
        if codex_enabled:
            verify_hosts.append("api.openai.com")
        for vhost in verify_hosts:
            try:
                addrs = {info[4][0] for info in socket.getaddrinfo(vhost, 443)}
                loopback_ok = bool(addrs & {"127.0.0.1", "::1"})
                print(f"   系统解析验证 ({vhost}): {'[OK] ' + ', '.join(sorted(addrs)) if loopback_ok else '[WARN] ' + ', '.join(sorted(addrs))}")
                if not loopback_ok:
                    issues.append(f"{vhost} 未通过 /etc/resolver 解析到本地，可尝试 sudo ai-proxy restart 刷新 DNS 缓存。")
            except OSError as exc:
                print(f"   系统解析验证 ({vhost}): [FAIL] {exc}")
                issues.append(f"域名解析失败 ({vhost}): {exc}")

    codex_env_on = has_codex_env()
    lc_on = has_launchctl_env(sdir)
    if codex_enabled:
        print(f"5. Codex 环境状态: ~/.codex/.env={'[OK] 已托管' if codex_env_on else '[WARN] 未写入'} | launchctl={'[OK] 已设置' if lc_on else '[INFO] 未设置'}")
        if not codex_env_on:
            issues.append("Codex 已启用但 ~/.codex/.env 未写入，请执行 sudo ai-proxy restart。")
    else:
        print(f"5. Codex 环境状态: [INFO] Codex 服务已禁用 (~/.codex/.env={'已写入' if codex_env_on else '干净'}, launchctl={'已设置' if lc_on else '干净'})")

    check_targets: List[Tuple[str, str]] = []
    if agy_enabled:
        check_targets.extend(
            [
                ("AGY Token/登录", "oauth2.googleapis.com"),
                ("AGY Token/登录", "accounts.google.com"),
                ("AGY Model", "daily-cloudcode-pa.googleapis.com"),
                ("AGY Model", "cloudcode-pa.googleapis.com"),
                ("AGY CLI/下载", "antigravity.google"),
                ("AGY CLI/下载", "storage.googleapis.com"),
            ]
        )
    if codex_enabled:
        check_targets.extend(
            [
                ("Codex API/登录", "api.openai.com"),
                ("Codex API/登录", "chatgpt.com"),
                ("Codex API/登录", "auth.openai.com"),
            ]
        )

    if running and port_open and check_targets:
        print(f"6. 核心接口端到端 TLS 检测（经 127.0.0.1:{listen_port} -> FlClash）:")
        failed_hosts: List[str] = []
        for group, host in check_targets:
            ok, detail, _ = test_tls_endpoint(host, listen_port, connect_host="127.0.0.1")
            tag = "[OK]  " if ok else "[FAIL]"
            print(f"   {tag} [{group}] {host:<36} -> {detail}")
            if not ok:
                failed_hosts.append(host)
        if failed_hosts:
            issues.append(
                f"有 {len(failed_hosts)} 个核心接口 TLS 握手失败（{', '.join(failed_hosts)}），"
                "请运行 ai-proxy logs -n 30 查看报错，或确认 FlClash 代理规则及节点可用。"
            )
    elif not check_targets:
        print("6. 核心接口端到端 TLS 检测: [SKIP] 无已启用服务")
    else:
        print("6. 核心接口端到端 TLS 检测: [SKIP] 请先执行 sudo ai-proxy on 启动转发")

    print("")
    if not issues:
        print("结论: [ALL PASS] 所有检测通过，FlClash 无需 TUN 即可正常工作。")
    else:
        print("结论: 发现以下问题：")
        for idx, item in enumerate(issues, 1):
            print(f"  {idx}. {item}")


def cmd_uninstall(args: argparse.Namespace) -> None:
    require_root()
    removed_resolvers, stopped_relay, removed_codex, cleared_lc = _perform_full_cleanup()

    cfg_path = get_config_path()
    sdir = get_state_dir()
    exe_path = get_standalone_executable()

    print("[OK] ai-proxy 系统接管状态已全部清理")
    print(f"  - /etc/resolver 清理: {f'已移除 {removed_resolvers} 个托管文件' if removed_resolvers else '无托管文件'}")
    print(f"  - SNI + DNS 服务:     {'已停止' if stopped_relay else '未在运行'}")
    print(f"  - Codex .env 清理:    {'已移除托管条目' if removed_codex else '无托管条目'}")
    print(f"  - launchctl 环境变量: {'已清除' if cleared_lc else '未设置'}")

    if exe_path is not None:
        try:
            exe_path.unlink()
            print(f"  - 可执行文件:         已删除 {exe_path}")
        except OSError as exc:
            print(f"  - 可执行文件:         [WARN] 删除失败 {exe_path}: {exc}")
    else:
        print("  - 可执行文件:         当前从源码目录运行，跳过删除程序文件")

    if args.purge:
        for target_dir in (cfg_path.parent, sdir):
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
        print(f"  - 配置与状态目录:     已彻底删除 {cfg_path.parent} 与 {sdir}")
    else:
        print(f"  - 配置文件:           已保留 {cfg_path}（如需一并清除请运行 ai-proxy uninstall --purge）")


def cmd_check_update(args: argparse.Namespace) -> None:
    cfg = load_config()
    upstream = cfg.get("upstream", "socks5://127.0.0.1:7890")
    repo = (getattr(args, "repo", None) or os.environ.get("AI_PROXY_REPO") or DEFAULT_REPO).strip()

    try:
        release = fetch_release_info(repo, version=None, upstream=upstream)
    except (RuntimeError, ValueError) as exc:
        print(f"[错误] 检查更新失败: {exc}", file=sys.stderr)
        sys.exit(1)

    remote_ver = release["version"]
    print(f"当前版本: v{__version__}")
    print(f"最新版本: v{remote_ver}")
    print(f"发布地址: {release['html_url']}")
    if is_newer_version(remote_ver, __version__):
        print("发现新版本！执行 ai-proxy upgrade 即可一键升级。")
    else:
        print("[OK] 当前已是最新版本。")


def cmd_upgrade(args: argparse.Namespace) -> None:
    if getattr(args, "check", False):
        cmd_check_update(args)
        return

    exe_path = get_standalone_executable()
    if exe_path is None:
        print(
            "[错误] 当前从源码目录运行，无法原地覆盖源码。请通过 git pull && ./scripts/build.sh 更新，或先使用安装脚本安装单文件版本。",
            file=sys.stderr,
        )
        sys.exit(1)

    cfg = load_config()
    upstream = cfg.get("upstream", "socks5://127.0.0.1:7890")
    repo = (getattr(args, "repo", None) or os.environ.get("AI_PROXY_REPO") or DEFAULT_REPO).strip()
    target_version = getattr(args, "version", None)

    try:
        release = fetch_release_info(repo, version=target_version, upstream=upstream)
    except (RuntimeError, ValueError) as exc:
        print(f"[错误] 获取版本信息失败: {exc}", file=sys.stderr)
        sys.exit(1)

    remote_ver = release["version"]
    if not getattr(args, "force", False) and not target_version and not is_newer_version(remote_ver, __version__):
        print(f"[OK] 当前已是最新版本 (v{__version__})，无需升级（如需强制重装可加 --force）。")
        return

    dir_writable = os.access(exe_path.parent, os.W_OK)
    file_writable = (not exe_path.exists()) or exe_path.is_symlink() or os.access(exe_path, os.W_OK)
    if os.geteuid() != 0 and not (dir_writable and file_writable):
        require_root("需要管理员权限以替换可执行文件，正在请求 sudo 授权...")

    assets = release.get("assets") or {}
    bin_url = assets.get("ai-proxy")
    sums_url = assets.get("SHA256SUMS")
    if not bin_url or not sums_url:
        print(
            f"[错误] Release {release['tag_name']} 缺少必需产物 (ai-proxy 或 SHA256SUMS)。",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"正在下载 ai-proxy {release['tag_name']}...")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            bin_tmp = tmp_dir / "ai-proxy"
            sums_tmp = tmp_dir / "SHA256SUMS"
            download_file(sums_url, sums_tmp, upstream=upstream, timeout=30)
            download_file(bin_url, bin_tmp, upstream=upstream, timeout=90)
            sums_text = sums_tmp.read_text(encoding="utf-8")
            digest = verify_file_sha256(bin_tmp, sums_text, "ai-proxy")
            os.chmod(bin_tmp, 0o755)
            smoke_test_binary(bin_tmp, expected_version=remote_ver)
            atomic_replace_binary(bin_tmp, exe_path)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"[错误] 升级失败: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[OK] ai-proxy 已升级: v{__version__} -> v{remote_ver} ({exe_path})")
    print(f"  - SHA256: {digest}")

    if is_pid_running(read_pid()):
        print("检测到代理服务正在运行，正在使用新版本平滑重启...")
        subprocess.run([str(exe_path), "restart"], check=False)


def _cmd_relay(args: argparse.Namespace) -> None:
    relay_argv = ["--config", args.config]
    if args.log:
        relay_argv.extend(["--log", args.log])
    run_relay_cli(relay_argv)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-proxy",
        description="macOS 免 TUN 透明代理开关工具（/etc/resolver 分域 DNS + SNI Relay -> FlClash 默认模式）",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"ai-proxy {__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("on", help="开启免 TUN 代理（SNI + 本地 DNS + /etc/resolver + Codex .env / launchctl）")
    sub.add_parser("off", help="关闭并彻底撤回（清理 /etc/resolver、停服务、清 Codex .env 与 launchctl）")
    sub.add_parser("restart", help="重启代理并刷新所有托管配置")
    sub.add_parser("status", help="查看当前运行与托管状态")
    sub.add_parser("check", help="全面检测：FlClash 出口地区、/etc/resolver、Codex 环境及核心接口连通性")

    p_cfg = sub.add_parser("config", help="查看或修改上游 FlClash 代理地址及服务开关")
    p_cfg.add_argument("--proxy", help="例如 socks5://127.0.0.1:7890 或 http://127.0.0.1:7890")
    agy_grp = p_cfg.add_mutually_exclusive_group()
    agy_grp.add_argument("--enable-agy", action="store_true", help="启用 Antigravity (agy) 代理")
    agy_grp.add_argument("--disable-agy", action="store_true", help="禁用 Antigravity (agy) 代理")
    codex_grp = p_cfg.add_mutually_exclusive_group()
    codex_grp.add_argument("--enable-codex", action="store_true", help="启用 Codex 代理")
    codex_grp.add_argument("--disable-codex", action="store_true", help="禁用 Codex 代理")
    lc_grp = p_cfg.add_mutually_exclusive_group()
    lc_grp.add_argument("--enable-launchctl", action="store_true", help="启用 Codex GUI launchctl 会话变量")
    lc_grp.add_argument("--disable-launchctl", action="store_true", help="禁用 Codex GUI launchctl 会话变量")

    p_dom = sub.add_parser("domains", help="管理各服务 /etc/resolver 托管域名区域")
    p_dom.add_argument("action", nargs="?", choices=["list", "add", "remove"], default="list")
    p_dom.add_argument("domain", nargs="?", help="要添加或删除的域名（如 googleapis.com）")
    p_dom.add_argument("--service", choices=["antigravity", "codex"], default="antigravity", help="添加域名到哪个服务（默认 antigravity）")

    p_log = sub.add_parser("logs", help="查看转发日志")
    p_log.add_argument("-n", "--lines", type=int, default=40, help="显示最近 N 行（默认 40）")
    p_log.add_argument("-f", "--follow", action="store_true", help="实时跟踪日志")

    p_chk_upd = sub.add_parser("check-update", help="检查 GitHub Releases 是否有新版本")
    p_chk_upd.add_argument("--repo", help="覆盖 GitHub 仓库（格式 owner/repo）")

    p_upg = sub.add_parser("upgrade", help="从 GitHub Releases 自动下载并升级单文件可执行程序")
    p_upg.add_argument("--check", action="store_true", help="仅检查更新，不执行下载安装")
    p_upg.add_argument("--version", help="指定安装版本（如 v1.0.0）")
    p_upg.add_argument("--force", action="store_true", help="即使已是最新版本也强制重新下载安装")
    p_upg.add_argument("--repo", help="覆盖 GitHub 仓库（格式 owner/repo）")

    p_un = sub.add_parser("uninstall", help="清理代理并卸载 ai-proxy 可执行文件")
    p_un.add_argument("--purge", action="store_true", help="一并删除配置文件与运行状态/日志目录")

    p_relay = sub.add_parser("_relay")
    p_relay.add_argument("--config", required=True)
    p_relay.add_argument("--log", default=None)

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "on": cmd_on,
        "off": cmd_off,
        "restart": cmd_restart,
        "status": cmd_status,
        "check": cmd_check,
        "config": cmd_config,
        "domains": cmd_domains,
        "logs": cmd_logs,
        "check-update": cmd_check_update,
        "upgrade": cmd_upgrade,
        "uninstall": cmd_uninstall,
        "_relay": _cmd_relay,
    }
    handlers[args.command](args)
