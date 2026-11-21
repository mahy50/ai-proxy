import argparse
import asyncio
import contextlib
import hashlib
import io
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import ai_proxy  # noqa: E402
from ai_proxy import cli, codex, config, relay, resolver, updater  # noqa: E402


def build_tls_client_hello(sni: str, extra_padding: int = 0) -> bytes:
    host_bytes = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(host_bytes)) + host_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    pad_ext = b""
    if extra_padding > 0:
        pad_ext = struct.pack("!HH", 0x0033, extra_padding) + (b"\xAA" * extra_padding)

    extensions = pad_ext + sni_ext
    body = (
        b"\x03\x03"
        + (b"\x11" * 32)
        + b"\x00"
        + struct.pack("!HH", 2, 0x1301)
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def wrap_tls_records(handshake: bytes, max_record_len: int = 16384) -> bytes:
    out = bytearray()
    for i in range(0, len(handshake), max_record_len):
        chunk = handshake[i : i + max_record_len]
        out.extend(b"\x16\x03\x01" + struct.pack("!H", len(chunk)) + chunk)
    return bytes(out)


def build_dns_query(domain: str, qtype: int, qclass: int = 1, txid: int = 0xABCD, rd: int = 1) -> bytes:
    flags = 0x0100 if rd else 0x0000
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    qname = bytearray()
    for part in domain.strip(".").split("."):
        encoded = part.encode("ascii")
        qname.append(len(encoded))
        qname.extend(encoded)
    qname.append(0)
    return header + bytes(qname) + struct.pack("!HH", qtype, qclass)


class TestAiProxy(unittest.TestCase):
    def test_version_consistency(self):
        version_txt = (ROOT_DIR / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(version_txt, ai_proxy.__version__)

    def test_config_auto_init_and_non_destructive_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / ".config" / "ai-proxy" / "config.json"
            cfg = config.load_config(cfg_path, auto_init=True)
            self.assertTrue(cfg_path.exists())
            self.assertEqual(cfg["schema_version"], config.SCHEMA_VERSION)
            self.assertEqual(cfg["upstream"], "socks5://127.0.0.1:7890")

            # Simulate an older/partial user config without schema_version or dns_port
            partial = {
                "upstream": "http://127.0.0.1:7897",
                "services": {
                    "antigravity": {
                        "enabled": False,
                        "domains": ["googleapis.com"],
                    },
                    "codex": {
                        "enabled": True,
                        "domains": ["openai.com", "custom.ai"],
                    },
                },
            }
            cfg_path.write_text(json.dumps(partial), encoding="utf-8")
            upgraded = config.load_config(cfg_path, auto_init=False)
            self.assertEqual(upgraded["schema_version"], config.SCHEMA_VERSION)
            self.assertEqual(upgraded["upstream"], "http://127.0.0.1:7897")
            self.assertEqual(upgraded["dns_port"], 15353)
            self.assertFalse(upgraded["services"]["antigravity"]["enabled"])
            self.assertEqual(upgraded["services"]["antigravity"]["domains"], ["googleapis.com"])
            self.assertEqual(upgraded["services"]["codex"]["domains"], ["openai.com", "custom.ai"])
            self.assertTrue(upgraded["services"]["codex"]["manage_env"])

    def test_get_enabled_domains(self):
        cfg = {
            "services": {
                "antigravity": {
                    "enabled": True,
                    "domains": ["googleapis.com", "OPENAI.COM"],
                },
                "codex": {
                    "enabled": True,
                    "domains": ["openai.com", "chatgpt.com"],
                },
            }
        }
        self.assertEqual(
            config.get_enabled_domains(cfg),
            ["googleapis.com", "openai.com", "chatgpt.com"],
        )

        cfg["services"]["codex"]["enabled"] = False
        self.assertEqual(
            config.get_enabled_domains(cfg),
            ["googleapis.com", "openai.com"],
        )

    def test_sni_parsing_standard_and_fragmented(self):
        async def run():
            hs1 = build_tls_client_hello("cloudcode-pa.googleapis.com")
            self.assertEqual(relay.parse_sni_from_handshake(hs1), "cloudcode-pa.googleapis.com")

            hs2 = build_tls_client_hello("api.openai.com", extra_padding=2000)
            recs = wrap_tls_records(hs2, max_record_len=900)
            reader = asyncio.StreamReader()
            reader.feed_data(recs[:100])
            reader.feed_data(recs[100:1100])
            reader.feed_data(recs[1100:])
            reader.feed_eof()
            sni, raw = await relay.read_client_hello_and_sni(reader, timeout=2.0)
            self.assertEqual(sni, "api.openai.com")
            self.assertEqual(raw, recs)

        asyncio.run(run())

    def test_dns_response_builder(self):
        q_a = build_dns_query("daily-cloudcode-pa.googleapis.com", qtype=1, txid=0x1357, rd=1)
        r_a = relay.build_dns_response(q_a)
        self.assertIsNotNone(r_a)
        txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", r_a[:12])
        self.assertEqual(txid, 0x1357)
        self.assertEqual(flags & 0x858F, 0x8580)
        self.assertEqual((qd, an, ns, ar), (1, 1, 0, 0))
        self.assertTrue(r_a.endswith(socket.inet_aton("127.0.0.1")))

        q_aaaa = build_dns_query("api.openai.com", qtype=28, txid=0x2468, rd=0)
        r_aaaa = relay.build_dns_response(q_aaaa)
        self.assertIsNotNone(r_aaaa)
        txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", r_aaaa[:12])
        self.assertEqual(txid, 0x2468)
        self.assertEqual(flags & 0x858F, 0x8480)
        self.assertEqual((qd, an, ns, ar), (1, 1, 0, 0))
        self.assertTrue(r_aaaa.endswith(socket.inet_pton(socket.AF_INET6, "::1")))

        q_https = build_dns_query("chatgpt.com", qtype=65, txid=0x9999, rd=1)
        r_https = relay.build_dns_response(q_https)
        self.assertIsNotNone(r_https)
        txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", r_https[:12])
        self.assertEqual(txid, 0x9999)
        self.assertEqual(flags & 0x800F, 0x8000)
        self.assertEqual((qd, an, ns, ar), (1, 0, 0, 0))
        self.assertEqual(r_https[12:], q_https[12:])

        self.assertIsNone(relay.build_dns_response(b"\x00\x01"))

    def test_upstream_socks5_and_http_connect_handshakes(self):
        async def make_stream_pair():
            s1, s2 = socket.socketpair()
            s1.setblocking(False)
            s2.setblocking(False)
            r1, w1 = await asyncio.open_connection(sock=s1)
            r2, w2 = await asyncio.open_connection(sock=s2)
            return (r1, w1), (r2, w2)

        async def run():
            orig_open = asyncio.open_connection

            # 1. SOCKS5 domain handshake
            (c_r, c_w), (s_r, s_w) = await make_stream_pair()

            async def fake_open_socks(host, port):
                return c_r, c_w

            async def mock_socks5_domain():
                head = await s_r.readexactly(2)
                await s_r.readexactly(head[1])
                s_w.write(b"\x05\x00")
                await s_w.drain()
                req = await s_r.readexactly(4)
                self.assertEqual(req, b"\x05\x01\x00\x03")
                dlen = (await s_r.readexactly(1))[0]
                host = (await s_r.readexactly(dlen)).decode("ascii")
                port = struct.unpack("!H", await s_r.readexactly(2))[0]
                self.assertEqual((host, port), ("api.openai.com", 443))
                s_w.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                await s_w.drain()
                data = await s_r.read(64)
                s_w.write(b"OK:" + data)
                await s_w.drain()
                s_w.close()

            relay.asyncio.open_connection = fake_open_socks
            try:
                srv_task = asyncio.create_task(mock_socks5_domain())
                up_r, up_w = await relay.open_via_socks5(
                    "127.0.0.1", 7890, "api.openai.com", 443, None, None, 2.0
                )
                up_w.write(b"HELLO")
                await up_w.drain()
                reply = await up_r.read(64)
                self.assertEqual(reply, b"OK:HELLO")
                await srv_task
                up_w.close()
            finally:
                relay.asyncio.open_connection = orig_open

            # 2. HTTP CONNECT handshake
            (hc_r, hc_w), (hs_r, hs_w) = await make_stream_pair()

            async def fake_open_http(host, port):
                return hc_r, hc_w

            async def mock_http_connect():
                line = await hs_r.readline()
                self.assertTrue(
                    line.startswith(b"CONNECT daily-cloudcode-pa.googleapis.com:443 HTTP/1.1")
                )
                while True:
                    hdr = await hs_r.readline()
                    if hdr in (b"\r\n", b"\n", b""):
                        break
                hs_w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await hs_w.drain()
                data = await hs_r.read(64)
                hs_w.write(b"HTTP_OK:" + data)
                await hs_w.drain()
                hs_w.close()

            relay.asyncio.open_connection = fake_open_http
            try:
                srv_task = asyncio.create_task(mock_http_connect())
                up_r, up_w = await relay.open_via_http_connect(
                    "127.0.0.1", 7890, "daily-cloudcode-pa.googleapis.com", 443, None, None, 2.0
                )
                up_w.write(b"TLS")
                await up_w.drain()
                reply = await up_r.read(64)
                self.assertEqual(reply, b"HTTP_OK:TLS")
                await srv_task
                up_w.close()
            finally:
                relay.asyncio.open_connection = orig_open

        asyncio.run(run())

    def test_strip_managed_block_idempotency(self):
        sample = "OPENAI_API_KEY=sk-test\nOTHER=1\n"
        block = (
            f"\n{codex.START_MARKER}\n"
            "HTTP_PROXY=http://127.0.0.1:7890\n"
            f"{codex.END_MARKER}\n"
        )
        cleaned = codex.strip_managed_block(sample + block)
        self.assertEqual(cleaned, sample)
        self.assertEqual(codex.strip_managed_block(cleaned), sample)
        self.assertEqual(codex.strip_managed_block(block), "")

    def test_resolver_files_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            rdir = Path(tmp) / "resolver"
            rdir.mkdir()
            unmanaged = rdir / "corp.internal"
            unmanaged.write_text("nameserver 10.0.0.2\n", encoding="utf-8")
            colliding = rdir / "openai.com"
            colliding.write_text("nameserver 1.1.1.1\n", encoding="utf-8")

            written, skipped = resolver.write_resolver_files(
                ["googleapis.com", "openai.com", "chatgpt.com", "../bad"],
                dns_port=15353,
                resolver_dir=rdir,
            )
            self.assertEqual(written, 2)
            self.assertEqual(set(skipped), {"openai.com", "../bad"})
            self.assertEqual(colliding.read_text(encoding="utf-8"), "nameserver 1.1.1.1\n")
            self.assertEqual(unmanaged.read_text(encoding="utf-8"), "nameserver 10.0.0.2\n")

            g_content = (rdir / "googleapis.com").read_text(encoding="utf-8")
            self.assertIn(resolver.RESOLVER_MARKER, g_content)
            self.assertIn("nameserver 127.0.0.1", g_content)
            self.assertIn("port 15353", g_content)
            self.assertEqual(
                resolver.list_managed_resolver_files(rdir),
                ["chatgpt.com", "googleapis.com"],
            )

            removed = resolver.remove_resolver_files(rdir)
            self.assertEqual(removed, 2)
            self.assertEqual(resolver.list_managed_resolver_files(rdir), [])
            self.assertFalse((rdir / "googleapis.com").exists())
            self.assertFalse((rdir / "chatgpt.com").exists())
            self.assertEqual(unmanaged.read_text(encoding="utf-8"), "nameserver 10.0.0.2\n")
            self.assertEqual(colliding.read_text(encoding="utf-8"), "nameserver 1.1.1.1\n")

    def test_codex_env_lifecycle(self):
        uid, gid = os.getuid(), os.getgid()

        # Case (a): preserve pre-existing OPENAI_API_KEY
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            home_a = tmp_path / "home_a"
            state_a = tmp_path / "state_a"
            codex_dir = home_a / ".codex"
            codex_dir.mkdir(parents=True)
            env_file = codex_dir / ".env"
            env_file.write_text("OPENAI_API_KEY=sk-test-123\n", encoding="utf-8")

            written_path, http_url = codex.write_codex_env(
                "socks5://127.0.0.1:7890",
                home_dir=home_a,
                state_dir=state_a,
                user_ids=(uid, gid),
            )
            self.assertEqual(written_path, env_file)
            self.assertEqual(http_url, "http://127.0.0.1:7890")
            self.assertIn("OPENAI_API_KEY=sk-test-123", env_file.read_text(encoding="utf-8"))
            self.assertTrue(codex.has_codex_env(home_dir=home_a))
            self.assertEqual(
                (state_a / "codex.env.original.bak").read_text(encoding="utf-8"),
                "OPENAI_API_KEY=sk-test-123\n",
            )

            removed = codex.remove_codex_env(
                home_dir=home_a, state_dir=state_a, user_ids=(uid, gid)
            )
            self.assertTrue(removed)
            self.assertTrue(env_file.exists())
            self.assertEqual(env_file.read_text(encoding="utf-8"), "OPENAI_API_KEY=sk-test-123\n")
            self.assertFalse(codex.has_codex_env(home_dir=home_a))

        # Case (b): newly created empty .env should be deleted on off
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            home_b = tmp_path / "home_b"
            state_b = tmp_path / "state_b"
            home_b.mkdir(parents=True)

            env_path, _ = codex.write_codex_env(
                "http://127.0.0.1:7890",
                home_dir=home_b,
                state_dir=state_b,
                user_ids=(uid, gid),
            )
            self.assertTrue(env_path.exists())
            removed = codex.remove_codex_env(
                home_dir=home_b, state_dir=state_b, user_ids=(uid, gid)
            )
            self.assertTrue(removed)
            self.assertFalse(env_path.exists())
            self.assertFalse((state_b / "codex.meta.json").exists())

        # Case (c): upgrading over an ai-proxy-managed-only .env without meta file still deletes it on off
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            home_c = tmp_path / "home_c"
            state_c = tmp_path / "state_c"
            (home_c / ".codex").mkdir(parents=True)
            env_c = home_c / ".codex" / ".env"
            env_c.write_text(
                f"{codex.START_MARKER}\nHTTP_PROXY=http://127.0.0.1:7890\n{codex.END_MARKER}\n",
                encoding="utf-8",
            )

            codex.write_codex_env(
                "socks5://127.0.0.1:7890",
                home_dir=home_c,
                state_dir=state_c,
                user_ids=(uid, gid),
            )
            removed = codex.remove_codex_env(
                home_dir=home_c, state_dir=state_c, user_ids=(uid, gid)
            )
            self.assertTrue(removed)
            self.assertFalse(env_c.exists())

    def test_dist_zipapp_cli(self):
        dist_bin = ROOT_DIR / "dist" / "ai-proxy"
        self.assertTrue(
            dist_bin.exists(),
            "dist/ai-proxy not found; run ./scripts/build.sh first",
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = os.environ.copy()
            env["AI_PROXY_CONFIG"] = str(tmp_path / "cfg" / "config.json")
            env["AI_PROXY_STATE_DIR"] = str(tmp_path / "state")

            res_ver = subprocess.run(
                [str(dist_bin), "--version"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(res_ver.stdout.strip(), f"ai-proxy {ai_proxy.__version__}")

            res_help = subprocess.run(
                [str(dist_bin), "--help"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("uninstall", res_help.stdout)
            self.assertIn("check-update", res_help.stdout)
            self.assertIn("upgrade", res_help.stdout)

            res_cfg = subprocess.run(
                [str(dist_bin), "config"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            parsed = json.loads(res_cfg.stdout)
            self.assertEqual(parsed["schema_version"], config.SCHEMA_VERSION)
            self.assertTrue(Path(env["AI_PROXY_CONFIG"]).exists())

    def test_semver_parsing_and_comparison(self):
        self.assertEqual(updater.parse_semver("v1.0.0"), (1, 0, 0, 1, ""))
        self.assertEqual(updater.parse_semver("1.2.3-rc.1+build.5"), (1, 2, 3, 0, "rc.1"))
        self.assertTrue(updater.is_newer_version("v1.0.1", "1.0.0"))
        self.assertTrue(updater.is_newer_version("v1.1.0", "1.0.9"))
        self.assertTrue(updater.is_newer_version("2.0.0", "1.9.9"))
        self.assertTrue(updater.is_newer_version("1.0.0", "1.0.0-rc.1"))
        self.assertFalse(updater.is_newer_version("1.0.0", "v1.0.0"))
        self.assertFalse(updater.is_newer_version("0.9.9", "1.0.0"))
        self.assertEqual(updater.normalize_tag("1.0.2"), "v1.0.2")
        self.assertEqual(updater.normalize_tag("V1.0.2"), "v1.0.2")
        for bad in ("not-a-version", "", "1.0"):
            with self.assertRaises(ValueError):
                updater.parse_semver(bad)

    def test_sha256sums_parsing_and_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            payload = b"hello ai-proxy zipapp\n"
            digest = hashlib.sha256(payload).hexdigest()
            sample = tmp_path / "ai-proxy"
            sample.write_bytes(payload)

            sums_text = (
                f"{digest}  ai-proxy\n"
                f"{'0' * 64} *ai-proxy-v1.0.0.tar.gz\n"
            )
            parsed = updater.parse_sha256sums(sums_text)
            self.assertEqual(parsed["ai-proxy"], digest)
            self.assertEqual(parsed["ai-proxy-v1.0.0.tar.gz"], "0" * 64)
            self.assertEqual(updater.verify_file_sha256(sample, sums_text, "ai-proxy"), digest)

            with self.assertRaises(ValueError):
                updater.verify_file_sha256(sample, f"{'f' * 64}  ai-proxy\n", "ai-proxy")
            with self.assertRaises(ValueError):
                updater.verify_file_sha256(sample, sums_text, "missing-file")

    def test_upgrade_check_and_source_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_patch = {
                "AI_PROXY_CONFIG": str(tmp_path / "cfg" / "config.json"),
                "AI_PROXY_STATE_DIR": str(tmp_path / "state"),
            }
            with patch.dict(os.environ, env_patch):
                newer_release = {
                    "tag_name": "v9.9.9",
                    "version": "9.9.9",
                    "html_url": "https://github.com/mahy50/ai-proxy/releases/tag/v9.9.9",
                    "published_at": "2026-11-20T00:00:00Z",
                    "assets": {},
                }
                buf_new = io.StringIO()
                with patch.object(cli, "fetch_release_info", return_value=newer_release):
                    with contextlib.redirect_stdout(buf_new):
                        cli.cmd_check_update(argparse.Namespace(repo=None))
                out_new = buf_new.getvalue()
                self.assertIn("v9.9.9", out_new)
                self.assertIn("发现新版本", out_new)

                same_release = {
                    "tag_name": f"v{ai_proxy.__version__}",
                    "version": ai_proxy.__version__,
                    "html_url": f"https://github.com/mahy50/ai-proxy/releases/tag/v{ai_proxy.__version__}",
                    "published_at": "2026-11-20T00:00:00Z",
                    "assets": {},
                }
                buf_same = io.StringIO()
                with patch.object(cli, "fetch_release_info", return_value=same_release):
                    with contextlib.redirect_stdout(buf_same):
                        cli.cmd_check_update(argparse.Namespace(repo=None))
                self.assertIn("当前已是最新版本", buf_same.getvalue())

                err_buf = io.StringIO()
                with patch.object(cli, "get_standalone_executable", return_value=None):
                    with contextlib.redirect_stderr(err_buf):
                        with self.assertRaises(SystemExit) as cm:
                            cli.cmd_upgrade(
                                argparse.Namespace(
                                    check=False, version=None, force=False, repo=None
                                )
                            )
                self.assertEqual(cm.exception.code, 1)
                self.assertIn("源码目录运行", err_buf.getvalue())

    def test_atomic_replace_binary_over_dangling_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            dest = tmp_path / "ai-proxy"
            dest.symlink_to(tmp_path / "nonexistent-target")
            self.assertTrue(dest.is_symlink())
            self.assertFalse(dest.exists())

            src = tmp_path / "new-ai-proxy"
            payload = b"#!/usr/bin/env python3\nprint('ai-proxy test')\n"
            src.write_bytes(payload)

            updater.atomic_replace_binary(src, dest)
            self.assertFalse(dest.is_symlink())
            self.assertTrue(dest.is_file())
            self.assertEqual(dest.read_bytes(), payload)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
