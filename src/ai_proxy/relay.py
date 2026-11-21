"""
Lightweight local UDP DNS responder (127.0.0.1:15353) and TLS SNI TCP relay
(:443) for ai-proxy.
Resolves managed /etc/resolver/ domains to loopback, reads TLS SNI from
ClientHello without decrypting traffic, and forwards raw TLS streams to an
upstream SOCKS5 or HTTP CONNECT proxy (e.g., FlClash).
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import signal
import socket
import struct
import sys
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse


MAX_CLIENT_HELLO_BYTES = 64 * 1024  # 64 KiB cap for safety
BUFFER_SIZE = 65536


def _set_nodelay(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass


def build_dns_response(query: bytes) -> Optional[bytes]:
    """
    Build a minimal RFC 1035 UDP DNS response resolving A -> 127.0.0.1,
    AAAA -> ::1, and returning clean NOERROR NODATA for other record types (e.g. HTTPS/SVCB).
    """
    if len(query) < 12:
        return None

    txid, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", query[:12])
    if qdcount == 0:
        return None

    pos = 12
    q_len = len(query)
    while True:
        if pos >= q_len:
            return None
        label_len = query[pos]
        if label_len == 0:
            pos += 1
            break
        if (label_len & 0xC0) != 0:
            return None
        pos += 1 + label_len
        if pos > q_len:
            return None

    if pos + 4 > q_len:
        return None

    qtype, qclass = struct.unpack("!HH", query[pos : pos + 4])
    q_end = pos + 4
    question = query[12:q_end]

    # QR=1, AA=1, RA=1, preserve RD, RCODE=0
    resp_flags = 0x8480 | (flags & 0x0100)
    answer = b""
    ancount = 0

    if qclass == 1 and qtype == 1:  # IN A
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("127.0.0.1")
        ancount = 1
    elif qclass == 1 and qtype == 28:  # IN AAAA
        answer = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 28, 1, 30, 16)
            + socket.inet_pton(socket.AF_INET6, "::1")
        )
        ancount = 1

    header = struct.pack("!HHHHHH", txid, resp_flags, 1, ancount, 0, 0)
    return header + question + answer


class LocalDNSProtocol(asyncio.DatagramProtocol):
    """Lightweight UDP DNS responder serving local /etc/resolver/ zones."""

    def __init__(self) -> None:
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            resp = build_dns_response(data)
            if resp is not None and self.transport is not None:
                self.transport.sendto(resp, addr)
        except Exception as exc:
            logging.debug("Local DNS responder error from %s: %s", addr, exc)


def parse_sni_from_handshake(hs: bytes) -> Optional[str]:
    """Parse SNI hostname from a TLS Handshake ClientHello message."""
    if len(hs) < 4 or hs[0] != 0x01:  # HandshakeType.client_hello
        return None

    hs_len = int.from_bytes(hs[1:4], "big")
    if len(hs) < 4 + hs_len:
        return None

    pos = 4
    end = 4 + hs_len

    # client_version (2) + random (32)
    if pos + 34 > end:
        return None
    pos += 34

    # session_id (1-byte length + bytes)
    if pos + 1 > end:
        return None
    session_id_len = hs[pos]
    pos += 1 + session_id_len
    if pos + 2 > end:
        return None

    # cipher_suites (2-byte length + bytes)
    cipher_suites_len = int.from_bytes(hs[pos : pos + 2], "big")
    pos += 2 + cipher_suites_len
    if pos + 1 > end:
        return None

    # compression_methods (1-byte length + bytes)
    comp_len = hs[pos]
    pos += 1 + comp_len
    if pos + 2 > end:
        return None

    # extensions (2-byte total length)
    ext_total_len = int.from_bytes(hs[pos : pos + 2], "big")
    pos += 2
    ext_end = min(pos + ext_total_len, end)

    while pos + 4 <= ext_end:
        ext_type = int.from_bytes(hs[pos : pos + 2], "big")
        ext_len = int.from_bytes(hs[pos + 2 : pos + 4], "big")
        pos += 4
        if pos + ext_len > ext_end:
            break

        if ext_type == 0x0000:  # server_name extension
            sni_pos = pos
            sni_end = pos + ext_len
            if sni_pos + 2 > sni_end:
                return None
            list_len = int.from_bytes(hs[sni_pos : sni_pos + 2], "big")
            sni_pos += 2
            list_end = min(sni_pos + list_len, sni_end)
            while sni_pos + 3 <= list_end:
                name_type = hs[sni_pos]
                name_len = int.from_bytes(hs[sni_pos + 1 : sni_pos + 3], "big")
                sni_pos += 3
                if sni_pos + name_len > list_end:
                    return None
                if name_type == 0x00:  # host_name
                    try:
                        return hs[sni_pos : sni_pos + name_len].decode("ascii").strip(".")
                    except UnicodeDecodeError:
                        return None
                sni_pos += name_len

        pos += ext_len

    return None


async def read_client_hello_and_sni(
    reader: asyncio.StreamReader, timeout: float
) -> Tuple[Optional[str], bytes]:
    """
    Read one or more TLS handshake records until the full ClientHello handshake
    message is available (supports fragmented / post-quantum MLKEM ClientHello).
    Returns (sni_hostname, raw_bytes_read).
    """
    raw_buf = bytearray()
    hs_buf = bytearray()
    expected_hs_total: Optional[int] = None

    while len(raw_buf) < MAX_CLIENT_HELLO_BYTES:
        header = await asyncio.wait_for(reader.readexactly(5), timeout=timeout)
        raw_buf.extend(header)

        content_type = header[0]
        major_ver = header[1]
        record_len = int.from_bytes(header[3:5], "big")

        if content_type != 0x16 or major_ver != 0x03 or record_len == 0:
            return None, bytes(raw_buf)
        if len(raw_buf) + record_len > MAX_CLIENT_HELLO_BYTES:
            return None, bytes(raw_buf)

        payload = await asyncio.wait_for(reader.readexactly(record_len), timeout=timeout)
        raw_buf.extend(payload)
        hs_buf.extend(payload)

        if expected_hs_total is None and len(hs_buf) >= 4:
            if hs_buf[0] != 0x01:  # Not ClientHello
                return None, bytes(raw_buf)
            expected_hs_total = 4 + int.from_bytes(hs_buf[1:4], "big")

        if expected_hs_total is not None and len(hs_buf) >= expected_hs_total:
            sni = parse_sni_from_handshake(bytes(hs_buf))
            return sni, bytes(raw_buf)

    return None, bytes(raw_buf)


def _build_socks5_connect_request(target_host: str, target_port: int) -> bytes:
    host_bytes = target_host.encode("ascii")
    if len(host_bytes) > 255:
        raise ConnectionError(f"Target hostname too long: {target_host}")
    return (
        b"\x05\x01\x00\x03"
        + struct.pack("!B", len(host_bytes))
        + host_bytes
        + struct.pack("!H", target_port)
    )


async def open_via_socks5(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    username: Optional[str],
    password: Optional[str],
    timeout: float,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port), timeout=timeout
    )
    try:
        _set_nodelay(writer)

        if username is not None:
            writer.write(b"\x05\x02\x00\x02")
        else:
            writer.write(b"\x05\x01\x00")
        await writer.drain()

        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp[0] != 0x05:
            raise ConnectionError(f"Invalid SOCKS5 version: {resp[0]}")

        method = resp[1]
        if method == 0x02:
            if username is None or password is None:
                raise ConnectionError("SOCKS5 proxy requires authentication")
            u_bytes = username.encode("utf-8")
            p_bytes = password.encode("utf-8")
            writer.write(
                struct.pack("!BB", 0x01, len(u_bytes))
                + u_bytes
                + struct.pack("!B", len(p_bytes))
                + p_bytes
            )
            await writer.drain()
            auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            if auth_resp[1] != 0x00:
                raise ConnectionError("SOCKS5 authentication failed")
        elif method != 0x00:
            raise ConnectionError(f"Unsupported SOCKS5 auth method: {method}")

        req = _build_socks5_connect_request(target_host, target_port)
        writer.write(req)
        await writer.drain()

        rep_head = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if rep_head[0] != 0x05 or rep_head[1] != 0x00:
            raise ConnectionError(f"SOCKS5 CONNECT failed, reply code={rep_head[1]}")

        atyp = rep_head[3]
        if atyp == 0x01:  # IPv4
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
        elif atyp == 0x03:  # Domain
            dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
            await asyncio.wait_for(reader.readexactly(dlen + 2), timeout=timeout)
        elif atyp == 0x04:  # IPv6
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)
        else:
            raise ConnectionError(f"Invalid SOCKS5 reply ATYP: {atyp}")

        return reader, writer
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


async def open_via_http_connect(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    username: Optional[str],
    password: Optional[str],
    timeout: float,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port), timeout=timeout
    )
    try:
        _set_nodelay(writer)

        headers = [
            f"CONNECT {target_host}:{target_port} HTTP/1.1",
            f"Host: {target_host}:{target_port}",
            "Proxy-Connection: Keep-Alive",
        ]
        if username is not None:
            creds = f"{username}:{password or ''}".encode("utf-8")
            token = base64.b64encode(creds).decode("ascii")
            headers.append(f"Proxy-Authorization: Basic {token}")

        req = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
        writer.write(req)
        await writer.drain()

        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not status_line:
            raise ConnectionError("Empty HTTP CONNECT response")
        parts = status_line.decode("latin1").strip().split(" ", 2)
        if len(parts) < 2 or parts[1] != "200":
            raise ConnectionError(f"HTTP CONNECT failed: {status_line.decode('latin1').strip()}")

        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not line or line in (b"\r\n", b"\n"):
                break

        return reader, writer
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


async def pipe_stream(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        while True:
            data = await reader.read(BUFFER_SIZE)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass


class SNIRelayServer:
    """Async TCP relay that forwards TLS connections via upstream proxy by SNI."""

    def __init__(
        self,
        upstream_url: str,
        listen_port: int,
        timeout: float,
    ) -> None:
        parsed = urlparse(upstream_url)
        scheme = (parsed.scheme or "socks5").lower()
        if scheme in ("socks5", "socks5h"):
            self.scheme = "socks5"
        elif scheme in ("http", "https"):
            self.scheme = "http"
        else:
            raise ValueError(f"Unsupported upstream scheme: {scheme}")

        self.proxy_host = parsed.hostname or "127.0.0.1"
        self.proxy_port = parsed.port or 7890
        self.username = parsed.username
        self.password = parsed.password
        self.listen_port = listen_port
        self.timeout = timeout
        self.target_port = 443
        self.active_conns = 0

    async def open_upstream(
        self, target_host: str
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self.scheme == "socks5":
            return await open_via_socks5(
                self.proxy_host,
                self.proxy_port,
                target_host,
                self.target_port,
                self.username,
                self.password,
                self.timeout,
            )
        return await open_via_http_connect(
            self.proxy_host,
            self.proxy_port,
            target_host,
            self.target_port,
            self.username,
            self.password,
            self.timeout,
        )

    async def handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        peer = client_writer.get_extra_info("peername")
        up_writer: Optional[asyncio.StreamWriter] = None
        self.active_conns += 1
        try:
            _set_nodelay(client_writer)

            if self.active_conns > 256:
                logging.warning(
                    "Too many concurrent connections (%d); possible routing loop! Rejecting %s",
                    self.active_conns,
                    peer,
                )
                return

            try:
                sni, initial_bytes = await read_client_hello_and_sni(
                    client_reader, self.timeout
                )
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError) as exc:
                logging.debug("Failed reading ClientHello from %s: %s", peer, exc)
                return

            if not sni:
                logging.warning("No valid TLS SNI from %s; closing connection", peer)
                return

            if sni in ("localhost", "127.0.0.1", "::1"):
                logging.warning("Refusing loopback SNI=%s from %s", sni, peer)
                return

            try:
                up_reader, up_writer = await self.open_upstream(sni)
            except Exception as exc:
                logging.error(
                    "Upstream %s://%s:%d connect failed for SNI=%s: %s",
                    self.scheme,
                    self.proxy_host,
                    self.proxy_port,
                    sni,
                    exc,
                )
                return

            logging.info(
                "RELAY %s -> %s:%d via %s://%s:%d",
                peer,
                sni,
                self.target_port,
                self.scheme,
                self.proxy_host,
                self.proxy_port,
            )

            up_writer.write(initial_bytes)
            await up_writer.drain()

            t1 = asyncio.create_task(pipe_stream(client_reader, up_writer))
            t2 = asyncio.create_task(pipe_stream(up_reader, client_writer))
            await asyncio.gather(t1, t2, return_exceptions=True)
        except Exception as exc:
            logging.error("Unhandled error for %s: %s", peer, exc)
        finally:
            self.active_conns -= 1
            for w in (up_writer, client_writer):
                if w is not None:
                    try:
                        w.close()
                        await w.wait_closed()
                    except Exception:
                        pass


async def run_server(config_path: Path, log_path: Optional[Path]) -> None:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    upstream = cfg.get("upstream", "socks5://127.0.0.1:7890")
    listen_port = int(cfg.get("listen_port", 443))
    dns_port = int(cfg.get("dns_port", 15353))
    timeout = float(cfg.get("connect_timeout", 10))

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers = [logging.FileHandler(log_path, encoding="utf-8")]
        try:
            os.chmod(log_path, 0o644)
        except OSError:
            pass

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )

    loop = asyncio.get_running_loop()
    dns_transport: Optional[asyncio.DatagramTransport] = None
    if dns_port > 0:
        dns_transport, _ = await loop.create_datagram_endpoint(
            LocalDNSProtocol, local_addr=("127.0.0.1", dns_port)
        )
        logging.info("DNS responder listening on 127.0.0.1:%d", dns_port)

    relay = SNIRelayServer(upstream, listen_port, timeout)
    servers = []

    try:
        srv_v4 = await asyncio.start_server(
            relay.handle_client, host="127.0.0.1", port=listen_port, reuse_address=True
        )
        servers.append(srv_v4)
        logging.info("Listening on 127.0.0.1:%d -> upstream %s", listen_port, upstream)

        try:
            srv_v6 = await asyncio.start_server(
                relay.handle_client, host="::1", port=listen_port, reuse_address=True
            )
            servers.append(srv_v6)
            logging.info("Listening on [::1]:%d -> upstream %s", listen_port, upstream)
        except OSError as exc:
            logging.warning("IPv6 loopback [::1]:%d unavailable (%s); IPv4 only", listen_port, exc)

        stop_event = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except NotImplementedError:
                pass

        await stop_event.wait()
        logging.info("Shutting down SNI + DNS relay...")
    finally:
        if dns_transport is not None:
            dns_transport.close()
        for srv in servers:
            srv.close()
            await srv.wait_closed()


def run_relay_cli(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="ai-proxy _relay",
        description="ai-proxy internal SNI + DNS relay daemon",
    )
    parser.add_argument("--config", required=True, help="Path to config.json")
    parser.add_argument("--log", default=None, help="Path to log file")
    args = parser.parse_args(argv)

    try:
        asyncio.run(
            run_server(
                Path(args.config),
                Path(args.log) if args.log else None,
            )
        )
    except KeyboardInterrupt:
        pass
