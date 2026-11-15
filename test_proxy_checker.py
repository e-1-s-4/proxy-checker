#!/usr/bin/env python3
"""Comprehensive unit and integration test suite for proxy_checker.py.

Runs 100% locally with zero external internet dependencies by spinning up
in-process asyncio HTTP, HTTPS, CONNECT, SOCKS4/4a, and SOCKS5/5h servers.
"""

from __future__ import annotations

import asyncio
import base64
import csv
import gc
import gzip
import ipaddress
import json
import os
from pathlib import Path
import signal
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Callable, Coroutine, Dict, List, Optional, Set, Tuple

import proxy_checker as pc


def _generate_self_signed_cert(directory: str) -> Tuple[str, str]:
    """Generate a temporary localhost self-signed cert/key pair using openssl."""
    key_path = os.path.join(directory, "key.pem")
    cert_path = os.path.join(directory, "cert.pem")
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert_path, key_path


async def _close_writer(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is None:
        return
    try:
        if not writer.is_closing():
            writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
    except (OSError, asyncio.TimeoutError, asyncio.CancelledError):
        try:
            writer.transport.abort()
        except Exception:
            pass


class TestParsingAndSecurity(unittest.TestCase):
    """Unit tests for proxy parsing, validation, sanitization, and TLS defaults."""

    def test_valid_proxy_formats(self) -> None:
        e1 = pc.parse_proxy_line("127.0.0.1:8080")
        assert e1 is not None
        self.assertEqual(e1.protocol, pc.ProxyProtocol.HTTP)
        self.assertEqual(e1.host, "127.0.0.1")
        self.assertEqual(e1.port, 8080)
        self.assertEqual(e1.output_line(), "127.0.0.1:8080")

        e2 = pc.parse_proxy_line("  socks5h://alice:s%40cret@proxy.example:1080  # note")
        assert e2 is not None
        self.assertEqual(e2.protocol, pc.ProxyProtocol.SOCKS5H)
        self.assertEqual(e2.username, "alice")
        self.assertEqual(e2.password, "s@cret")
        self.assertEqual(e2.host, "proxy.example")
        self.assertEqual(e2.port, 1080)
        self.assertEqual(e2.masked_uri(), "socks5h://***:***@proxy.example:1080")
        self.assertNotIn("alice", repr(e2))
        self.assertNotIn("s@cret", repr(e2))

        e3 = pc.parse_proxy_line("10.0.0.5:3128:bob:pw123")
        assert e3 is not None
        self.assertEqual(e3.host, "10.0.0.5")
        self.assertEqual(e3.port, 3128)
        self.assertEqual(e3.username, "bob")
        self.assertEqual(e3.password, "pw123")

        e4 = pc.parse_proxy_line("https://[::1]:8443")
        assert e4 is not None
        self.assertEqual(e4.protocol, pc.ProxyProtocol.HTTPS)
        self.assertEqual(e4.host, "::1")
        self.assertEqual(e4.port, 8443)
        self.assertEqual(e4.format_host_port(), "[::1]:8443")

    def test_comments_and_bom_skipped(self) -> None:
        self.assertIsNone(pc.parse_proxy_line("\ufeff"))
        self.assertIsNone(pc.parse_proxy_line("   "))
        self.assertIsNone(pc.parse_proxy_line("# comment"))
        self.assertIsNone(pc.parse_proxy_line("  ; comment"))

    def test_malformed_inputs_rejected(self) -> None:
        bad_lines = [
            "ftp://127.0.0.1:21",
            "127.0.0.1",
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "127.0.0.1:abc",
            "bad host:8080",
            "127.0.0.1:8080/path",
            "socks4://user:pass@127.0.0.1:1080",
            f"socks5://{'a' * 256}:pw@127.0.0.1:1080",
            "127.0.0.1:8080\x00",
        ]
        for line in bad_lines:
            with self.subTest(line=line):
                with self.assertRaises(pc.ProxyParseError):
                    pc.parse_proxy_line(line)

    def test_sanitization_and_csv_neutralization(self) -> None:
        msg = pc.sanitize_error_message(
            "Failed connecting http://admin:topsecret@1.2.3.4:8080\nnewline",
            secrets=("topsecret", "admin"),
        )
        self.assertNotIn("topsecret", msg)
        self.assertNotIn("admin", msg)
        self.assertNotIn("\n", msg)

        self.assertEqual(pc.sanitize_csv_cell("=CMD()"), "'=CMD()")
        self.assertEqual(pc.sanitize_csv_cell("+1+1"), "'+1+1")
        self.assertEqual(pc.sanitize_csv_cell("-2+3"), "'-2+3")
        self.assertEqual(pc.sanitize_csv_cell("@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(pc.sanitize_csv_cell(8080), "8080")
        self.assertEqual(pc.sanitize_csv_cell(12.5), "12.5")

    def test_strict_ssl_context_defaults(self) -> None:
        ctx = pc.create_strict_ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)


class TestProxyIntegration(unittest.IsolatedAsyncioTestCase):
    """End-to-end integration tests using local asyncio proxy & target servers."""

    _cert_tmpdir: tempfile.TemporaryDirectory[str]
    cert_path: str
    key_path: str
    server_ssl: ssl.SSLContext
    client_ssl: ssl.SSLContext

    @classmethod
    def setUpClass(cls) -> None:
        cls._cert_tmpdir = tempfile.TemporaryDirectory()
        cls.cert_path, cls.key_path = _generate_self_signed_cert(cls._cert_tmpdir.name)
        cls.server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_ssl.load_cert_chain(cls.cert_path, cls.key_path)
        cls.client_ssl = ssl.create_default_context(cafile=cls.cert_path)
        cls.client_ssl.minimum_version = ssl.TLSVersion.TLSv1_2

    @classmethod
    def tearDownClass(cls) -> None:
        cls._cert_tmpdir.cleanup()

    async def asyncSetUp(self) -> None:
        self._servers: List[asyncio.AbstractServer] = []
        self._handler_tasks: Set[asyncio.Task[None]] = set()

    async def asyncTearDown(self) -> None:
        for srv in self._servers:
            srv.close()
        for task in list(self._handler_tasks):
            task.cancel()
        if self._handler_tasks:
            await asyncio.gather(*self._handler_tasks, return_exceptions=True)
        for srv in self._servers:
            await srv.wait_closed()
        gc.collect()

    def _track_handler(
        self,
        fn: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Coroutine[object, object, None]],
    ) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Coroutine[object, object, None]]:
        async def _wrapper(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            if task is not None:
                self._handler_tasks.add(task)
            try:
                await fn(reader, writer)
            finally:
                await _close_writer(writer)
                if task is not None:
                    self._handler_tasks.discard(task)

        return _wrapper

    async def _start_http_target(
        self,
        *,
        use_tls: bool = False,
        mode: str = "json_ip",
    ) -> Tuple[int, List[Dict[str, str]]]:
        captured_headers: List[Dict[str, str]] = []

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                raw_head = await reader.readuntil(b"\r\n\r\n")
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
                return

            lines = raw_head.decode("latin-1").split("\r\n")
            hdrs: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()
            captured_headers.append(hdrs)

            if mode == "json_ip":
                body = json.dumps({"origin": "198.51.100.42", "headers": hdrs}).encode("utf-8")
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                    + body
                )
            elif mode == "chunked_gzip":
                payload = gzip.compress(b'{"origin":"198.51.100.77"}')
                mid = len(payload) // 2
                c1, c2 = payload[:mid], payload[mid:]
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Encoding: gzip\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Connection: close\r\n\r\n"
                    + f"{len(c1):x}\r\n".encode("ascii")
                    + c1
                    + b"\r\n"
                    + f"{len(c2):x}\r\n".encode("ascii")
                    + c2
                    + b"\r\n0\r\n\r\n"
                )
            elif mode == "interim_100":
                body = b"Example Domain OK"
                writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                await writer.drain()
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                    + body
                )
            elif mode == "captive_portal":
                body = b"<html><body>Sign in to Wi-Fi</body></html>"
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                    + body
                )
            elif mode == "redirect_localhost":
                writer.write(
                    b"HTTP/1.1 302 Found\r\n"
                    b"Location: http://127.0.0.1:9999/internal\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
            elif mode == "oversized_2mb":
                total = 1500 * 1024
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {total}\r\nConnection: close\r\n\r\n".encode("ascii")
                )
                chunk = b"A" * 32768
                sent = 0
                while sent < total:
                    piece = chunk[: min(len(chunk), total - sent)]
                    try:
                        writer.write(piece)
                        await writer.drain()
                    except ConnectionError:
                        break
                    sent += len(piece)
            elif mode == "trickle":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                await writer.drain()
                for _ in range(10):
                    await asyncio.sleep(0.15)
                    try:
                        writer.write(b"x")
                        await writer.drain()
                    except ConnectionError:
                        break
            try:
                await writer.drain()
            except ConnectionError:
                pass

        srv = await asyncio.start_server(
            self._track_handler(handle),
            "127.0.0.1",
            0,
            ssl=self.server_ssl if use_tls else None,
        )
        self._servers.append(srv)
        return srv.sockets[0].getsockname()[1], captured_headers

    async def _pipe(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await r.read(16384)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except (OSError, asyncio.CancelledError):
            pass

    async def _start_http_proxy(
        self,
        *,
        use_tls: bool = False,
        required_auth: Optional[Tuple[str, str]] = None,
        allow_connect: bool = True,
        inject_header: Optional[Tuple[str, str]] = None,
        garbage_banner: bool = False,
    ) -> int:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            up_w: Optional[asyncio.StreamWriter] = None
            try:
                if garbage_banner:
                    writer.write(b"NOT_HTTP_BANNER\r\n")
                    await writer.drain()
                    return
                try:
                    raw_head = await reader.readuntil(b"\r\n\r\n")
                except (asyncio.IncompleteReadError, ConnectionError):
                    return
                lines = raw_head.decode("latin-1").split("\r\n")
                req_parts = lines[0].split()
                if len(req_parts) < 2:
                    return
                method, target = req_parts[0], req_parts[1]
                hdrs: Dict[str, str] = {}
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        hdrs[k.strip().lower()] = v.strip()

                if required_auth is not None:
                    expected = base64.b64encode(
                        f"{required_auth[0]}:{required_auth[1]}".encode("utf-8")
                    ).decode("ascii")
                    if hdrs.get("proxy-authorization") != f"Basic {expected}":
                        writer.write(
                            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                            b"Proxy-Authenticate: Basic realm=\"test\"\r\n"
                            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        await writer.drain()
                        return

                if method.upper() == "CONNECT":
                    if not allow_connect:
                        writer.write(
                            b"HTTP/1.1 405 Method Not Allowed\r\n"
                            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        await writer.drain()
                        return
                    host, port_s = target.rsplit(":", 1)
                    host = host.strip("[]")
                    up_r, up_w = await asyncio.open_connection(host, int(port_s))
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()
                    await asyncio.gather(self._pipe(reader, up_w), self._pipe(up_r, writer))
                    return

                parsed = pc.urlsplit(target)
                up_host = parsed.hostname or "127.0.0.1"
                up_port = parsed.port or 80
                up_path = parsed.path or "/"
                if parsed.query:
                    up_path = f"{up_path}?{parsed.query}"
                up_r, up_w = await asyncio.open_connection(up_host, up_port)
                fwd_lines = [f"{method} {up_path} HTTP/1.1"]
                for line in lines[1:]:
                    if not line:
                        continue
                    k = line.split(":", 1)[0].strip().lower()
                    if k not in ("proxy-authorization", "proxy-connection"):
                        fwd_lines.append(line)
                if inject_header:
                    fwd_lines.append(f"{inject_header[0]}: {inject_header[1]}")
                up_w.write(("\r\n".join(fwd_lines) + "\r\n\r\n").encode("latin-1"))
                await up_w.drain()
                await self._pipe(up_r, writer)
            finally:
                await _close_writer(up_w)

        srv = await asyncio.start_server(
            self._track_handler(handle),
            "127.0.0.1",
            0,
            ssl=self.server_ssl if use_tls else None,
        )
        self._servers.append(srv)
        return srv.sockets[0].getsockname()[1]

    async def _start_socks4_proxy(self, reject: bool = False) -> int:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            up_w: Optional[asyncio.StreamWriter] = None
            try:
                head = await reader.readexactly(8)
                ver, cmd, port = struct.unpack("!BBH", head[:4])
                ip_bytes = head[4:8]
                while (await reader.readexactly(1)) != b"\x00":
                    pass
                if ver != 4 or cmd != 1:
                    return
                if ip_bytes[:3] == b"\x00\x00\x00" and ip_bytes[3] != 0:
                    dom = bytearray()
                    while True:
                        b1 = await reader.readexactly(1)
                        if b1 == b"\x00":
                            break
                        dom.extend(b1)
                    host = dom.decode("ascii")
                else:
                    host = ".".join(str(b) for b in ip_bytes)
                if reject:
                    writer.write(b"\x00\x5b" + struct.pack("!H", 0) + b"\x00\x00\x00\x00")
                    await writer.drain()
                    return
                up_r, up_w = await asyncio.open_connection(host, port)
                writer.write(b"\x00\x5a" + struct.pack("!H", port) + b"\x7f\x00\x00\x01")
                await writer.drain()
                await asyncio.gather(self._pipe(reader, up_w), self._pipe(up_r, writer))
            except (asyncio.IncompleteReadError, OSError):
                pass
            finally:
                await _close_writer(up_w)

        srv = await asyncio.start_server(self._track_handler(handle), "127.0.0.1", 0)
        self._servers.append(srv)
        return srv.sockets[0].getsockname()[1]

    async def _start_socks5_proxy(
        self,
        required_auth: Optional[Tuple[str, str]] = None,
    ) -> int:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            up_w: Optional[asyncio.StreamWriter] = None
            try:
                ver_n = await reader.readexactly(2)
                methods = await reader.readexactly(ver_n[1])
                if required_auth:
                    if 0x02 not in methods:
                        writer.write(b"\x05\xff")
                        await writer.drain()
                        return
                    writer.write(b"\x05\x02")
                    await writer.drain()
                    aver = await reader.readexactly(1)
                    ulen = (await reader.readexactly(1))[0]
                    user = (await reader.readexactly(ulen)).decode("utf-8")
                    plen = (await reader.readexactly(1))[0]
                    pw = (await reader.readexactly(plen)).decode("utf-8")
                    if aver[0] != 1 or (user, pw) != required_auth:
                        writer.write(b"\x01\x01")
                        await writer.drain()
                        return
                    writer.write(b"\x01\x00")
                else:
                    writer.write(b"\x05\x00")
                await writer.drain()

                req = await reader.readexactly(4)
                atyp = req[3]
                if atyp == 0x01:
                    host = ".".join(str(b) for b in await reader.readexactly(4))
                elif atyp == 0x03:
                    dlen = (await reader.readexactly(1))[0]
                    host = (await reader.readexactly(dlen)).decode("ascii")
                elif atyp == 0x04:
                    host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
                else:
                    return
                port = struct.unpack("!H", await reader.readexactly(2))[0]
                up_r, up_w = await asyncio.open_connection(host, port)
                writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", port))
                await writer.drain()
                await asyncio.gather(self._pipe(reader, up_w), self._pipe(up_r, writer))
            except (asyncio.IncompleteReadError, OSError):
                pass
            finally:
                await _close_writer(up_w)

        srv = await asyncio.start_server(self._track_handler(handle), "127.0.0.1", 0)
        self._servers.append(srv)
        return srv.sockets[0].getsockname()[1]

    def _make_client(self, **kwargs: object) -> pc.AsyncProxyClient:
        return pc.AsyncProxyClient(
            proxy_ssl_context=self.client_ssl,
            target_ssl_context=self.client_ssl,
            **kwargs,  # type: ignore[arg-type]
        )

    async def test_all_protocols_and_nested_tls(self) -> None:
        http_port, _ = await self._start_http_target(use_tls=False, mode="json_ip")
        https_port, https_hdrs = await self._start_http_target(use_tls=True, mode="json_ip")

        p_http = await self._start_http_proxy(required_auth=("u1", "p1"))
        p_https = await self._start_http_proxy(use_tls=True, required_auth=("u2", "p2"))
        p_s4 = await self._start_socks4_proxy()
        p_s5 = await self._start_socks5_proxy()
        p_s5_auth = await self._start_socks5_proxy(required_auth=("suser", "spass"))

        targets = (
            pc.TestTarget(url=f"https://localhost:{https_port}/ip", expected_json_key="origin"),
            pc.TestTarget(url=f"http://127.0.0.1:{http_port}/ip", expected_json_key="origin"),
        )
        cfg = pc.CheckerConfig(targets=targets, quiet=True, concurrency=10)
        checker = pc.ProxyChecker(cfg, client=self._make_client())

        lines = [
            (1, f"http://u1:p1@127.0.0.1:{p_http}"),
            (2, f"https://u2:p2@localhost:{p_https}"),
            (3, f"socks4://127.0.0.1:{p_s4}"),
            (4, f"socks4a://127.0.0.1:{p_s4}"),
            (5, f"socks5://127.0.0.1:{p_s5}"),
            (6, f"socks5h://suser:spass@127.0.0.1:{p_s5_auth}"),
            (7, f"socks5://suser:spass@127.0.0.1:{p_s5_auth}"),
        ]
        summary = await checker.run_entries(lines)
        self.assertEqual(summary.working_count, 7)
        self.assertEqual(summary.dead_count, 0)
        for h in https_hdrs:
            self.assertNotIn("proxy-authorization", h)

    async def test_http_only_fallback_and_require_https(self) -> None:
        http_port, _ = await self._start_http_target(use_tls=False, mode="json_ip")
        https_port, _ = await self._start_http_target(use_tls=True, mode="json_ip")
        p_no_connect = await self._start_http_proxy(allow_connect=False)

        targets = (
            pc.TestTarget(url=f"https://localhost:{https_port}/ip", expected_json_key="origin"),
            pc.TestTarget(url=f"http://127.0.0.1:{http_port}/ip", expected_json_key="origin"),
        )
        cfg1 = pc.CheckerConfig(targets=targets, quiet=True)
        res1 = await pc.ProxyChecker(cfg1, client=self._make_client()).run_entries(
            [(1, f"http://127.0.0.1:{p_no_connect}")]
        )
        self.assertEqual(res1.working_count, 1)
        self.assertTrue((res1.results[0].checked_url or "").startswith("http://"))

        cfg2 = pc.CheckerConfig(targets=(targets[0],), require_https=True, quiet=True)
        res2 = await pc.ProxyChecker(cfg2, client=self._make_client()).run_entries(
            [(1, f"http://127.0.0.1:{p_no_connect}")]
        )
        self.assertEqual(res2.dead_count, 1)
        self.assertEqual(res2.results[0].error_category, pc.ErrorCategory.HTTP_ERROR)

    async def test_chunked_gzip_and_interim_100_and_oversized_body(self) -> None:
        p_http = await self._start_http_proxy()
        t_gzip, _ = await self._start_http_target(mode="chunked_gzip")
        t_100, _ = await self._start_http_target(mode="interim_100")
        t_big, _ = await self._start_http_target(mode="oversized_2mb")

        client = self._make_client()
        res_gzip = await pc.ProxyChecker(
            pc.CheckerConfig(
                targets=(pc.TestTarget(url=f"http://127.0.0.1:{t_gzip}/ip", expected_json_key="origin"),),
                quiet=True,
            ),
            client=client,
        ).run_entries([(1, f"http://127.0.0.1:{p_http}")])
        self.assertEqual(res_gzip.working_count, 1)

        res_100 = await pc.ProxyChecker(
            pc.CheckerConfig(
                targets=(pc.TestTarget(url=f"http://127.0.0.1:{t_100}/", expected_substring="Example Domain"),),
                quiet=True,
            ),
            client=client,
        ).run_entries([(1, f"http://127.0.0.1:{p_http}")])
        self.assertEqual(res_100.working_count, 1)

        status, _, body, _ = await client.fetch(
            pc.ProxyEntry(protocol=pc.ProxyProtocol.HTTP, host="127.0.0.1", port=p_http),
            f"http://127.0.0.1:{t_big}/",
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(body), pc.MAX_BODY_BYTES)

    async def test_captive_portal_redirect_ssrf_and_failures(self) -> None:
        t_captive, _ = await self._start_http_target(mode="captive_portal")
        t_redir, _ = await self._start_http_target(mode="redirect_localhost")
        t_trickle, _ = await self._start_http_target(mode="trickle")

        p_http = await self._start_http_proxy()
        p_auth = await self._start_http_proxy(required_auth=("admin", "secret"))
        p_garbage = await self._start_http_proxy(garbage_banner=True)
        p_s4_rej = await self._start_socks4_proxy(reject=True)
        p_s5_auth = await self._start_socks5_proxy(required_auth=("u", "p"))

        c1 = pc.ProxyChecker(
            pc.CheckerConfig(
                targets=(pc.TestTarget(url=f"http://127.0.0.1:{t_captive}/ip", expected_json_key="origin"),),
                quiet=True,
            ),
            client=self._make_client(),
        )
        r1 = await c1.run_entries([(1, f"http://127.0.0.1:{p_http}")])
        self.assertEqual(r1.results[0].error_category, pc.ErrorCategory.INVALID_RESPONSE)

        c2 = pc.ProxyChecker(
            pc.CheckerConfig(
                targets=(pc.TestTarget(url=f"http://127.0.0.1:{t_redir}/"),),
                follow_redirects=True,
                quiet=True,
            ),
            client=self._make_client(follow_redirects=True),
        )
        r2 = await c2.run_entries([(1, f"http://127.0.0.1:{p_http}")])
        self.assertEqual(r2.results[0].error_category, pc.ErrorCategory.REDIRECT_BLOCKED)

        c3 = pc.ProxyChecker(
            pc.CheckerConfig(
                targets=(pc.TestTarget(url=f"http://127.0.0.1:{t_trickle}/"),),
                total_timeout=0.35,
                read_timeout=2.0,
                quiet=True,
            ),
            client=self._make_client(total_timeout=0.35, read_timeout=2.0),
        )
        r3 = await c3.run_entries([(1, f"http://127.0.0.1:{p_http}")])
        self.assertIn(
            r3.results[0].error_category,
            (pc.ErrorCategory.TOTAL_TIMEOUT, pc.ErrorCategory.READ_TIMEOUT),
        )

        c4 = pc.ProxyChecker(
            pc.CheckerConfig(
                targets=(pc.TestTarget(url=f"http://127.0.0.1:{t_captive}/", expected_substring="Sign in"),),
                quiet=True,
            ),
            client=self._make_client(),
        )
        r4 = await c4.run_entries(
            [
                (1, f"http://127.0.0.1:{p_auth}"),
                (2, f"http://admin:wrongpw@127.0.0.1:{p_auth}"),
                (3, f"http://127.0.0.1:{p_garbage}"),
                (4, f"socks4://127.0.0.1:{p_s4_rej}"),
                (5, f"socks5://u:wrong@127.0.0.1:{p_s5_auth}"),
                (6, "http://127.0.0.1:1"),
            ]
        )
        cats = {res.line_number: res.error_category for res in r4.results}
        self.assertEqual(cats[1], pc.ErrorCategory.PROXY_AUTH_REQUIRED)
        self.assertEqual(cats[2], pc.ErrorCategory.PROXY_AUTH_FAILED)
        self.assertNotIn("wrongpw", r4.results[1].error_message)
        self.assertEqual(cats[3], pc.ErrorCategory.PROXY_PROTOCOL_ERROR)
        self.assertEqual(cats[4], pc.ErrorCategory.CONNECTION_REFUSED)
        self.assertEqual(cats[5], pc.ErrorCategory.PROXY_AUTH_FAILED)
        self.assertEqual(cats[6], pc.ErrorCategory.CONNECTION_REFUSED)

    async def test_untrusted_tls_cert_rejected(self) -> None:
        https_port, _ = await self._start_http_target(use_tls=True, mode="json_ip")
        p_http = await self._start_http_proxy()
        strict_client = pc.AsyncProxyClient()
        checker = pc.ProxyChecker(
            pc.CheckerConfig(
                targets=(pc.TestTarget(url=f"https://localhost:{https_port}/ip", expected_json_key="origin"),),
                quiet=True,
            ),
            client=strict_client,
        )
        summary = await checker.run_entries([(1, f"http://127.0.0.1:{p_http}")])
        self.assertEqual(summary.dead_count, 1)
        self.assertEqual(summary.results[0].error_category, pc.ErrorCategory.TLS_ERROR)

    async def test_anonymity_classification(self) -> None:
        t_ip, _ = await self._start_http_target(mode="json_ip")
        p_elite = await self._start_http_proxy()
        p_anon = await self._start_http_proxy(inject_header=("Via", "1.1 proxy"))
        p_trans = await self._start_http_proxy(inject_header=("X-Forwarded-For", "203.0.113.9"))

        cfg = pc.CheckerConfig(
            targets=(pc.TestTarget(url=f"http://127.0.0.1:{t_ip}/ip", expected_json_key="origin"),),
            check_anonymity=True,
            anonymity_url=f"http://127.0.0.1:{t_ip}/get",
            quiet=True,
        )
        summary = await pc.ProxyChecker(cfg, client=self._make_client()).run_entries(
            [
                (1, f"http://127.0.0.1:{p_elite}"),
                (2, f"http://127.0.0.1:{p_anon}"),
                (3, f"http://127.0.0.1:{p_trans}"),
            ],
            client_public_ip="203.0.113.9",
        )
        by_line = {r.line_number: r for r in summary.results}
        self.assertEqual(by_line[1].anonymity, pc.AnonymityLevel.ELITE)
        self.assertEqual(by_line[2].anonymity, pc.AnonymityLevel.ANONYMOUS)
        self.assertEqual(by_line[3].anonymity, pc.AnonymityLevel.TRANSPARENT)

    async def test_dedup_filtering_and_exports(self) -> None:
        t_ip, _ = await self._start_http_target(mode="json_ip")
        p_http = await self._start_http_proxy(required_auth=("user1", "pass1"))
        p_s5 = await self._start_socks5_proxy()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            in_file = tmp_dir / "in.txt"
            out_file = tmp_dir / "out.txt"
            failed_file = tmp_dir / "failed.txt"
            json_file = tmp_dir / "report.json"
            csv_file = tmp_dir / "report.csv"

            in_file.write_text(
                "\n".join(
                    [
                        "# header comment",
                        f"http://user1:pass1@127.0.0.1:{p_http}",
                        f"http://user1:pass1@127.0.0.1:{p_http}",
                        f"socks5://127.0.0.1:{p_s5}",
                        "bad_entry",
                    ]
                ),
                encoding="utf-8",
            )
            cfg = pc.CheckerConfig(
                input_file=in_file,
                output_file=out_file,
                failed_output_file=failed_file,
                json_output_file=json_file,
                csv_output_file=csv_file,
                protocols=(pc.ProxyProtocol.HTTP,),
                targets=(pc.TestTarget(url=f"http://127.0.0.1:{t_ip}/ip", expected_json_key="origin"),),
                quiet=True,
            )
            checker = pc.ProxyChecker(cfg, client=self._make_client())
            summary = await checker.run_entries(pc.iter_proxy_lines(in_file))
            pc.ResultWriter.write_all(cfg, summary)

            self.assertEqual(summary.working_count, 1)
            self.assertEqual(summary.duplicates_skipped, 1)
            self.assertEqual(summary.filtered_skipped, 1)
            self.assertEqual(summary.invalid_count, 1)

            self.assertIn("user1:pass1@", out_file.read_text(encoding="utf-8"))
            report = json.loads(json_file.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["working"], 1)
            self.assertNotIn("pass1", json_file.read_text(encoding="utf-8"))
            with csv_file.open("r", encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), 2)
            self.assertNotIn("pass1", csv_file.read_text(encoding="utf-8"))

    async def test_large_input_streaming_bounded_concurrency(self) -> None:
        t_ip, _ = await self._start_http_target(mode="json_ip")
        p_http = await self._start_http_proxy()
        cfg = pc.CheckerConfig(
            targets=(pc.TestTarget(url=f"http://127.0.0.1:{t_ip}/ip", expected_json_key="origin"),),
            concurrency=50,
            deduplicate=False,
            quiet=True,
        )
        entries = ((i, f"http://127.0.0.1:{p_http}") for i in range(1, 301))
        summary = await pc.ProxyChecker(cfg, client=self._make_client()).run_entries(entries)
        self.assertEqual(summary.checked_count, 300)
        self.assertEqual(summary.working_count, 300)


class TestCLISubprocess(unittest.TestCase):
    """CLI argument validation, error codes, version, and Ctrl+C tests."""

    def test_cli_validation_and_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            missing = p / "nope.txt"
            rc = pc.main(["-i", str(missing), "-o", str(p / "out.txt")])
            self.assertEqual(rc, 1)

            existing_in = p / "same.txt"
            existing_in.write_text("127.0.0.1:8080\n", encoding="utf-8")
            rc_same = pc.main(["-i", str(existing_in), "-o", str(existing_in)])
            self.assertEqual(rc_same, 1)

            existing_out = p / "exists.txt"
            existing_out.write_text("old\n", encoding="utf-8")
            rc_no_overwrite = pc.main(
                ["-i", str(existing_in), "-o", str(existing_out), "--no-overwrite"]
            )
            self.assertEqual(rc_no_overwrite, 1)

        with self.assertRaises(ValueError):
            pc.build_config(
                pc.build_arg_parser().parse_args(
                    ["-u", "http://example.com", "--require-https"]
                )
            )

    def test_version_flag(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent / "proxy_checker.py"), "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn(pc.__version__, proc.stdout)

    def test_sigint_graceful_shutdown_saves_partial_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            in_file = tmp_dir / "unchecked.txt"
            out_file = tmp_dir / "checked.txt"
            lines = [f"http://127.0.0.1:{40000 + i}" for i in range(400)]
            in_file.write_text("\n".join(lines), encoding="utf-8")

            proc = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parent / "proxy_checker.py"),
                    "-i",
                    str(in_file),
                    "-o",
                    str(out_file),
                    "-c",
                    "5",
                    "--connect-timeout",
                    "2",
                    "--total-timeout",
                    "3",
                    "-q",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                time.sleep(0.35)
                proc.send_signal(signal.SIGINT)
                stdout, stderr = proc.communicate(timeout=5)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()

            self.assertEqual(proc.returncode, 130, f"stderr={stderr}")
            self.assertIn("Interrupted!", stdout)
            self.assertTrue(out_file.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
