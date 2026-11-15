#!/usr/bin/env python3
"""Production-grade asynchronous proxy checker and validator.

Supports HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h proxies using only
the Python standard library. Provides bounded concurrency, strict TLS
verification, nested TLS-over-TLS tunneling, response content validation,
optional anonymity assessment, credential redaction, atomic output writes,
JSON/CSV exports, and graceful Ctrl+C cancellation.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from collections import Counter
import csv
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import struct
import sys
import tempfile
import time
from typing import (
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)
from urllib.parse import unquote, urljoin, urlsplit
import zlib

__version__ = "2.0.0"

# ---------------------------------------------------------------------------
# Constants & Safety Bounds
# ---------------------------------------------------------------------------

DEFAULT_INPUT_FILE = "unchecked.txt"
DEFAULT_OUTPUT_FILE = "checked.txt"
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 10.0
DEFAULT_TOTAL_TIMEOUT = 15.0
DEFAULT_CONCURRENCY = 100
MAX_CONCURRENCY = 2000
DEFAULT_USER_AGENT = f"ProxyChecker/{__version__}"
DEFAULT_ANONYMITY_URL = "http://httpbin.org/get"

MAX_HEADER_BYTES = 64 * 1024       # 64 KiB cap on HTTP response headers
MAX_HEADERS = 200                  # Cap on header lines to prevent header floods
MAX_BODY_BYTES = 512 * 1024        # 512 KiB cap on read response bodies
MAX_DECOMPRESSED_BYTES = 1024 * 1024  # 1 MiB cap against decompression bombs
MAX_REDIRECTS = 3
MAX_INTERIM_RESPONSES = 5
MAX_ERROR_MSG_LEN = 220

SUPPORTED_PROTOCOLS: Tuple[str, ...] = (
    "http",
    "https",
    "socks4",
    "socks4a",
    "socks5",
    "socks5h",
)

# Reveal headers commonly added by transparent/anonymous proxies
ANONYMITY_PROXY_HEADERS: Tuple[str, ...] = (
    "x-forwarded-for",
    "via",
    "forwarded",
    "x-real-ip",
    "client-ip",
    "x-client-ip",
    "x-proxy-id",
    "proxy-connection",
    "x-forwarded-host",
    "x-forwarded-proto",
    "true-client-ip",
    "cf-connecting-ip",
)

_HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_URL_CREDS_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@\s]+@)")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_STATUS_LINE_RE = re.compile(rb"^HTTP/(\d\.\d)\s+(\d{3})(?:\s+(.*))?$")

_SOCKS5_REPLY_MESSAGES: Dict[int, str] = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused by destination",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


# ---------------------------------------------------------------------------
# Enums & Exceptions
# ---------------------------------------------------------------------------


class ProxyProtocol(str, Enum):
    """Supported proxy transport schemes."""

    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS4A = "socks4a"
    SOCKS5 = "socks5"
    SOCKS5H = "socks5h"


class ProxyStatus(str, Enum):
    """Outcome of validating a single proxy."""

    WORKING = "working"
    DEAD = "dead"
    INVALID = "invalid"


class ErrorCategory(str, Enum):
    """Structured classification of proxy validation failures."""

    NONE = "none"
    MALFORMED_INPUT = "malformed_input"
    UNSUPPORTED_PROTOCOL = "unsupported_protocol"
    DNS_ERROR = "dns_error"
    CONNECT_TIMEOUT = "connect_timeout"
    READ_TIMEOUT = "read_timeout"
    TOTAL_TIMEOUT = "total_timeout"
    CONNECTION_REFUSED = "connection_refused"
    CONNECTION_RESET = "connection_reset"
    NETWORK_UNREACHABLE = "network_unreachable"
    TLS_ERROR = "tls_error"
    PROXY_AUTH_REQUIRED = "proxy_auth_required"
    PROXY_AUTH_FAILED = "proxy_auth_failed"
    PROXY_PROTOCOL_ERROR = "proxy_protocol_error"
    HTTP_ERROR = "http_error"
    REDIRECT_BLOCKED = "redirect_blocked"
    INVALID_RESPONSE = "invalid_response"
    RESPONSE_TOO_LARGE = "response_too_large"
    CANCELLED = "cancelled"


class AnonymityLevel(str, Enum):
    """Proxy anonymity classification."""

    UNKNOWN = "unknown"
    TRANSPARENT = "transparent"
    ANONYMOUS = "anonymous"
    ELITE = "elite"


class ProxyCheckerError(Exception):
    """Base exception carrying structured error classification."""

    def __init__(
        self,
        message: str,
        category: ErrorCategory,
        proxy_fatal: bool = False,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.proxy_fatal = proxy_fatal


class ProxyParseError(ProxyCheckerError):
    """Raised when a proxy line cannot be parsed or fails validation."""

    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.MALFORMED_INPUT,
    ) -> None:
        super().__init__(message, category=category, proxy_fatal=True)


class ProxyTransportError(ProxyCheckerError):
    """Raised when establishing or maintaining a proxy tunnel fails."""


class TargetValidationError(ProxyCheckerError):
    """Raised when the target HTTP response fails verification."""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestTarget:
    """Target endpoint and response validation criteria."""

    url: str
    expected_statuses: Tuple[int, ...] = (200,)
    expected_substring: Optional[str] = None
    expected_json_key: Optional[str] = None
    require_non_empty: bool = True

    @property
    def is_https(self) -> bool:
        return self.url.lower().startswith("https://")


DEFAULT_TEST_TARGETS: Tuple[TestTarget, ...] = (
    TestTarget(
        url="https://httpbin.org/ip",
        expected_statuses=(200,),
        expected_json_key="origin",
    ),
    TestTarget(
        url="https://example.com",
        expected_statuses=(200,),
        expected_substring="Example Domain",
    ),
    TestTarget(
        url="http://httpbin.org/ip",
        expected_statuses=(200,),
        expected_json_key="origin",
    ),
    TestTarget(
        url="http://example.com",
        expected_statuses=(200,),
        expected_substring="Example Domain",
    ),
)

DEFAULT_HTTPS_TARGETS: Tuple[TestTarget, ...] = tuple(
    t for t in DEFAULT_TEST_TARGETS if t.is_https
)


@dataclass(frozen=True)
class ProxyEntry:
    """Validated representation of a proxy endpoint."""

    protocol: ProxyProtocol
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    raw: str = ""
    explicit_scheme: bool = False
    line_number: Optional[int] = None

    def format_host_port(self) -> str:
        """Format host:port, bracketing IPv6 addresses."""
        host_part = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host_part}:{self.port}"

    def masked_uri(self) -> str:
        """Return URI safe for logs/reports with credentials redacted."""
        hp = self.format_host_port()
        creds = "***:***@" if (self.username is not None or self.password is not None) else ""
        return f"{self.protocol.value}://{creds}{hp}"

    def output_line(self, include_scheme: bool = False) -> str:
        """Return usable proxy string for checked proxy file output."""
        if include_scheme or self.explicit_scheme:
            hp = self.format_host_port()
            if self.username is not None:
                pw = self.password or ""
                return f"{self.protocol.value}://{self.username}:{pw}@{hp}"
            return f"{self.protocol.value}://{hp}"
        if self.raw:
            return self.raw
        hp = self.format_host_port()
        if self.username is not None:
            pw = self.password or ""
            return f"{hp}:{self.username}:{pw}"
        return hp

    @property
    def dedup_key(self) -> Tuple[str, str, int, Optional[str]]:
        """Normalized key used for duplicate detection."""
        return (
            self.protocol.value,
            self.host.lower(),
            self.port,
            self.username,
        )

    def __repr__(self) -> str:
        return (
            f"ProxyEntry(protocol={self.protocol.value!r}, "
            f"host={self.host!r}, port={self.port!r}, "
            f"has_auth={self.username is not None})"
        )


@dataclass(frozen=True)
class CheckResult:
    """Structured outcome for a single checked or invalid proxy."""

    proxy_masked: str
    proxy_output: str
    protocol: str
    host: str
    port: Optional[int]
    status: ProxyStatus
    latency_ms: Optional[float] = None
    http_status: Optional[int] = None
    checked_url: Optional[str] = None
    anonymity: AnonymityLevel = AnonymityLevel.UNKNOWN
    exit_ip: Optional[str] = None
    error_category: ErrorCategory = ErrorCategory.NONE
    error_message: str = ""
    line_number: Optional[int] = None

    def to_dict(self, include_credentials: bool = False) -> Dict[str, object]:
        """Serialize result for JSON export, masking credentials by default."""
        return {
            "proxy": self.proxy_output if include_credentials else self.proxy_masked,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "status": self.status.value,
            "latency_ms": round(self.latency_ms, 2) if self.latency_ms is not None else None,
            "http_status": self.http_status,
            "checked_url": self.checked_url,
            "anonymity": self.anonymity.value,
            "exit_ip": self.exit_ip,
            "error_category": self.error_category.value,
            "error_message": self.error_message,
            "line_number": self.line_number,
        }


@dataclass
class CheckerConfig:
    """Validated runtime configuration for a proxy check run."""

    input_file: Path = Path(DEFAULT_INPUT_FILE)
    output_file: Path = Path(DEFAULT_OUTPUT_FILE)
    failed_output_file: Optional[Path] = None
    json_output_file: Optional[Path] = None
    csv_output_file: Optional[Path] = None
    protocols: Tuple[ProxyProtocol, ...] = tuple(ProxyProtocol)
    default_protocol: ProxyProtocol = ProxyProtocol.HTTP
    concurrency: int = DEFAULT_CONCURRENCY
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    read_timeout: float = DEFAULT_READ_TIMEOUT
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT
    targets: Tuple[TestTarget, ...] = DEFAULT_TEST_TARGETS
    require_https: bool = False
    follow_redirects: bool = False
    check_anonymity: bool = False
    anonymity_url: str = DEFAULT_ANONYMITY_URL
    user_agent: str = DEFAULT_USER_AGENT
    deduplicate: bool = True
    allow_overwrite: bool = True
    output_with_scheme: bool = False
    include_credentials_in_reports: bool = False
    verbose: bool = False
    quiet: bool = False


@dataclass
class CheckSummary:
    """Aggregated statistics and results for a completed or interrupted run."""

    results: List[CheckResult] = field(default_factory=list)
    total_lines: int = 0
    checked_count: int = 0
    working_count: int = 0
    dead_count: int = 0
    invalid_count: int = 0
    duplicates_skipped: int = 0
    filtered_skipped: int = 0
    elapsed_seconds: float = 0.0
    interrupted: bool = False
    error_counts: Dict[str, int] = field(default_factory=dict)
    client_public_ip: Optional[str] = None


# ---------------------------------------------------------------------------
# Security, Validation & Sanitization Utilities
# ---------------------------------------------------------------------------


def sanitize_error_message(
    message: str,
    secrets: Iterable[Optional[str]] = (),
) -> str:
    """Strip credentials, control characters, and excess length from error text."""
    cleaned = _CONTROL_CHARS_RE.sub(" ", message).strip()
    cleaned = _URL_CREDS_RE.sub(r"\1***:***@", cleaned)
    for secret in secrets:
        if secret and len(secret) >= 2:
            cleaned = cleaned.replace(secret, "***")
    if len(cleaned) > MAX_ERROR_MSG_LEN:
        cleaned = cleaned[: MAX_ERROR_MSG_LEN - 3] + "..."
    return cleaned


def sanitize_csv_cell(value: object) -> str:
    """Neutralize spreadsheet formula injection in string CSV cells."""
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def is_valid_hostname(host: str) -> bool:
    """Validate an IPv4, IPv6, or RFC-1123 hostname."""
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    stripped = host[:-1] if host.endswith(".") else host
    if not stripped or ".." in stripped:
        return False
    labels = stripped.split(".")
    return all(_HOSTNAME_LABEL_RE.match(label) is not None for label in labels)


def is_non_public_ip(host: str) -> bool:
    """Return True if host is a literal loopback, private, link-local, or reserved IP."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() in {"localhost", "localhost.localdomain"}
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def format_host_header(host: str, port: int, default_port: int) -> str:
    """Format Host header (RFC 9110), bracketing IPv6 literals."""
    host_part = f"[{host}]" if ":" in host else host
    if port == default_port:
        return host_part
    return f"{host_part}:{port}"


def format_authority(host: str, port: int) -> str:
    """Format host:port authority for HTTP CONNECT."""
    host_part = f"[{host}]" if ":" in host else host
    return f"{host_part}:{port}"


def validate_target_url(url: str) -> Tuple[str, str, int, str]:
    """Parse and validate an HTTP/HTTPS target URL.

    Returns (scheme, host, port, path_and_query).
    """
    if _CONTROL_CHARS_RE.search(url):
        raise ValueError("Target URL contains control characters")
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported target URL scheme {scheme!r}; expected http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Target URL must not contain embedded credentials")
    host = parsed.hostname
    if not host or not is_valid_hostname(host):
        raise ValueError(f"Invalid target hostname in URL: {url!r}")
    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid target port {port} in URL: {url!r}")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return scheme, host, port, path


def create_strict_ssl_context() -> ssl.SSLContext:
    """Create a hardened TLS 1.2+ SSLContext with strict hostname verification."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Enforce HTTP/1.1 since this engine implements RFC 9112 HTTP/1.1
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    return ctx


def validate_io_paths(config: CheckerConfig) -> None:
    """Verify input/output paths exist, do not collide, and respect overwrite policy."""
    in_path = config.input_file
    if not in_path.exists():
        raise FileNotFoundError(f"Input file does not exist: {in_path}")
    if not in_path.is_file():
        raise IsADirectoryError(f"Input path is not a regular file: {in_path}")

    resolved_in = in_path.resolve()
    output_paths: List[Path] = [config.output_file]
    for opt in (config.failed_output_file, config.json_output_file, config.csv_output_file):
        if opt is not None:
            output_paths.append(opt)

    seen_outputs: Set[Path] = set()
    for out_path in output_paths:
        resolved_out = out_path.resolve()
        if resolved_out == resolved_in:
            raise ValueError(
                f"Output path {out_path} resolves to the same file as input {in_path}"
            )
        if resolved_out in seen_outputs:
            raise ValueError(f"Duplicate output file path specified: {out_path}")
        seen_outputs.add(resolved_out)

        if out_path.exists():
            if out_path.is_dir():
                raise IsADirectoryError(f"Output path is a directory: {out_path}")
            if not config.allow_overwrite:
                raise FileExistsError(
                    f"Output file already exists and --no-overwrite is set: {out_path}"
                )

        parent = out_path.parent if out_path.parent != Path("") else Path(".")
        if not parent.exists():
            raise FileNotFoundError(f"Output directory does not exist: {parent}")
        if not os.access(parent, os.W_OK):
            raise PermissionError(f"Output directory is not writable: {parent}")


# ---------------------------------------------------------------------------
# Proxy Input Parsing & Streaming
# ---------------------------------------------------------------------------


def _strip_inline_comment(line: str) -> str:
    """Strip inline comments preceded by whitespace, preserving URL passwords."""
    for idx, ch in enumerate(line):
        if ch in ("#", ";") and (idx == 0 or line[idx - 1].isspace()):
            return line[:idx].strip()
    return line.strip()


def _parse_port(port_str: str) -> int:
    if not port_str.isdigit():
        raise ProxyParseError(f"Invalid port: {port_str!r}")
    port = int(port_str)
    if not (1 <= port <= 65535):
        raise ProxyParseError(f"Port out of range (1-65535): {port}")
    return port


def _validate_credentials(
    protocol: ProxyProtocol,
    username: Optional[str],
    password: Optional[str],
) -> None:
    for val in (username, password):
        if val is not None and _CONTROL_CHARS_RE.search(val):
            raise ProxyParseError("Proxy credentials contain invalid control characters")
    if protocol in (ProxyProtocol.SOCKS5, ProxyProtocol.SOCKS5H):
        if username is not None and len(username.encode("utf-8")) > 255:
            raise ProxyParseError("SOCKS5 username exceeds 255 bytes")
        if password is not None and len(password.encode("utf-8")) > 255:
            raise ProxyParseError("SOCKS5 password exceeds 255 bytes")
    if protocol in (ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS4A) and password is not None:
        raise ProxyParseError("SOCKS4/SOCKS4a does not support password authentication")


def parse_proxy_line(
    raw_line: str,
    default_protocol: ProxyProtocol = ProxyProtocol.HTTP,
    line_number: Optional[int] = None,
) -> Optional[ProxyEntry]:
    """Parse a single proxy line into a validated ProxyEntry, or None for blank/comment."""
    cleaned = raw_line.lstrip("\ufeff")
    stripped = _strip_inline_comment(cleaned)
    if not stripped:
        return None

    if _CONTROL_CHARS_RE.search(stripped) or any(ch.isspace() for ch in stripped):
        raise ProxyParseError("Proxy entry contains whitespace or control characters")

    explicit_scheme = "://" in stripped
    if explicit_scheme:
        scheme_raw, rest = stripped.split("://", 1)
        scheme_lower = scheme_raw.lower()
        if scheme_lower not in SUPPORTED_PROTOCOLS:
            raise ProxyParseError(
                f"Unsupported proxy protocol: {scheme_raw!r}",
                category=ErrorCategory.UNSUPPORTED_PROTOCOL,
            )
        protocol = ProxyProtocol(scheme_lower)
        # Strip optional trailing slash only (reject paths/queries)
        if rest.endswith("/"):
            rest = rest[:-1]
        if "/" in rest or "?" in rest or "#" in rest:
            raise ProxyParseError("Proxy URI must not contain path, query, or fragment")
        parsed = urlsplit(f"{protocol.value}://{rest}")
        host = parsed.hostname
        if not host or not is_valid_hostname(host):
            raise ProxyParseError(f"Invalid proxy host: {host!r}")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ProxyParseError(f"Invalid proxy port: {exc}") from exc
        if port is None or not (1 <= port <= 65535):
            raise ProxyParseError("Missing or out-of-range proxy port")
        username = unquote(parsed.username) if parsed.username is not None else None
        password = unquote(parsed.password) if parsed.password is not None else None
        _validate_credentials(protocol, username, password)
        return ProxyEntry(
            protocol=protocol,
            host=host,
            port=port,
            username=username,
            password=password,
            raw=stripped,
            explicit_scheme=True,
            line_number=line_number,
        )

    # Check host:port:user:pass format (only when no @ and 3 colons and part 2 is port)
    if "@" not in stripped and stripped.count(":") == 3 and not stripped.startswith("["):
        parts = stripped.split(":")
        host_candidate, port_candidate, user_part, pass_part = parts
        if port_candidate.isdigit():
            if not is_valid_hostname(host_candidate):
                raise ProxyParseError(f"Invalid proxy host: {host_candidate!r}")
            port = _parse_port(port_candidate)
            _validate_credentials(default_protocol, user_part, pass_part)
            return ProxyEntry(
                protocol=default_protocol,
                host=host_candidate,
                port=port,
                username=user_part,
                password=pass_part,
                raw=stripped,
                explicit_scheme=False,
                line_number=line_number,
            )

    # Otherwise treat as [user:pass@]host:port or [user:pass@][ipv6]:port
    parsed = urlsplit(f"{default_protocol.value}://{stripped}")
    if parsed.path or parsed.query or parsed.fragment:
        raise ProxyParseError("Proxy entry must not contain path, query, or fragment")
    host = parsed.hostname
    if not host or not is_valid_hostname(host):
        raise ProxyParseError(f"Invalid proxy host: {host!r}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProxyParseError(f"Invalid proxy port: {exc}") from exc
    if port is None or not (1 <= port <= 65535):
        raise ProxyParseError("Missing or out-of-range proxy port")
    username = unquote(parsed.username) if parsed.username is not None else None
    password = unquote(parsed.password) if parsed.password is not None else None
    _validate_credentials(default_protocol, username, password)
    return ProxyEntry(
        protocol=default_protocol,
        host=host,
        port=port,
        username=username,
        password=password,
        raw=stripped,
        explicit_scheme=False,
        line_number=line_number,
    )


def iter_proxy_lines(input_file: Path) -> Iterator[Tuple[int, str]]:
    """Lazily yield (1-based line_number, line) from input file in UTF-8."""
    with input_file.open("r", encoding="utf-8", errors="replace") as handle:
        for idx, line in enumerate(handle, start=1):
            yield idx, line


# ---------------------------------------------------------------------------
# Async Stream & Nested TLS-over-TLS Transport Layer
# ---------------------------------------------------------------------------


class _StreamChannel:
    """Unified async stream wrapper supporting plain TCP, start_tls, and MemoryBIO TLS."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_tls: bool = False,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._is_tls = is_tls
        self._ssl_obj: Optional[ssl.SSLObject] = None
        self._in_bio: Optional[ssl.MemoryBIO] = None
        self._out_bio: Optional[ssl.MemoryBIO] = None
        self._plain_buf = bytearray()
        self._closed = False

    @property
    def is_tls(self) -> bool:
        return self._is_tls

    async def upgrade_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str,
        handshake_timeout: float,
    ) -> None:
        """Upgrade the channel to TLS, using MemoryBIO when already inside TLS."""
        if not self._is_tls:
            loop = asyncio.get_running_loop()
            new_transport = await asyncio.wait_for(
                loop.start_tls(
                    self._writer.transport,
                    self._writer._protocol,  # type: ignore[attr-defined]
                    ssl_context,
                    server_hostname=server_hostname,
                ),
                timeout=handshake_timeout,
            )
            self._writer._transport = new_transport  # type: ignore[attr-defined]
            self._is_tls = True
            return

        # Nested TLS-over-TLS (e.g. HTTPS proxy -> HTTPS target) using ssl.MemoryBIO
        # Works identically on Python 3.8-3.10 where loop.start_tls cannot stack TLS.
        in_bio = ssl.MemoryBIO()
        out_bio = ssl.MemoryBIO()
        ssl_obj = ssl_context.wrap_bio(
            in_bio,
            out_bio,
            server_side=False,
            server_hostname=server_hostname,
        )
        self._in_bio = in_bio
        self._out_bio = out_bio
        self._ssl_obj = ssl_obj

        async def _handshake() -> None:
            while True:
                try:
                    ssl_obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    pending = out_bio.read()
                    if pending:
                        self._writer.write(pending)
                        await self._writer.drain()
                    chunk = await self._reader.read(16384)
                    if not chunk:
                        raise EOFError("TLS handshake interrupted by peer EOF")
                    in_bio.write(chunk)
                except ssl.SSLWantWriteError:
                    pending = out_bio.read()
                    if pending:
                        self._writer.write(pending)
                        await self._writer.drain()
            pending = out_bio.read()
            if pending:
                self._writer.write(pending)
                await self._writer.drain()

        await asyncio.wait_for(_handshake(), timeout=handshake_timeout)

    async def _fill_plain_buf(self, min_bytes: int = 1) -> bool:
        """Read encrypted bytes from outer stream into inner MemoryBIO plaintext buffer."""
        assert self._ssl_obj is not None
        assert self._in_bio is not None
        assert self._out_bio is not None
        while len(self._plain_buf) < min_bytes:
            try:
                data = self._ssl_obj.read(16384)
                if not data:
                    return len(self._plain_buf) > 0
                self._plain_buf.extend(data)
                return True
            except ssl.SSLWantReadError:
                pending = self._out_bio.read()
                if pending:
                    self._writer.write(pending)
                    await self._writer.drain()
                chunk = await self._reader.read(16384)
                if not chunk:
                    self._in_bio.write_eof()
                    return len(self._plain_buf) > 0
                self._in_bio.write(chunk)
            except ssl.SSLWantWriteError:
                pending = self._out_bio.read()
                if pending:
                    self._writer.write(pending)
                    await self._writer.drain()
        return True

    async def write_and_drain(self, data: bytes) -> None:
        if self._ssl_obj is None:
            self._writer.write(data)
            await self._writer.drain()
            return
        assert self._in_bio is not None and self._out_bio is not None
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            try:
                written = self._ssl_obj.write(view[offset:])
                offset += written
            except ssl.SSLWantWriteError:
                pass
            except ssl.SSLWantReadError:
                pending = self._out_bio.read()
                if pending:
                    self._writer.write(pending)
                    await self._writer.drain()
                chunk = await self._reader.read(16384)
                if not chunk:
                    raise EOFError("Peer closed connection during TLS write")
                self._in_bio.write(chunk)
            pending = self._out_bio.read()
            if pending:
                self._writer.write(pending)
                await self._writer.drain()

    async def read(self, n: int = 65536) -> bytes:
        if self._ssl_obj is None:
            return await self._reader.read(n)
        if not self._plain_buf:
            has_data = await self._fill_plain_buf(1)
            if not has_data:
                return b""
        out = bytes(self._plain_buf[:n])
        del self._plain_buf[:n]
        return out

    async def readexactly(self, n: int) -> bytes:
        if n == 0:
            return b""
        if self._ssl_obj is None:
            return await self._reader.readexactly(n)
        while len(self._plain_buf) < n:
            before = len(self._plain_buf)
            has_data = await self._fill_plain_buf(n)
            if not has_data or len(self._plain_buf) == before:
                partial = bytes(self._plain_buf)
                self._plain_buf.clear()
                raise asyncio.IncompleteReadError(partial, n)
        out = bytes(self._plain_buf[:n])
        del self._plain_buf[:n]
        return out

    async def readline(self, limit: int = MAX_HEADER_BYTES) -> bytes:
        if self._ssl_obj is None:
            return await self._reader.readline()
        while True:
            nl_idx = self._plain_buf.find(b"\n")
            if nl_idx != -1:
                end = nl_idx + 1
                line = bytes(self._plain_buf[:end])
                del self._plain_buf[:end]
                return line
            if len(self._plain_buf) > limit:
                raise ValueError("Line length exceeded limit")
            before = len(self._plain_buf)
            has_data = await self._fill_plain_buf(before + 1)
            if not has_data or len(self._plain_buf) == before:
                line = bytes(self._plain_buf)
                self._plain_buf.clear()
                return line

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if not self._writer.is_closing():
                self._writer.close()
            await asyncio.wait_for(self._writer.wait_closed(), timeout=0.5)
        except (OSError, asyncio.TimeoutError, asyncio.CancelledError):
            try:
                self._writer.transport.abort()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Async Network & Protocol Engine
# ---------------------------------------------------------------------------


def _classify_os_error(exc: OSError, stage: str = "connect") -> ProxyTransportError:
    """Map low-level socket/SSL exceptions to structured ProxyTransportError."""
    if isinstance(exc, ssl.SSLError):
        return ProxyTransportError(
            f"TLS error ({stage}): {exc}",
            category=ErrorCategory.TLS_ERROR,
            proxy_fatal=(stage == "proxy"),
        )
    if isinstance(exc, socket.gaierror):
        return ProxyTransportError(
            f"DNS resolution failed: {exc}",
            category=ErrorCategory.DNS_ERROR,
            proxy_fatal=(stage == "proxy"),
        )
    if isinstance(exc, ConnectionRefusedError):
        return ProxyTransportError(
            "Connection refused",
            category=ErrorCategory.CONNECTION_REFUSED,
            proxy_fatal=(stage == "proxy"),
        )
    if isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
        return ProxyTransportError(
            f"Connection reset: {exc}",
            category=ErrorCategory.CONNECTION_RESET,
            proxy_fatal=False,
        )
    err_no = getattr(exc, "errno", None)
    if err_no in {101, 113}:  # ENETUNREACH / EHOSTUNREACH on Linux
        return ProxyTransportError(
            f"Network or host unreachable: {exc}",
            category=ErrorCategory.NETWORK_UNREACHABLE,
            proxy_fatal=(stage == "proxy"),
        )
    return ProxyTransportError(
        f"Network error ({stage}): {exc}",
        category=ErrorCategory.CONNECTION_REFUSED if stage == "proxy" else ErrorCategory.CONNECTION_RESET,
        proxy_fatal=(stage == "proxy"),
    )


def _safe_decompress(data: bytes, content_encoding: str) -> bytes:
    """Safely decompress gzip/deflate payloads with strict memory bounds."""
    enc = content_encoding.strip().lower()
    if not enc or enc == "identity":
        return data
    if enc == "gzip":
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif enc == "deflate":
        decompressor = zlib.decompressobj(zlib.MAX_WBITS)
    else:
        return data

    try:
        out = decompressor.decompress(data, MAX_DECOMPRESSED_BYTES)
        if decompressor.unconsumed_tail:
            raise TargetValidationError(
                "Compressed response exceeded decompression limit",
                category=ErrorCategory.RESPONSE_TOO_LARGE,
            )
        out += decompressor.flush(MAX_DECOMPRESSED_BYTES - len(out))
        return out
    except zlib.error as exc:
        if enc == "deflate":
            # Retry raw RFC 1951 deflate
            try:
                raw_dec = zlib.decompressobj(-zlib.MAX_WBITS)
                out = raw_dec.decompress(data, MAX_DECOMPRESSED_BYTES)
                out += raw_dec.flush(MAX_DECOMPRESSED_BYTES - len(out))
                return out
            except zlib.error:
                pass
        raise TargetValidationError(
            f"Corrupt {enc} response body: {exc}",
            category=ErrorCategory.INVALID_RESPONSE,
        ) from exc


class AsyncProxyClient:
    """Asynchronous HTTP/HTTPS/SOCKS proxy client built on Python stdlib."""

    def __init__(
        self,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        follow_redirects: bool = False,
        proxy_ssl_context: Optional[ssl.SSLContext] = None,
        target_ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.total_timeout = total_timeout
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.proxy_ssl_context = proxy_ssl_context or create_strict_ssl_context()
        self.target_ssl_context = target_ssl_context or create_strict_ssl_context()

    async def _resolve_target_ip(
        self,
        host: str,
        port: int,
        ipv4_only: bool = False,
    ) -> Tuple[int, str]:
        """Resolve target hostname locally, preferring IPv4 for SOCKS compatibility."""
        try:
            addr = ipaddress.ip_address(host)
            if ipv4_only and addr.version != 4:
                raise ProxyTransportError(
                    "SOCKS4 requires an IPv4 address",
                    category=ErrorCategory.PROXY_PROTOCOL_ERROR,
                    proxy_fatal=False,
                )
            family = socket.AF_INET if addr.version == 4 else socket.AF_INET6
            return family, str(addr)
        except ValueError:
            pass

        loop = asyncio.get_running_loop()
        family_req = socket.AF_INET if ipv4_only else socket.AF_UNSPEC
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, family=family_req, type=socket.SOCK_STREAM),
                timeout=self.connect_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ProxyTransportError(
                "Target DNS resolution timed out",
                category=ErrorCategory.CONNECT_TIMEOUT,
            ) from exc
        except OSError as exc:
            raise ProxyTransportError(
                f"Target DNS resolution failed: {exc}",
                category=ErrorCategory.DNS_ERROR,
            ) from exc

        if not infos:
            raise ProxyTransportError(
                f"No DNS records found for {host}",
                category=ErrorCategory.DNS_ERROR,
            )
        # Prefer IPv4 because many SOCKS proxies lack IPv6 outbound routing
        for fam, _, _, _, sockaddr in infos:
            if fam == socket.AF_INET:
                return socket.AF_INET, str(sockaddr[0])
        fam, _, _, _, sockaddr = infos[0]
        return fam, str(sockaddr[0])

    async def _open_proxy_channel(self, proxy: ProxyEntry) -> _StreamChannel:
        """Open raw TCP (or TLS for HTTPS proxy) connection to the proxy endpoint."""
        use_proxy_tls = proxy.protocol == ProxyProtocol.HTTPS
        try:
            if use_proxy_tls:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        proxy.host,
                        proxy.port,
                        ssl=self.proxy_ssl_context,
                        server_hostname=proxy.host,
                    ),
                    timeout=self.connect_timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(proxy.host, proxy.port),
                    timeout=self.connect_timeout,
                )
            return _StreamChannel(reader, writer, is_tls=use_proxy_tls)
        except asyncio.TimeoutError as exc:
            raise ProxyTransportError(
                "Proxy connection timed out",
                category=ErrorCategory.CONNECT_TIMEOUT,
                proxy_fatal=True,
            ) from exc
        except (OSError, ssl.SSLError) as exc:
            raise _classify_os_error(exc, stage="proxy") from exc

    async def _socks4_handshake(
        self,
        channel: _StreamChannel,
        proxy: ProxyEntry,
        target_host: str,
        target_port: int,
    ) -> None:
        """Perform SOCKS4 / SOCKS4a CONNECT handshake."""
        user_bytes = (proxy.username or "").encode("utf-8")
        use_4a = False
        try:
            ip_obj = ipaddress.ip_address(target_host)
            if ip_obj.version != 4:
                raise ProxyTransportError(
                    "SOCKS4 does not support IPv6 targets",
                    category=ErrorCategory.PROXY_PROTOCOL_ERROR,
                )
            ip_bytes = ip_obj.packed
        except ValueError:
            if proxy.protocol == ProxyProtocol.SOCKS4A:
                use_4a = True
                ip_bytes = b"\x00\x00\x00\x01"
            else:
                _, resolved_ip = await self._resolve_target_ip(
                    target_host, target_port, ipv4_only=True
                )
                ip_bytes = ipaddress.IPv4Address(resolved_ip).packed

        packet = bytearray(b"\x04\x01")
        packet.extend(struct.pack("!H", target_port))
        packet.extend(ip_bytes)
        packet.extend(user_bytes)
        packet.append(0x00)
        if use_4a:
            packet.extend(target_host.encode("idna"))
            packet.append(0x00)

        try:
            await asyncio.wait_for(
                channel.write_and_drain(bytes(packet)),
                timeout=self.read_timeout,
            )
            reply = await asyncio.wait_for(
                channel.readexactly(8),
                timeout=self.read_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ProxyTransportError(
                "SOCKS4 handshake timed out",
                category=ErrorCategory.READ_TIMEOUT,
            ) from exc
        except asyncio.IncompleteReadError as exc:
            raise ProxyTransportError(
                "SOCKS4 proxy closed connection during handshake",
                category=ErrorCategory.PROXY_PROTOCOL_ERROR,
            ) from exc
        except OSError as exc:
            raise _classify_os_error(exc, stage="tunnel") from exc

        if reply[0] != 0x00:
            raise ProxyTransportError(
                f"Invalid SOCKS4 reply version: {reply[0]!r}",
                category=ErrorCategory.PROXY_PROTOCOL_ERROR,
            )
        status = reply[1]
        if status == 0x5A:
            return
        if status == 0x5B:
            raise ProxyTransportError(
                "SOCKS4 request rejected or failed",
                category=ErrorCategory.CONNECTION_REFUSED,
            )
        if status in (0x5C, 0x5D):
            raise ProxyTransportError(
                "SOCKS4 ident/authentication failed",
                category=ErrorCategory.PROXY_AUTH_FAILED,
                proxy_fatal=True,
            )
        raise ProxyTransportError(
            f"SOCKS4 unknown status code: 0x{status:02x}",
            category=ErrorCategory.PROXY_PROTOCOL_ERROR,
        )

    async def _socks5_handshake(
        self,
        channel: _StreamChannel,
        proxy: ProxyEntry,
        target_host: str,
        target_port: int,
    ) -> None:
        """Perform RFC 1928 / RFC 1929 SOCKS5/SOCKS5h CONNECT handshake."""
        has_creds = proxy.username is not None
        methods = b"\x00\x02" if has_creds else b"\x00"
        greeting = bytes([0x05, len(methods)]) + methods

        try:
            await asyncio.wait_for(
                channel.write_and_drain(greeting),
                timeout=self.read_timeout,
            )
            method_resp = await asyncio.wait_for(
                channel.readexactly(2),
                timeout=self.read_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ProxyTransportError(
                "SOCKS5 greeting timed out",
                category=ErrorCategory.READ_TIMEOUT,
            ) from exc
        except asyncio.IncompleteReadError as exc:
            raise ProxyTransportError(
                "SOCKS5 proxy closed connection during greeting",
                category=ErrorCategory.PROXY_PROTOCOL_ERROR,
            ) from exc
        except OSError as exc:
            raise _classify_os_error(exc, stage="tunnel") from exc

        if method_resp[0] != 0x05:
            raise ProxyTransportError(
                f"Invalid SOCKS5 version byte: 0x{method_resp[0]:02x}",
                category=ErrorCategory.PROXY_PROTOCOL_ERROR,
            )
        chosen_method = method_resp[1]
        if chosen_method == 0xFF:
            cat = (
                ErrorCategory.PROXY_AUTH_REQUIRED
                if not has_creds
                else ErrorCategory.PROXY_AUTH_FAILED
            )
            raise ProxyTransportError(
                "SOCKS5 proxy rejected authentication methods",
                category=cat,
                proxy_fatal=True,
            )
        if chosen_method == 0x02:
            if not has_creds:
                raise ProxyTransportError(
                    "SOCKS5 proxy requires username/password authentication",
                    category=ErrorCategory.PROXY_AUTH_REQUIRED,
                    proxy_fatal=True,
                )
            u_bytes = (proxy.username or "").encode("utf-8")
            p_bytes = (proxy.password or "").encode("utf-8")
            auth_pkt = (
                bytes([0x01, len(u_bytes)])
                + u_bytes
                + bytes([len(p_bytes)])
                + p_bytes
            )
            try:
                await asyncio.wait_for(
                    channel.write_and_drain(auth_pkt),
                    timeout=self.read_timeout,
                )
                auth_resp = await asyncio.wait_for(
                    channel.readexactly(2),
                    timeout=self.read_timeout,
                )
            except asyncio.TimeoutError as exc:
                raise ProxyTransportError(
                    "SOCKS5 authentication timed out",
                    category=ErrorCategory.READ_TIMEOUT,
                ) from exc
            except asyncio.IncompleteReadError as exc:
                raise ProxyTransportError(
                    "SOCKS5 proxy closed connection during authentication",
                    category=ErrorCategory.PROXY_AUTH_FAILED,
                    proxy_fatal=True,
                ) from exc
            except OSError as exc:
                raise _classify_os_error(exc, stage="tunnel") from exc
            if auth_resp[0] != 0x01 or auth_resp[1] != 0x00:
                raise ProxyTransportError(
                    "SOCKS5 username/password authentication failed",
                    category=ErrorCategory.PROXY_AUTH_FAILED,
                    proxy_fatal=True,
                )
        elif chosen_method != 0x00:
            raise ProxyTransportError(
                f"Unsupported SOCKS5 auth method selected: 0x{chosen_method:02x}",
                category=ErrorCategory.PROXY_PROTOCOL_ERROR,
                proxy_fatal=True,
            )

        # Build CONNECT request
        addr_payload = bytearray()
        try:
            ip_obj = ipaddress.ip_address(target_host)
            if ip_obj.version == 4:
                addr_payload.append(0x01)
                addr_payload.extend(ip_obj.packed)
            else:
                addr_payload.append(0x04)
                addr_payload.extend(ip_obj.packed)
        except ValueError:
            if proxy.protocol == ProxyProtocol.SOCKS5H:
                host_bytes = target_host.encode("idna")
                if len(host_bytes) > 255:
                    raise ProxyTransportError(
                        "Target hostname exceeds SOCKS5 domain limit",
                        category=ErrorCategory.PROXY_PROTOCOL_ERROR,
                    )
                addr_payload.append(0x03)
                addr_payload.append(len(host_bytes))
                addr_payload.extend(host_bytes)
            else:
                fam, resolved_ip = await self._resolve_target_ip(target_host, target_port)
                ip_obj = ipaddress.ip_address(resolved_ip)
                addr_payload.append(0x01 if fam == socket.AF_INET else 0x04)
                addr_payload.extend(ip_obj.packed)

        connect_req = bytearray(b"\x05\x01\x00")
        connect_req.extend(addr_payload)
        connect_req.extend(struct.pack("!H", target_port))

        try:
            await asyncio.wait_for(
                channel.write_and_drain(bytes(connect_req)),
                timeout=self.read_timeout,
            )
            header = await asyncio.wait_for(
                channel.readexactly(4),
                timeout=self.read_timeout,
            )
            if header[0] != 0x05:
                raise ProxyTransportError(
                    f"Invalid SOCKS5 CONNECT reply version: 0x{header[0]:02x}",
                    category=ErrorCategory.PROXY_PROTOCOL_ERROR,
                )
            atyp = header[3]
            if atyp == 0x01:
                await asyncio.wait_for(channel.readexactly(4 + 2), timeout=self.read_timeout)
            elif atyp == 0x04:
                await asyncio.wait_for(channel.readexactly(16 + 2), timeout=self.read_timeout)
            elif atyp == 0x03:
                dlen = (await asyncio.wait_for(channel.readexactly(1), timeout=self.read_timeout))[0]
                await asyncio.wait_for(channel.readexactly(dlen + 2), timeout=self.read_timeout)
            else:
                raise ProxyTransportError(
                    f"Invalid SOCKS5 ATYP byte: 0x{atyp:02x}",
                    category=ErrorCategory.PROXY_PROTOCOL_ERROR,
                )
        except asyncio.TimeoutError as exc:
            raise ProxyTransportError(
                "SOCKS5 CONNECT timed out",
                category=ErrorCategory.READ_TIMEOUT,
            ) from exc
        except asyncio.IncompleteReadError as exc:
            raise ProxyTransportError(
                "SOCKS5 proxy closed connection during CONNECT",
                category=ErrorCategory.PROXY_PROTOCOL_ERROR,
            ) from exc
        except OSError as exc:
            raise _classify_os_error(exc, stage="tunnel") from exc

        rep = header[1]
        if rep == 0x00:
            return
        msg = _SOCKS5_REPLY_MESSAGES.get(rep, f"SOCKS5 failure code 0x{rep:02x}")
        if rep in (0x03, 0x04):
            cat = ErrorCategory.NETWORK_UNREACHABLE
        elif rep == 0x05:
            cat = ErrorCategory.CONNECTION_REFUSED
        elif rep == 0x06:
            cat = ErrorCategory.CONNECT_TIMEOUT
        else:
            cat = ErrorCategory.PROXY_PROTOCOL_ERROR
        raise ProxyTransportError(f"SOCKS5 CONNECT failed: {msg}", category=cat)

    def _build_proxy_auth_header(self, proxy: ProxyEntry) -> Optional[str]:
        if proxy.username is None:
            return None
        raw_creds = f"{proxy.username}:{proxy.password or ''}".encode("utf-8")
        token = base64.b64encode(raw_creds).decode("ascii")
        return f"Basic {token}"

    async def _read_http_head(
        self,
        channel: _StreamChannel,
    ) -> Tuple[int, Dict[str, str]]:
        """Read HTTP/1.x status line and headers with strict size/count bounds."""
        total_bytes = 0
        for _ in range(MAX_INTERIM_RESPONSES + 1):
            try:
                status_line = await asyncio.wait_for(
                    channel.readline(MAX_HEADER_BYTES),
                    timeout=self.read_timeout,
                )
            except asyncio.TimeoutError as exc:
                raise ProxyTransportError(
                    "Timed out reading HTTP status line",
                    category=ErrorCategory.READ_TIMEOUT,
                ) from exc
            except ValueError as exc:
                raise ProxyTransportError(
                    "HTTP status line exceeded maximum size",
                    category=ErrorCategory.PROXY_PROTOCOL_ERROR,
                ) from exc
            except OSError as exc:
                raise _classify_os_error(exc, stage="tunnel") from exc

            if not status_line:
                raise ProxyTransportError(
                    "Empty HTTP response (connection closed)",
                    category=ErrorCategory.CONNECTION_RESET,
                )
            total_bytes += len(status_line)
            stripped = status_line.rstrip(b"\r\n")
            match = _STATUS_LINE_RE.match(stripped)
            if not match:
                raise ProxyTransportError(
                    "Malformed or non-HTTP response status line",
                    category=ErrorCategory.PROXY_PROTOCOL_ERROR,
                )
            status_code = int(match.group(2))

            headers: Dict[str, str] = {}
            header_count = 0
            while True:
                try:
                    line = await asyncio.wait_for(
                        channel.readline(MAX_HEADER_BYTES),
                        timeout=self.read_timeout,
                    )
                except asyncio.TimeoutError as exc:
                    raise ProxyTransportError(
                        "Timed out reading HTTP headers",
                        category=ErrorCategory.READ_TIMEOUT,
                    ) from exc
                except ValueError as exc:
                    raise ProxyTransportError(
                        "HTTP header line exceeded maximum size",
                        category=ErrorCategory.PROXY_PROTOCOL_ERROR,
                    ) from exc
                except OSError as exc:
                    raise _classify_os_error(exc, stage="tunnel") from exc

                if not line:
                    raise ProxyTransportError(
                        "Unexpected EOF while reading HTTP headers",
                        category=ErrorCategory.CONNECTION_RESET,
                    )
                total_bytes += len(line)
                if total_bytes > MAX_HEADER_BYTES:
                    raise ProxyTransportError(
                        "HTTP headers exceeded 64 KiB cap",
                        category=ErrorCategory.RESPONSE_TOO_LARGE,
                    )
                if line in (b"\r\n", b"\n"):
                    break
                header_count += 1
                if header_count > MAX_HEADERS:
                    raise ProxyTransportError(
                        "HTTP response exceeded header count cap",
                        category=ErrorCategory.RESPONSE_TOO_LARGE,
                    )
                decoded_line = line.rstrip(b"\r\n").decode("latin-1")
                if ":" not in decoded_line:
                    raise ProxyTransportError(
                        "Malformed HTTP header line",
                        category=ErrorCategory.PROXY_PROTOCOL_ERROR,
                    )
                name, val = decoded_line.split(":", 1)
                key = name.strip().lower()
                val_clean = val.strip()
                if key in headers:
                    headers[key] = f"{headers[key]}, {val_clean}"
                else:
                    headers[key] = val_clean

            if 100 <= status_code < 200:
                continue
            return status_code, headers

        raise ProxyTransportError(
            "Too many interim 1xx HTTP responses",
            category=ErrorCategory.PROXY_PROTOCOL_ERROR,
        )

    async def _read_bounded_body(
        self,
        channel: _StreamChannel,
        headers: Dict[str, str],
        deadline: float,
    ) -> bytes:
        """Read HTTP body via Transfer-Encoding: chunked, Content-Length, or EOF."""
        transfer_enc = headers.get("transfer-encoding", "").lower()
        body = bytearray()

        def _remaining_timeout() -> float:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise asyncio.TimeoutError()
            return min(self.read_timeout, rem)

        if "chunked" in transfer_enc:
            while len(body) < MAX_BODY_BYTES:
                try:
                    size_line = await asyncio.wait_for(
                        channel.readline(MAX_HEADER_BYTES),
                        timeout=_remaining_timeout(),
                    )
                except asyncio.TimeoutError as exc:
                    raise ProxyTransportError(
                        "Timed out reading chunk size",
                        category=ErrorCategory.READ_TIMEOUT,
                    ) from exc
                if not size_line:
                    raise TargetValidationError(
                        "Unexpected EOF in chunked body",
                        category=ErrorCategory.INVALID_RESPONSE,
                    )
                size_token = size_line.split(b";", 1)[0].strip()
                try:
                    chunk_size = int(size_token, 16)
                except ValueError as exc:
                    raise TargetValidationError(
                        "Invalid HTTP chunk size",
                        category=ErrorCategory.INVALID_RESPONSE,
                    ) from exc
                if chunk_size < 0:
                    raise TargetValidationError(
                        "Negative HTTP chunk size",
                        category=ErrorCategory.INVALID_RESPONSE,
                    )
                if chunk_size == 0:
                    break

                to_read = min(chunk_size, MAX_BODY_BYTES - len(body))
                remaining_in_chunk = chunk_size
                while to_read > 0:
                    try:
                        part = await asyncio.wait_for(
                            channel.readexactly(to_read),
                            timeout=_remaining_timeout(),
                        )
                    except asyncio.TimeoutError as exc:
                        raise ProxyTransportError(
                            "Timed out reading chunked payload",
                            category=ErrorCategory.READ_TIMEOUT,
                        ) from exc
                    except asyncio.IncompleteReadError as exc:
                        raise TargetValidationError(
                            "Incomplete HTTP chunk payload",
                            category=ErrorCategory.INVALID_RESPONSE,
                        ) from exc
                    body.extend(part)
                    remaining_in_chunk -= len(part)
                    to_read = 0

                if remaining_in_chunk > 0:
                    # Reached MAX_BODY_BYTES cap safely
                    break

                # Consume trailing CRLF after chunk
                try:
                    crlf = await asyncio.wait_for(
                        channel.readline(16),
                        timeout=_remaining_timeout(),
                    )
                except asyncio.TimeoutError as exc:
                    raise ProxyTransportError(
                        "Timed out reading chunk terminator",
                        category=ErrorCategory.READ_TIMEOUT,
                    ) from exc
                if crlf not in (b"\r\n", b"\n"):
                    raise TargetValidationError(
                        "Missing CRLF after HTTP chunk",
                        category=ErrorCategory.INVALID_RESPONSE,
                    )
            return bytes(body)

        content_length_raw = headers.get("content-length")
        if content_length_raw is not None:
            try:
                content_length = int(content_length_raw.split(",")[0].strip())
            except ValueError as exc:
                raise TargetValidationError(
                    "Invalid Content-Length header",
                    category=ErrorCategory.INVALID_RESPONSE,
                ) from exc
            if content_length < 0:
                raise TargetValidationError(
                    "Negative Content-Length header",
                    category=ErrorCategory.INVALID_RESPONSE,
                )
            target_read = min(content_length, MAX_BODY_BYTES)
            while len(body) < target_read:
                try:
                    chunk = await asyncio.wait_for(
                        channel.read(min(16384, target_read - len(body))),
                        timeout=_remaining_timeout(),
                    )
                except asyncio.TimeoutError as exc:
                    raise ProxyTransportError(
                        "Timed out reading HTTP body",
                        category=ErrorCategory.READ_TIMEOUT,
                    ) from exc
                if not chunk:
                    raise TargetValidationError(
                        "Truncated HTTP body before Content-Length",
                        category=ErrorCategory.INVALID_RESPONSE,
                    )
                body.extend(chunk)
            return bytes(body)

        # Read until EOF up to MAX_BODY_BYTES
        while len(body) < MAX_BODY_BYTES:
            try:
                chunk = await asyncio.wait_for(
                    channel.read(min(16384, MAX_BODY_BYTES - len(body))),
                    timeout=_remaining_timeout(),
                )
            except asyncio.TimeoutError as exc:
                raise ProxyTransportError(
                    "Timed out reading HTTP body",
                    category=ErrorCategory.READ_TIMEOUT,
                ) from exc
            if not chunk:
                break
            body.extend(chunk)
        return bytes(body)

    async def _http_connect_tunnel(
        self,
        channel: _StreamChannel,
        proxy: ProxyEntry,
        target_host: str,
        target_port: int,
    ) -> None:
        """Send HTTP CONNECT to establish a tunnel through an HTTP/HTTPS proxy."""
        authority = format_authority(target_host, target_port)
        lines = [
            f"CONNECT {authority} HTTP/1.1",
            f"Host: {authority}",
            f"User-Agent: {self.user_agent}",
            "Proxy-Connection: Keep-Alive",
        ]
        auth_header = self._build_proxy_auth_header(proxy)
        if auth_header:
            lines.append(f"Proxy-Authorization: {auth_header}")
        req_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")

        try:
            await asyncio.wait_for(
                channel.write_and_drain(req_bytes),
                timeout=self.read_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ProxyTransportError(
                "Timed out sending HTTP CONNECT request",
                category=ErrorCategory.READ_TIMEOUT,
            ) from exc
        except OSError as exc:
            raise _classify_os_error(exc, stage="tunnel") from exc

        status_code, _ = await self._read_http_head(channel)
        if status_code == 407:
            raise ProxyTransportError(
                "Proxy requires authentication (HTTP 407)",
                category=ErrorCategory.PROXY_AUTH_REQUIRED
                if proxy.username is None
                else ErrorCategory.PROXY_AUTH_FAILED,
                proxy_fatal=True,
            )
        if not (200 <= status_code < 300):
            raise ProxyTransportError(
                f"HTTP CONNECT rejected with status {status_code}",
                category=ErrorCategory.HTTP_ERROR,
                proxy_fatal=False,
            )

    async def _single_http_request(
        self,
        proxy: ProxyEntry,
        url: str,
        deadline: float,
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Execute one HTTP/1.1 GET through the configured proxy without redirects."""
        scheme, target_host, target_port, path = validate_target_url(url)
        default_port = 443 if scheme == "https" else 80
        is_http_proxy = proxy.protocol in (ProxyProtocol.HTTP, ProxyProtocol.HTTPS)
        use_tunnel = (not is_http_proxy) or (scheme == "https")

        channel = await self._open_proxy_channel(proxy)
        try:
            if proxy.protocol in (ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS4A):
                await self._socks4_handshake(channel, proxy, target_host, target_port)
            elif proxy.protocol in (ProxyProtocol.SOCKS5, ProxyProtocol.SOCKS5H):
                await self._socks5_handshake(channel, proxy, target_host, target_port)
            elif is_http_proxy and use_tunnel:
                await self._http_connect_tunnel(channel, proxy, target_host, target_port)

            if scheme == "https":
                try:
                    await channel.upgrade_tls(
                        self.target_ssl_context,
                        server_hostname=target_host,
                        handshake_timeout=min(self.connect_timeout, max(0.2, deadline - time.monotonic())),
                    )
                except asyncio.TimeoutError as exc:
                    raise ProxyTransportError(
                        "Target TLS handshake timed out",
                        category=ErrorCategory.CONNECT_TIMEOUT,
                    ) from exc
                except (ssl.SSLError, OSError, EOFError) as exc:
                    raise ProxyTransportError(
                        f"Target TLS error: {exc}",
                        category=ErrorCategory.TLS_ERROR,
                    ) from exc

            request_target = path if use_tunnel else url
            host_header = format_host_header(target_host, target_port, default_port)
            req_lines = [
                f"GET {request_target} HTTP/1.1",
                f"Host: {host_header}",
                f"User-Agent: {self.user_agent}",
                "Accept: application/json, text/html, */*;q=0.8",
                "Accept-Encoding: gzip, deflate",
                "Connection: close",
            ]
            # Send Proxy-Authorization ONLY to direct HTTP/HTTPS proxy requests,
            # never inside an encrypted/SOCKS tunnel to the target server.
            if is_http_proxy and not use_tunnel:
                auth_header = self._build_proxy_auth_header(proxy)
                if auth_header:
                    req_lines.append(f"Proxy-Authorization: {auth_header}")
                req_lines.append("Proxy-Connection: close")

            payload = ("\r\n".join(req_lines) + "\r\n\r\n").encode("latin-1")
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise ProxyTransportError(
                    "Request exceeded total timeout",
                    category=ErrorCategory.TOTAL_TIMEOUT,
                )
            try:
                await asyncio.wait_for(
                    channel.write_and_drain(payload),
                    timeout=min(self.read_timeout, rem),
                )
            except asyncio.TimeoutError as exc:
                raise ProxyTransportError(
                    "Timed out sending HTTP GET request",
                    category=ErrorCategory.READ_TIMEOUT,
                ) from exc
            except OSError as exc:
                raise _classify_os_error(exc, stage="tunnel") from exc

            status_code, headers = await self._read_http_head(channel)
            if status_code == 407 and is_http_proxy and not use_tunnel:
                raise ProxyTransportError(
                    "Proxy requires authentication (HTTP 407)",
                    category=ErrorCategory.PROXY_AUTH_REQUIRED
                    if proxy.username is None
                    else ErrorCategory.PROXY_AUTH_FAILED,
                    proxy_fatal=True,
                )
            body_raw = await self._read_bounded_body(channel, headers, deadline)
            body = _safe_decompress(body_raw, headers.get("content-encoding", ""))
            return status_code, headers, body
        finally:
            await channel.close()

    async def fetch(
        self,
        proxy: ProxyEntry,
        url: str,
    ) -> Tuple[int, Dict[str, str], bytes, float]:
        """Fetch URL through proxy with total deadline and optional safe redirects."""
        start = time.perf_counter()
        deadline = time.monotonic() + self.total_timeout
        current_url = url
        initial_scheme, _, _, _ = validate_target_url(url)

        async def _run() -> Tuple[int, Dict[str, str], bytes]:
            nonlocal current_url
            for _ in range(MAX_REDIRECTS + 1):
                status_code, headers, body = await self._single_http_request(
                    proxy, current_url, deadline
                )
                if status_code in (301, 302, 303, 307, 308):
                    if not self.follow_redirects:
                        return status_code, headers, body
                    location = headers.get("location")
                    if not location:
                        raise TargetValidationError(
                            f"Redirect {status_code} missing Location header",
                            category=ErrorCategory.REDIRECT_BLOCKED,
                        )
                    next_url = urljoin(current_url, location)
                    try:
                        next_scheme, next_host, _, _ = validate_target_url(next_url)
                    except ValueError as exc:
                        raise TargetValidationError(
                            f"Blocked invalid redirect target: {exc}",
                            category=ErrorCategory.REDIRECT_BLOCKED,
                        ) from exc
                    if initial_scheme == "https" and next_scheme != "https":
                        raise TargetValidationError(
                            "Blocked HTTPS-to-HTTP redirect downgrade",
                            category=ErrorCategory.REDIRECT_BLOCKED,
                        )
                    if is_non_public_ip(next_host):
                        raise TargetValidationError(
                            "Blocked redirect to non-public IP/localhost",
                            category=ErrorCategory.REDIRECT_BLOCKED,
                        )
                    current_url = next_url
                    continue
                return status_code, headers, body

            raise TargetValidationError(
                f"Exceeded maximum redirects ({MAX_REDIRECTS})",
                category=ErrorCategory.REDIRECT_BLOCKED,
            )

        try:
            rem = max(0.05, deadline - time.monotonic())
            status_code, headers, body = await asyncio.wait_for(_run(), timeout=rem)
        except asyncio.TimeoutError as exc:
            raise ProxyTransportError(
                f"Exceeded total timeout ({self.total_timeout:.1f}s)",
                category=ErrorCategory.TOTAL_TIMEOUT,
            ) from exc

        latency_ms = (time.perf_counter() - start) * 1000.0
        return status_code, headers, body, latency_ms


# ---------------------------------------------------------------------------
# Response & Anonymity Validation
# ---------------------------------------------------------------------------


def validate_target_response(
    target: TestTarget,
    status_code: int,
    body: bytes,
) -> None:
    """Verify HTTP status code and response content match expected target behavior."""
    if status_code in (301, 302, 303, 307, 308):
        raise TargetValidationError(
            f"Unexpected redirect (HTTP {status_code}); possible captive portal",
            category=ErrorCategory.REDIRECT_BLOCKED,
        )
    if status_code not in target.expected_statuses:
        raise TargetValidationError(
            f"Unexpected HTTP status {status_code}",
            category=ErrorCategory.HTTP_ERROR,
        )
    if target.require_non_empty and not body.strip():
        raise TargetValidationError(
            "Empty response body",
            category=ErrorCategory.INVALID_RESPONSE,
        )

    text = body.decode("utf-8", errors="replace")
    if target.expected_json_key is not None:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise TargetValidationError(
                "Response is not valid JSON (possible proxy error or captive portal)",
                category=ErrorCategory.INVALID_RESPONSE,
            ) from exc
        if not isinstance(parsed, dict) or target.expected_json_key not in parsed:
            raise TargetValidationError(
                f"JSON missing expected key {target.expected_json_key!r}",
                category=ErrorCategory.INVALID_RESPONSE,
            )

    if target.expected_substring is not None and target.expected_substring not in text:
        raise TargetValidationError(
            f"Response missing expected content {target.expected_substring!r}",
            category=ErrorCategory.INVALID_RESPONSE,
        )


async def fetch_client_public_ip(
    url: str = "https://httpbin.org/ip",
    timeout: float = 4.0,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Optional[str]:
    """Best-effort direct lookup of the client's public IP for transparency checks."""
    try:
        scheme, host, port, path = validate_target_url(url)
    except ValueError:
        return None
    ctx = (ssl_context or create_strict_ssl_context()) if scheme == "https" else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ctx,
                server_hostname=host if scheme == "https" else None,
            ),
            timeout=timeout,
        )
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        return None

    try:
        host_header = format_host_header(host, port, 443 if scheme == "https" else 80)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {DEFAULT_USER_AGENT}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin-1")
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        raw = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        sep = raw.find(b"\r\n\r\n")
        if sep == -1:
            return None
        payload = json.loads(raw[sep + 4 :].decode("utf-8", errors="replace"))
        origin = payload.get("origin")
        if isinstance(origin, str):
            return origin.split(",")[0].strip()
    except (OSError, asyncio.TimeoutError, json.JSONDecodeError, ValueError):
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except Exception:
            pass
    return None


def classify_anonymity(
    payload: Dict[str, object],
    client_public_ip: Optional[str],
) -> Tuple[AnonymityLevel, Optional[str]]:
    """Classify proxy anonymity from an httpbin-style JSON echo response."""
    origin_raw = payload.get("origin")
    origin_str = str(origin_raw) if isinstance(origin_raw, str) else ""
    exit_ip: Optional[str] = None
    if origin_str:
        exit_ip = origin_str.split(",")[-1].strip() or None

    raw_headers = payload.get("headers")
    headers_lower: Dict[str, str] = {}
    if isinstance(raw_headers, dict):
        headers_lower = {
            str(k).lower(): str(v) for k, v in raw_headers.items()
        }

    # Check if client's real IP leaked in origin or any header value
    if client_public_ip:
        if client_public_ip in origin_str:
            return AnonymityLevel.TRANSPARENT, exit_ip
        for val in headers_lower.values():
            if client_public_ip in val:
                return AnonymityLevel.TRANSPARENT, exit_ip

    # Check for proxy-revealing headers
    for hdr in ANONYMITY_PROXY_HEADERS:
        if hdr in headers_lower:
            return AnonymityLevel.ANONYMOUS, exit_ip

    if origin_str or headers_lower:
        return AnonymityLevel.ELITE, exit_ip
    return AnonymityLevel.UNKNOWN, exit_ip


# ---------------------------------------------------------------------------
# Concurrency Orchestrator
# ---------------------------------------------------------------------------


class ProxyChecker:
    """Bounded async proxy checking engine with streaming input and safe reporting."""

    def __init__(
        self,
        config: CheckerConfig,
        client: Optional[AsyncProxyClient] = None,
        output_stream: Optional[object] = None,
        error_stream: Optional[object] = None,
    ) -> None:
        self.config = config
        self.client = client or AsyncProxyClient(
            connect_timeout=config.connect_timeout,
            read_timeout=config.read_timeout,
            total_timeout=config.total_timeout,
            user_agent=config.user_agent,
            follow_redirects=config.follow_redirects,
        )
        self.out = output_stream if output_stream is not None else sys.stdout
        self.err = error_stream if error_stream is not None else sys.stderr
        self._print_lock = asyncio.Lock()

    async def _emit(self, message: str) -> None:
        if self.config.quiet:
            return
        async with self._print_lock:
            print(message, file=self.out, flush=True)

    async def _assess_anonymity(
        self,
        proxy: ProxyEntry,
        client_public_ip: Optional[str],
    ) -> Tuple[AnonymityLevel, Optional[str]]:
        try:
            status_code, _, body, _ = await self.client.fetch(
                proxy, self.config.anonymity_url
            )
            if status_code != 200:
                return AnonymityLevel.UNKNOWN, None
            data = json.loads(body.decode("utf-8", errors="replace"))
            if not isinstance(data, dict):
                return AnonymityLevel.UNKNOWN, None
            return classify_anonymity(data, client_public_ip)
        except (ProxyCheckerError, json.JSONDecodeError, ValueError):
            return AnonymityLevel.UNKNOWN, None

    async def check_single(
        self,
        proxy: ProxyEntry,
        client_public_ip: Optional[str] = None,
    ) -> CheckResult:
        """Validate a single ProxyEntry against configured targets."""
        last_error: Optional[ProxyCheckerError] = None
        secrets = (proxy.username, proxy.password)

        for target in self.config.targets:
            try:
                status_code, _, body, latency_ms = await self.client.fetch(
                    proxy, target.url
                )
                validate_target_response(target, status_code, body)

                anonymity = AnonymityLevel.UNKNOWN
                exit_ip: Optional[str] = None
                if self.config.check_anonymity:
                    anonymity, exit_ip = await self._assess_anonymity(
                        proxy, client_public_ip
                    )

                result = CheckResult(
                    proxy_masked=proxy.masked_uri(),
                    proxy_output=proxy.output_line(
                        include_scheme=self.config.output_with_scheme
                    ),
                    protocol=proxy.protocol.value,
                    host=proxy.host,
                    port=proxy.port,
                    status=ProxyStatus.WORKING,
                    latency_ms=latency_ms,
                    http_status=status_code,
                    checked_url=target.url,
                    anonymity=anonymity,
                    exit_ip=exit_ip,
                    error_category=ErrorCategory.NONE,
                    error_message="",
                    line_number=proxy.line_number,
                )
                extra = f" | {anonymity.value}" if self.config.check_anonymity else ""
                await self._emit(
                    f"[+] WORKING: {proxy.masked_uri()} ({target.url}, {latency_ms:.0f}ms{extra})"
                )
                return result
            except ProxyCheckerError as exc:
                last_error = exc
                if exc.proxy_fatal:
                    break

        category = last_error.category if last_error else ErrorCategory.CONNECTION_REFUSED
        raw_msg = str(last_error) if last_error else "All target checks failed"
        clean_msg = sanitize_error_message(raw_msg, secrets=secrets)
        result = CheckResult(
            proxy_masked=proxy.masked_uri(),
            proxy_output=proxy.output_line(
                include_scheme=self.config.output_with_scheme
            ),
            protocol=proxy.protocol.value,
            host=proxy.host,
            port=proxy.port,
            status=ProxyStatus.DEAD,
            error_category=category,
            error_message=clean_msg,
            line_number=proxy.line_number,
        )
        if self.config.verbose:
            await self._emit(
                f"[-] DEAD:    {proxy.masked_uri()} [{category.value}: {clean_msg}]"
            )
        else:
            await self._emit(f"[-] DEAD:    {proxy.masked_uri()}")
        return result

    async def run_entries(
        self,
        entries: Iterable[Tuple[int, str]],
        client_public_ip: Optional[str] = None,
    ) -> CheckSummary:
        """Stream, parse, deduplicate, and check proxy lines with bounded concurrency."""
        start_time = time.monotonic()
        summary = CheckSummary(client_public_ip=client_public_ip)
        allowed_protocols = set(self.config.protocols)
        seen_keys: Set[Tuple[str, str, int, Optional[str]]] = set()
        error_counter: Counter[str] = Counter()

        if self.config.check_anonymity and summary.client_public_ip is None:
            summary.client_public_ip = await fetch_client_public_ip(
                timeout=min(4.0, self.config.connect_timeout),
                ssl_context=self.client.target_ssl_context,
            )

        queue: asyncio.Queue[Optional[ProxyEntry]] = asyncio.Queue(
            maxsize=max(1, self.config.concurrency * 2)
        )
        stop_event = asyncio.Event()

        async def _producer() -> None:
            try:
                for line_no, raw_line in entries:
                    if stop_event.is_set():
                        break
                    summary.total_lines += 1
                    try:
                        entry = parse_proxy_line(
                            raw_line,
                            default_protocol=self.config.default_protocol,
                            line_number=line_no,
                        )
                    except ProxyParseError as exc:
                        summary.invalid_count += 1
                        error_counter[exc.category.value] += 1
                        clean = sanitize_error_message(str(exc))
                        summary.results.append(
                            CheckResult(
                                proxy_masked=f"<line:{line_no}>",
                                proxy_output="",
                                protocol=self.config.default_protocol.value,
                                host="",
                                port=None,
                                status=ProxyStatus.INVALID,
                                error_category=exc.category,
                                error_message=clean,
                                line_number=line_no,
                            )
                        )
                        if self.config.verbose:
                            await self._emit(
                                f"[!] INVALID: line {line_no} [{exc.category.value}: {clean}]"
                            )
                        continue

                    if entry is None:
                        continue

                    if entry.protocol not in allowed_protocols:
                        summary.filtered_skipped += 1
                        continue

                    if self.config.deduplicate:
                        key = entry.dedup_key
                        if key in seen_keys:
                            summary.duplicates_skipped += 1
                            continue
                        seen_keys.add(key)

                    await queue.put(entry)
            finally:
                for _ in range(self.config.concurrency):
                    try:
                        queue.put_nowait(None)
                    except asyncio.QueueFull:
                        await queue.put(None)

        async def _worker() -> None:
            while not stop_event.is_set():
                entry = await queue.get()
                try:
                    if entry is None:
                        return
                    res = await self.check_single(
                        entry, client_public_ip=summary.client_public_ip
                    )
                    summary.results.append(res)
                    summary.checked_count += 1
                    if res.status == ProxyStatus.WORKING:
                        summary.working_count += 1
                    else:
                        summary.dead_count += 1
                        error_counter[res.error_category.value] += 1
                finally:
                    queue.task_done()

        producer_task = asyncio.create_task(_producer())
        worker_tasks = [
            asyncio.create_task(_worker()) for _ in range(self.config.concurrency)
        ]

        loop = asyncio.get_running_loop()
        installed_signals: List[signal.Signals] = []

        def _handle_signal() -> None:
            summary.interrupted = True
            stop_event.set()
            producer_task.cancel()
            for wt in worker_tasks:
                wt.cancel()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _handle_signal)
                installed_signals.append(sig)
            except (NotImplementedError, RuntimeError):
                pass

        try:
            await asyncio.gather(producer_task, *worker_tasks)
        except asyncio.CancelledError:
            summary.interrupted = True
            stop_event.set()
            producer_task.cancel()
            for wt in worker_tasks:
                wt.cancel()
            await asyncio.gather(producer_task, *worker_tasks, return_exceptions=True)
        finally:
            for sig in installed_signals:
                try:
                    loop.remove_signal_handler(sig)
                except Exception:
                    pass

        summary.elapsed_seconds = time.monotonic() - start_time
        summary.error_counts = dict(error_counter)
        return summary

    def run_file(self) -> CheckSummary:
        """Run proxy checks synchronously from the configured input file."""
        validate_io_paths(self.config)
        return asyncio.run(self.run_entries(iter_proxy_lines(self.config.input_file)))


# ---------------------------------------------------------------------------
# Atomic Output & Report Exporting
# ---------------------------------------------------------------------------


class ResultWriter:
    """Safely writes proxy results to text, JSON, and CSV files atomically."""

    @staticmethod
    def _atomic_write_text(path: Path, content: str) -> None:
        parent = path.parent if path.parent != Path("") else Path(".")
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(parent)
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
        except BaseException:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    @classmethod
    def write_all(cls, config: CheckerConfig, summary: CheckSummary) -> None:
        """Write all configured output files atomically."""
        working_lines = [
            r.proxy_output
            for r in summary.results
            if r.status == ProxyStatus.WORKING and r.proxy_output
        ]
        content = ("\n".join(working_lines) + "\n") if working_lines else ""
        cls._atomic_write_text(config.output_file, content)

        if config.failed_output_file is not None:
            failed_lines = [
                f"{r.proxy_masked}\t{r.error_category.value}\t{r.error_message}"
                for r in summary.results
                if r.status in (ProxyStatus.DEAD, ProxyStatus.INVALID)
            ]
            failed_content = ("\n".join(failed_lines) + "\n") if failed_lines else ""
            cls._atomic_write_text(config.failed_output_file, failed_content)

        if config.json_output_file is not None:
            payload = {
                "version": __version__,
                "interrupted": summary.interrupted,
                "elapsed_seconds": round(summary.elapsed_seconds, 3),
                "summary": {
                    "total_lines": summary.total_lines,
                    "checked": summary.checked_count,
                    "working": summary.working_count,
                    "dead": summary.dead_count,
                    "invalid": summary.invalid_count,
                    "duplicates_skipped": summary.duplicates_skipped,
                    "filtered_skipped": summary.filtered_skipped,
                    "error_counts": summary.error_counts,
                },
                "results": [
                    r.to_dict(include_credentials=config.include_credentials_in_reports)
                    for r in summary.results
                ],
            }
            cls._atomic_write_text(
                config.json_output_file,
                json.dumps(payload, indent=2) + "\n",
            )

        if config.csv_output_file is not None:
            fieldnames = [
                "proxy",
                "protocol",
                "host",
                "port",
                "status",
                "latency_ms",
                "http_status",
                "checked_url",
                "anonymity",
                "exit_ip",
                "error_category",
                "error_message",
                "line_number",
            ]
            parent = (
                config.csv_output_file.parent
                if config.csv_output_file.parent != Path("")
                else Path(".")
            )
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{config.csv_output_file.name}.",
                suffix=".tmp",
                dir=str(parent),
            )
            tmp_path = Path(tmp_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fieldnames)
                    writer.writeheader()
                    for res in summary.results:
                        row = res.to_dict(
                            include_credentials=config.include_credentials_in_reports
                        )
                        safe_row = {
                            k: (
                                v
                                if isinstance(v, (int, float))
                                else sanitize_csv_cell(v)
                            )
                            for k, v in row.items()
                        }
                        writer.writerow(safe_row)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, config.csv_output_file)
            except BaseException:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass
                raise


# ---------------------------------------------------------------------------
# CLI Argument Parsing & Entrypoint
# ---------------------------------------------------------------------------


def _parse_protocols_arg(value: str) -> Tuple[ProxyProtocol, ...]:
    tokens = [tok.strip().lower() for tok in value.split(",") if tok.strip()]
    if not tokens:
        raise argparse.ArgumentTypeError("Protocol filter cannot be empty")
    if "all" in tokens:
        return tuple(ProxyProtocol)
    result: List[ProxyProtocol] = []
    for tok in tokens:
        if tok not in SUPPORTED_PROTOCOLS:
            raise argparse.ArgumentTypeError(
                f"Unsupported protocol {tok!r}. Choose from: {', '.join(SUPPORTED_PROTOCOLS)}, all"
            )
        proto = ProxyProtocol(tok)
        if proto not in result:
            result.append(proto)
    return tuple(result)


def _positive_float(value: str) -> float:
    try:
        num = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected number, got {value!r}") from exc
    if num <= 0 or num > 300:
        raise argparse.ArgumentTypeError("Timeout must be > 0 and <= 300 seconds")
    return num


def _bounded_concurrency(value: str) -> int:
    try:
        num = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected integer, got {value!r}") from exc
    if not (1 <= num <= MAX_CONCURRENCY):
        raise argparse.ArgumentTypeError(
            f"Concurrency must be between 1 and {MAX_CONCURRENCY}"
        )
    return num


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="proxy_checker",
        description=(
            "Asynchronous multi-protocol proxy checker (HTTP, HTTPS, SOCKS4, "
            "SOCKS4a, SOCKS5, SOCKS5h) with strict TLS verification."
        ),
    )
    parser.add_argument(
        "-i",
        "--input",
        default=DEFAULT_INPUT_FILE,
        help=f"Input file containing proxies (default: {DEFAULT_INPUT_FILE})",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT_FILE,
        help=f"Output file for working proxies (default: {DEFAULT_OUTPUT_FILE})",
    )
    parser.add_argument(
        "--failed-output",
        default=None,
        help="Optional file to save dead/invalid proxies with error classifications",
    )
    parser.add_argument(
        "--json-output",
        default=None,
        help="Optional path to export structured JSON results",
    )
    parser.add_argument(
        "--csv-output",
        default=None,
        help="Optional path to export structured CSV results",
    )
    parser.add_argument(
        "-p",
        "--protocol",
        type=_parse_protocols_arg,
        default=tuple(ProxyProtocol),
        help=(
            "Comma-separated protocols to check "
            f"({', '.join(SUPPORTED_PROTOCOLS)}, or 'all'; default: all)"
        ),
    )
    parser.add_argument(
        "--default-protocol",
        choices=SUPPORTED_PROTOCOLS,
        default=ProxyProtocol.HTTP.value,
        help="Protocol assumed for bare host:port lines without a scheme (default: http)",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=_bounded_concurrency,
        default=DEFAULT_CONCURRENCY,
        help=f"Max concurrent checks 1..{MAX_CONCURRENCY} (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "--connect-timeout",
        type=_positive_float,
        default=DEFAULT_CONNECT_TIMEOUT,
        help=f"Proxy TCP/TLS connect timeout in seconds (default: {DEFAULT_CONNECT_TIMEOUT})",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        "--read-timeout",
        dest="read_timeout",
        type=_positive_float,
        default=DEFAULT_READ_TIMEOUT,
        help=f"Socket read/handshake timeout in seconds (default: {DEFAULT_READ_TIMEOUT})",
    )
    parser.add_argument(
        "--total-timeout",
        type=_positive_float,
        default=DEFAULT_TOTAL_TIMEOUT,
        help=f"Total wall-clock timeout per target request in seconds (default: {DEFAULT_TOTAL_TIMEOUT})",
    )
    parser.add_argument(
        "-u",
        "--url",
        action="append",
        dest="urls",
        default=None,
        help="Custom test URL (repeatable; overrides default test URLs)",
    )
    parser.add_argument(
        "--expect-text",
        default=None,
        help="Required substring in custom --url response bodies",
    )
    parser.add_argument(
        "--expect-json-key",
        default=None,
        help="Required top-level JSON key in custom --url response bodies",
    )
    parser.add_argument(
        "--require-https",
        action="store_true",
        help="Only test HTTPS targets to strictly verify TLS tunneling",
    )
    parser.add_argument(
        "--follow-redirects",
        action="store_true",
        help="Follow safe HTTP redirects (off by default to catch captive portals)",
    )
    parser.add_argument(
        "--check-anonymity",
        action="store_true",
        help="Assess proxy anonymity (transparent/anonymous/elite) on working proxies",
    )
    parser.add_argument(
        "--anonymity-url",
        default=DEFAULT_ANONYMITY_URL,
        help=f"JSON echo URL used for anonymity checks (default: {DEFAULT_ANONYMITY_URL})",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help=f"Custom User-Agent header (default: {DEFAULT_USER_AGENT})",
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable duplicate proxy detection",
    )
    parser.add_argument(
        "--no-overwrite",
        action="store_true",
        help="Fail instead of overwriting existing output files",
    )
    parser.add_argument(
        "--output-with-scheme",
        action="store_true",
        help="Always include scheme:// in working proxy output file",
    )
    parser.add_argument(
        "--include-credentials",
        action="store_true",
        help="Include proxy credentials in JSON/CSV exports (masked by default)",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed failure reasons and invalid line diagnostics",
    )
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress per-proxy progress output; print only errors and summary",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def build_config(args: argparse.Namespace) -> CheckerConfig:
    """Convert validated CLI arguments into a CheckerConfig."""
    if args.urls:
        targets_list: List[TestTarget] = []
        for u in args.urls:
            scheme, _, _, _ = validate_target_url(u)
            if args.require_https and scheme != "https":
                raise ValueError(
                    f"Non-HTTPS custom URL {u!r} cannot be used with --require-https"
                )
            targets_list.append(
                TestTarget(
                    url=u,
                    expected_statuses=(200,),
                    expected_substring=args.expect_text,
                    expected_json_key=args.expect_json_key,
                )
            )
        targets = tuple(targets_list)
    else:
        targets = DEFAULT_HTTPS_TARGETS if args.require_https else DEFAULT_TEST_TARGETS

    validate_target_url(args.anonymity_url)
    total_timeout = max(args.total_timeout, args.connect_timeout, args.read_timeout)
    if _CONTROL_CHARS_RE.search(args.user_agent):
        raise ValueError("User-Agent contains invalid control characters")

    return CheckerConfig(
        input_file=Path(args.input),
        output_file=Path(args.output),
        failed_output_file=Path(args.failed_output) if args.failed_output else None,
        json_output_file=Path(args.json_output) if args.json_output else None,
        csv_output_file=Path(args.csv_output) if args.csv_output else None,
        protocols=args.protocol,
        default_protocol=ProxyProtocol(args.default_protocol),
        concurrency=args.concurrency,
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        total_timeout=total_timeout,
        targets=targets,
        require_https=args.require_https,
        follow_redirects=args.follow_redirects,
        check_anonymity=args.check_anonymity,
        anonymity_url=args.anonymity_url,
        user_agent=args.user_agent,
        deduplicate=not args.no_dedup,
        allow_overwrite=not args.no_overwrite,
        output_with_scheme=args.output_with_scheme,
        include_credentials_in_reports=args.include_credentials,
        verbose=args.verbose,
        quiet=args.quiet,
    )


def format_summary(config: CheckerConfig, summary: CheckSummary) -> str:
    """Format final human-readable summary statistics."""
    status_label = "Interrupted" if summary.interrupted else "Done"
    lines = [
        "",
        f"{status_label}! Checked {summary.checked_count} proxies in {summary.elapsed_seconds:.2f}s:",
        f"  Working:            {summary.working_count}",
        f"  Dead:               {summary.dead_count}",
        f"  Invalid lines:      {summary.invalid_count}",
        f"  Duplicates skipped: {summary.duplicates_skipped}",
        f"  Filtered skipped:   {summary.filtered_skipped}",
        f"  Saved working to:   {config.output_file}",
    ]
    if summary.error_counts:
        top_errors = ", ".join(
            f"{k}={v}"
            for k, v in sorted(
                summary.error_counts.items(), key=lambda item: item[1], reverse=True
            )
        )
        lines.append(f"  Error breakdown:    {top_errors}")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point returning POSIX exit code."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        config = build_config(args)
        validate_io_paths(config)
    except (
        ValueError,
        FileNotFoundError,
        FileExistsError,
        IsADirectoryError,
        PermissionError,
        OSError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    checker = ProxyChecker(config)
    try:
        summary = checker.run_file()
    except KeyboardInterrupt:
        print("\nInterrupted before results could be finalized.", file=sys.stderr)
        return 130
    except OSError as exc:
        print(f"Error reading input file {config.input_file}: {exc}", file=sys.stderr)
        return 1

    try:
        ResultWriter.write_all(config, summary)
    except OSError as exc:
        print(f"Error writing output file(s): {exc}", file=sys.stderr)
        return 1

    print(format_summary(config, summary), flush=True)
    return 130 if summary.interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())