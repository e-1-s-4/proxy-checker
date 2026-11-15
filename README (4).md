# Proxy Checker

A production-grade, single-file asynchronous Python proxy checker supporting **HTTP**, **HTTPS**, **SOCKS4**, **SOCKS4a**, **SOCKS5**, and **SOCKS5h** proxies using only the Python standard library.

---

## Features

- **Multi-Protocol Support**: Validates `http://`, `https://`, `socks4://`, `socks4a://`, `socks5://`, and `socks5h://` proxies, including nested TLS-over-TLS tunneling (`https://` proxy to `https://` targets).
- **Zero External Dependencies**: Built entirely on Python's standard library (`asyncio`, `ssl`, `ipaddress`, `zlib`, `json`, `csv`).
- **True Connectivity Verification**: Validates HTTP status codes and response content (JSON keys / expected substrings) rather than blindly accepting any HTTP `200` from captive portals or proxy error pages.
- **Bounded Async Concurrency**: Streams large input files lazily through a bounded worker queue with configurable concurrency limits (`1`–`2000`) and strict per-stage and total wall-clock timeouts.
- **Anonymity Assessment**: Optional `--check-anonymity` mode classifies working proxies as `elite`, `anonymous`, `transparent`, or `unknown`.
- **Security Hardened**:
  - Strict TLS 1.2+ certificate and hostname verification (`CERT_REQUIRED`) enabled at all times.
  - Credentials automatically masked in terminal output, error messages, and JSON/CSV reports by default.
  - `Proxy-Authorization` headers are never forwarded inside `CONNECT` TLS tunnels to target servers.
  - Bounded header, body, and gzip/deflate decompression caps prevent memory exhaustion.
  - CSV formula-injection neutralization and SSRF-safe redirect validation.
- **Atomic Exports & Graceful Shutdown**: Writes working proxies, failed diagnostics, JSON, and CSV reports atomically, and handles `Ctrl+C` (`SIGINT`/`SIGTERM`) cleanly while saving partial results.

---

## Requirements

- **Python 3.8 or higher** (tested on Python 3.10.12)
- No third-party packages required.

---

## Quick Start

1. Create an `unchecked.txt` file with one proxy per line:

```text
# HTTP / HTTPS proxies
127.0.0.1:8080
http://192.168.1.10:3128
https://user:pass@proxy.example.com:8443

# SOCKS proxies
socks4://203.0.113.10:1080
socks4a://203.0.113.11:1080
socks5://203.0.113.12:1080
socks5h://user:pass@203.0.113.13:1080

# Provider host:port:user:pass format and IPv6
198.51.100.5:8000:myuser:mypass
[::1]:8080
```

2. Run with default settings (`unchecked.txt` -> `checked.txt`):

```bash
python3 proxy_checker.py
```

3. Check `checked.txt` for verified working proxies.

---

## Usage Examples

```bash
# Require working HTTPS tunneling and check proxy anonymity
python3 proxy_checker.py -i proxies.txt -o working.txt --require-https --check-anonymity

# Filter only SOCKS5/SOCKS5h proxies and export JSON + CSV reports
python3 proxy_checker.py -i proxies.txt -p socks5,socks5h --json-output report.json --csv-output report.csv

# Check bare host:port lines as SOCKS5 proxies with custom concurrency and timeouts
python3 proxy_checker.py -i socks_list.txt --default-protocol socks5 -c 200 --connect-timeout 3 --total-timeout 10

# Test against a custom endpoint with expected text and verbose failure reasons
python3 proxy_checker.py -i proxies.txt -u https://example.com --expect-text "Example Domain" -v
```

---

## CLI Options

| Flag | Default | Description |
| --- | --- | --- |
| `-i`, `--input` | `unchecked.txt` | Input file containing proxies (one per line) |
| `-o`, `--output` | `checked.txt` | Output file for verified working proxies |
| `--failed-output` | `None` | Optional file for dead/invalid proxies with error categories |
| `--json-output` | `None` | Export structured summary and per-proxy results as JSON |
| `--csv-output` | `None` | Export structured per-proxy results as CSV |
| `-p`, `--protocol` | `all` | Comma-separated protocol filter (`http,https,socks4,socks4a,socks5,socks5h,all`) |
| `--default-protocol` | `http` | Protocol assumed for bare `host:port` lines without a scheme |
| `-c`, `--concurrency` | `100` | Maximum concurrent worker tasks (`1`–`2000`) |
| `--connect-timeout` | `5.0` | Proxy TCP/TLS connection timeout (seconds) |
| `-t`, `--timeout`, `--read-timeout` | `10.0` | Socket read and handshake timeout (seconds) |
| `--total-timeout` | `15.0` | Total wall-clock timeout per target request (seconds) |
| `-u`, `--url` | Built-in targets | Custom test URL (repeatable; overrides defaults) |
| `--expect-text` | `None` | Required substring when using custom `--url` |
| `--expect-json-key` | `None` | Required top-level JSON key when using custom `--url` |
| `--require-https` | `False` | Only test HTTPS targets to strictly verify TLS tunneling |
| `--follow-redirects` | `False` | Follow safe HTTP redirects (disabled by default to detect captive portals) |
| `--check-anonymity` | `False` | Assess anonymity (`elite`, `anonymous`, `transparent`) |
| `--anonymity-url` | `http://httpbin.org/get` | JSON echo endpoint used for anonymity assessment |
| `--user-agent` | `ProxyChecker/2.0.0` | Custom `User-Agent` request header |
| `--no-dedup` | `False` | Disable duplicate proxy removal |
| `--no-overwrite` | `False` | Abort instead of overwriting existing output files |
| `--output-with-scheme` | `False` | Always include `scheme://` prefix in working output file |
| `--include-credentials` | `False` | Include proxy credentials in JSON/CSV exports (masked by default) |
| `-v`, `--verbose` | `False` | Print detailed error categories and invalid line diagnostics |
| `-q`, `--quiet` | `False` | Suppress per-proxy progress lines; print only summary and errors |
| `-V`, `--version` | — | Print version and exit |

### Default Test Targets

When `-u/--url` is not specified, proxies are tested in order and stop after the first verified response:
1. `https://httpbin.org/ip` (verifies HTTP `200` and JSON `"origin"` key)
2. `https://example.com` (verifies HTTP `200` and `"Example Domain"`)
3. `http://httpbin.org/ip` (skipped if `--require-https` is set)
4. `http://example.com` (skipped if `--require-https` is set)

If a proxy fails due to a proxy-level fatal error (connection refused, connect timeout, DNS error, proxy TLS error, or authentication failure), remaining targets for that proxy are skipped immediately.

---

## Ethical Use Notice

Only test proxies you own or are authorized to evaluate, and configure concurrency and timeouts responsibly to avoid overloading target endpoints.

---

## License

This project is released under the MIT License.
