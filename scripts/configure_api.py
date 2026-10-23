#!/usr/bin/env python3
"""Connect a static CyberWatch deployment to its live collection service.

Usage: python scripts/configure_api.py https://your-cyberwatch-service.example/
       python scripts/configure_api.py --reset

This writes a public service URL, never an API key or credential. Allow the
dashboard's exact origin in CYBERWATCH_ALLOWED_ORIGINS on the live server.
"""
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, unquote
import argparse
import ipaddress
import json
import re

ROOT = Path(__file__).resolve().parents[1]


def validate_base(value):
    parsed = urlsplit(value)
    host = parsed.hostname
    if not host or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Use a service base URL without credentials, query parameters, or a fragment.")
    if re.search(r'[\s<>"\x00-\x1f]', value):
        raise ValueError("The service URL contains unsupported characters.")
    loopback = host.lower() == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise ValueError("Use an ASCII or punycode hostname.")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError("Use HTTPS; HTTP is allowed only for local loopback testing.")
    port = parsed.port  # Reject malformed or out-of-range ports.
    decoded_path = unquote(parsed.path)
    if "\\" in decoded_path or any(part in {".", ".."} for part in decoded_path.split("/")):
        raise ValueError("The service base must not contain relative path segments.")
    netloc = f"[{host}]" if ":" in host else host.lower()
    if port is not None:
        netloc += f":{port}"
    base = urlunsplit((parsed.scheme, netloc, parsed.path.rstrip("/") + "/", "", ""))
    origin = urlunsplit((parsed.scheme, netloc, "", "", ""))
    return base, origin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?")
    parser.add_argument("--reset", action="store_true", help="Use same-origin automatic discovery")
    args = parser.parse_args()
    if bool(args.url) == bool(args.reset):
        parser.error("Supply a service URL or --reset.")
    try:
        base, origin = ("auto", None) if args.reset else validate_base(args.url)
    except ValueError as error:
        parser.error(str(error))
    index = ROOT / "dist/index.html"
    html = index.read_text(encoding="utf-8")
    directive = "connect-src 'self'" + (f" {origin}" if origin else "")
    html, count = re.subn(r"connect-src[^;]+", directive, html, count=1)
    if count != 1:
        raise SystemExit("The dashboard CSP connect-src directive was not found; no files changed.")
    (ROOT / "dist/config.json").write_text(json.dumps({"apiBase": base}, indent=2) + "\n", encoding="utf-8")
    index.write_text(html, encoding="utf-8")
    print("Live service configuration updated. Commit dist/config.json and dist/index.html together.")
    if origin:
        print("Set CYBERWATCH_ALLOWED_ORIGINS on the server to the dashboard's exact origin (no path).")


if __name__ == "__main__":
    main()
