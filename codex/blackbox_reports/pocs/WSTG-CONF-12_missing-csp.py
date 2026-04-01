"""
WSTG-CONF-12: No Content Security Policy.

Verifies that the SPA entrypoint does not return a Content-Security-Policy
header.

Expected:
- GET / returns 200
- No Content-Security-Policy header is present
"""

from __future__ import annotations

import requests


BASE = "http://localhost:3000"


def main() -> None:
    resp = requests.get(f"{BASE}/", timeout=10)
    resp.raise_for_status()

    csp = resp.headers.get("Content-Security-Policy")
    print(f"[+] Status: {resp.status_code}")
    print(f"[+] Content-Security-Policy: {csp}")

    assert csp is None, "Expected no CSP header"
    print("\n[VULNERABLE] No Content Security Policy header present")


if __name__ == "__main__":
    main()
