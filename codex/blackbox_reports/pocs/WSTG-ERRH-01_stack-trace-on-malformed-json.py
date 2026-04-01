"""
WSTG-ERRH-01 / WSTG-ERRH-02: Malformed JSON exposes a stack trace.

Sends invalid JSON to the login endpoint and confirms that the response contains
parser details and stack-trace content.

Expected:
- HTTP 400 response
- Error body contains parser text and a stack trace/module path
"""

from __future__ import annotations

import requests


BASE = "http://localhost:3000"


def main() -> None:
    resp = requests.post(
        f"{BASE}/api/auth/login",
        headers={"Content-Type": "application/json"},
        data='{"email":"a"',
        timeout=10,
    )

    print(f"[+] Status: {resp.status_code}")
    print(f"[+] Body: {resp.text}")

    assert resp.status_code == 400, "Expected 400 for malformed JSON"
    assert "body-parser" in resp.text or "/app/node_modules" in resp.text, "Expected stack/module disclosure"

    print("\n[VULNERABLE] Error response exposes parser stack details")


if __name__ == "__main__":
    main()
