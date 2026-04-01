"""
WSTG-ATHN-03: No account lockout after repeated failed logins.

Registers a disposable account, sends 25 failed login attempts, and then proves
that the correct password still works immediately afterward.

Expected:
- All failed attempts return 401
- The subsequent correct login still returns 200
"""

from __future__ import annotations

import time
import uuid

import requests


BASE = "http://localhost:3000"
PASSWORD = "password123"


def main() -> None:
    stamp = f"{int(time.time())}_{uuid.uuid4().hex[:8]}"
    email = f"wstg_athn03_{stamp}@proton.test"
    username = f"wstg_athn03_{uuid.uuid4().hex[:10]}"

    reg = requests.post(
        f"{BASE}/api/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "username": username,
            "display_name": "WSTG ATHN03",
        },
        timeout=10,
    )
    reg.raise_for_status()
    print(f"[+] Registered disposable account: {email}")

    for i in range(1, 26):
        bad = requests.post(
            f"{BASE}/api/auth/login",
            json={"email": email, "password": "wrongpassword"},
            timeout=10,
        )
        if i in (1, 5, 10, 20, 25):
            print(f"[+] Failed attempt {i}: HTTP {bad.status_code}")
        assert bad.status_code == 401, f"Expected 401 on failed attempt {i}"

    good = requests.post(
        f"{BASE}/api/auth/login",
        json={"email": email, "password": PASSWORD},
        timeout=10,
    )
    print(f"[+] Correct password after 25 failures: HTTP {good.status_code}")
    assert good.status_code == 200, "Expected successful login despite repeated failures"

    print("\n[VULNERABLE] No account lockout after repeated failed logins")


if __name__ == "__main__":
    main()
