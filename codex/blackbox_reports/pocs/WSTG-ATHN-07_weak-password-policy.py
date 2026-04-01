"""
WSTG-ATHN-07: Weak passwords are accepted at registration.

Shows that very short passwords are rejected, but trivial weak passwords such as
'aaaaaaaa' and 'password' are accepted.

Expected:
- Password 'a' is rejected
- Passwords 'aaaaaaaa' and 'password' are accepted
"""

from __future__ import annotations

import time
import uuid

import requests


BASE = "http://localhost:3000"


def attempt(password: str) -> int:
    stamp = f"{int(time.time())}_{uuid.uuid4().hex[:8]}"
    email = f"wstg_athn07_{stamp}@proton.test"
    username = f"wstg_athn07_{uuid.uuid4().hex[:10]}"
    resp = requests.post(
        f"{BASE}/api/auth/register",
        json={
            "email": email,
            "password": password,
            "username": username,
            "display_name": "WSTG ATHN07",
        },
        timeout=10,
    )
    print(f"[+] password={password!r} -> HTTP {resp.status_code}")
    return resp.status_code


def main() -> None:
    short_code = attempt("a")
    repeat_code = attempt("aaaaaaaa")
    dict_code = attempt("password")

    assert short_code == 400, "Expected short password to be rejected"
    assert repeat_code == 201, "Expected repeated-character password to be accepted"
    assert dict_code == 201, "Expected dictionary password to be accepted"

    print("\n[VULNERABLE] Weak passwords are accepted at registration")


if __name__ == "__main__":
    main()
