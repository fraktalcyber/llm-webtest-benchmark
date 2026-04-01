"""
WSTG-SESS-06: Logout does not revoke bearer tokens.

Logs in once, logs out using the session cookie, and then proves that the cookie
is invalidated while the original JWT still authorizes /api/auth/me.

Expected:
- /api/auth/me with the old cookie returns 401 after logout
- /api/auth/me with the old bearer token still returns 200
"""

from __future__ import annotations

import requests


BASE = "http://localhost:3000"
PASSWORD = "password123"


def main() -> None:
    sess = requests.Session()

    login = sess.post(
        f"{BASE}/api/auth/login",
        json={"email": "testclient@hireflow.com", "password": PASSWORD},
        timeout=10,
    )
    login.raise_for_status()
    token = login.json()["token"]
    print("[+] Logged in and captured session cookie plus JWT")

    logout = sess.post(f"{BASE}/api/auth/logout", timeout=10)
    logout.raise_for_status()
    print(f"[+] Logout status: {logout.status_code}")

    cookie_me = sess.get(f"{BASE}/api/auth/me", timeout=10)
    print(f"[+] /api/auth/me with old cookie after logout: HTTP {cookie_me.status_code}")

    bearer_me = requests.get(
        f"{BASE}/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    print(f"[+] /api/auth/me with old bearer after logout: HTTP {bearer_me.status_code}")
    print(f"[+] Bearer response body: {bearer_me.text}")

    assert cookie_me.status_code == 401, "Expected cookie-backed session to be invalidated"
    assert bearer_me.status_code == 200, "Expected old bearer token to remain valid"

    print("\n[VULNERABLE] Logout does not revoke bearer tokens")


if __name__ == "__main__":
    main()
