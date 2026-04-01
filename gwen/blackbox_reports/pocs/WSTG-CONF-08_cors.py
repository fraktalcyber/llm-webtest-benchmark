#!/usr/bin/env python3
"""
WSTG-CONF-08: Overly Permissive CORS Configuration
Demonstrates that the application accepts cross-origin requests from any domain
with credentials, enabling cross-site attacks.
Expected: Access-Control-Allow-Origin reflects the malicious Origin header
"""

import requests

BASE = "http://localhost:3000"
EVIL_ORIGIN = "https://evil.attacker.com"


def main():
    print("[*] WSTG-CONF-08: Overly Permissive CORS PoC")
    print("=" * 50)

    # Step 1: Test CORS preflight with malicious origin
    print(f"[*] Testing CORS preflight with Origin: {EVIL_ORIGIN}")

    resp = requests.options(
        f"{BASE}/api/users",
        headers={
            "Origin": EVIL_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )

    print(f"\n[+] Status Code: {resp.status_code}")
    print(f"\n[+] CORS Headers:")
    print(
        f"    Access-Control-Allow-Origin: {resp.headers.get('Access-Control-Allow-Origin', 'NOT FOUND')}"
    )
    print(
        f"    Access-Control-Allow-Credentials: {resp.headers.get('Access-Control-Allow-Credentials', 'NOT FOUND')}"
    )
    print(
        f"    Access-Control-Allow-Methods: {resp.headers.get('Access-Control-Allow-Methods', 'NOT FOUND')}"
    )

    # Step 2: Check for vulnerability
    if resp.headers.get("Access-Control-Allow-Origin") == EVIL_ORIGIN:
        if resp.headers.get("Access-Control-Allow-Credentials") == "true":
            print("\n" + "=" * 50)
            print("[VULNERABLE] Overly Permissive CORS confirmed")
            print("=" * 50)
            print("\nVulnerability Details:")
            print("- Application reflects any Origin header")
            print("- Credentials (cookies, auth headers) allowed")
            print("- Attackers can make authenticated requests from malicious sites")
            print("- Enables CSRF-like attacks and token theft")
            return
        else:
            print("\n[!] CORS reflects Origin but credentials not allowed")
            print("    This is still a misconfiguration but lower risk")
            return
    else:
        print("\n[-] CORS properly configured - Origin not reflected")


if __name__ == "__main__":
    main()
