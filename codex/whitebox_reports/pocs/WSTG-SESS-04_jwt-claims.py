"""
WSTG-SESS-04 / WSTG-CRYP-03: Sensitive JWT claims disclosure.
Expected: decoded JWT contains email and walletBalance.
"""
import base64
import json
import requests

r = requests.post("http://localhost:3000/api/auth/login", json={
    "email": "testfreelancer@hireflow.com",
    "password": "password123",
}, timeout=10).json()
token = r["token"]
payload = token.split(".")[1]
payload += "=" * (-len(payload) % 4)
decoded = json.loads(base64.urlsafe_b64decode(payload))
print(json.dumps(decoded, indent=2))
assert "email" in decoded
assert "walletBalance" in decoded
print("\n[VULNERABLE] JWT embeds PII and wallet balance")
