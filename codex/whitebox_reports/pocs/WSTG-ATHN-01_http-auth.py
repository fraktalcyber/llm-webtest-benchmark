"""
WSTG-ATHN-01 / WSTG-CRYP-01: Authentication is exposed over plain HTTP.
Expected: the login endpoint is reachable over http:// and returns a token.
"""
import requests

BASE = "http://localhost:3000"

r = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testfreelancer@hireflow.com",
    "password": "password123",
}, timeout=10)

print("Status:", r.status_code)
print("Body:", r.text[:160])
assert r.status_code == 200
assert "token" in r.json()
print("\n[VULNERABLE] Credentials are accepted over plaintext HTTP")
