"""
WSTG-IDNT-03: Registration returns a working JWT before email verification.
Expected: register response has email_verified false and returned token can call /api/auth/me.
"""
import time
import requests

base = "http://localhost:3000"
stamp = str(int(time.time()))
email = f"wstg_unverified_{stamp}@example.com"
username = f"wstg_unverified_{stamp}"

r = requests.post(f"{base}/api/auth/register", json={
    "email": email,
    "username": username,
    "password": "StrongPass1234",
    "display_name": "WSTG Unverified",
}, timeout=10)
data = r.json()
print("Register:", r.status_code, data)
assert r.status_code == 201
assert data["user"]["email_verified"] is False
token = data["token"]

me = requests.get(f"{base}/api/auth/me", headers={"Authorization": f"Bearer {token}"}, timeout=10)
print("Me:", me.status_code, me.json())
assert me.status_code == 200
print("\n[VULNERABLE] Unverified accounts receive a valid authenticated token")
