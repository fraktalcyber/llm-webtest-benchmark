"""
WSTG-ATHN-07: Weak password policy.
Expected: registration succeeds with password 'aaaaaaaa'.
"""
import time
import requests

stamp = str(int(time.time()))
r = requests.post("http://localhost:3000/api/auth/register", json={
    "email": f"wstg_weak_{stamp}@example.com",
    "username": f"wstgweak{stamp}",
    "password": "aaaaaaaa",
    "display_name": "Weak Password",
}, timeout=10)

print("Status:", r.status_code)
print(r.text)
assert r.status_code == 201
print("\n[VULNERABLE] Weak dictionary password accepted")
