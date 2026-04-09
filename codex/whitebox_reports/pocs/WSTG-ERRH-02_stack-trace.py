"""
WSTG-ERRH-02: Stack trace disclosure on 500 errors.
Expected: malformed contract creation returns JSON with a stack field.
"""
import time
import requests

BASE = "http://localhost:3000"
stamp = str(int(time.time()))
reg = requests.post(f"{BASE}/api/auth/register", json={
    "email": f"wstg_stack_{stamp}@example.com",
    "username": f"wstgstack{stamp}",
    "password": "StrongPass1234",
    "display_name": "WSTG Stack",
}, timeout=10).json()
token = reg["token"]

r = requests.post(f"{BASE}/api/contracts", json={
    "freelancer_id": "3fcfb3b4-8335-4b13-b813-3d425c3ecf7e",
    "title": "Broken contract request",
    "description": "Missing amount to trigger DB constraint"
}, headers={"Authorization": f"Bearer {token}"}, timeout=10)
data = r.json()
print("Status:", r.status_code)
print(data)
assert r.status_code == 500
assert "stack" in data
print("\n[VULNERABLE] Stack trace disclosed in API response")
