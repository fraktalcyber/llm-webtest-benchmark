"""
WSTG-CONF-03 / WSTG-CONF-09 / WSTG-BUSL-08 / WSTG-BUSL-09:
HTML deliverables are accepted and served from the application origin.
Expected: upload returns a .html path under /uploads/ and fetching it returns text/html.
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
    "title": f"WSTG upload {stamp}",
    "description": "upload test",
    "amount": 100,
    "milestones": [{"title": "Upload milestone", "amount": 100}],
}, timeout=10).json()

milestone_id = contract["milestones"][0]["id"]
contract_id = contract["id"]
requests.post(f"{BASE}/api/payments/escrow/fund/{milestone_id}", headers={
    "Authorization": f"Bearer {CLIENT_TOKEN}",
}, timeout=10).raise_for_status()

submit = requests.post(
    f"{BASE}/api/contracts/{contract_id}/milestones/{milestone_id}/submit",
    headers={"Authorization": f"Bearer {FREELANCER_TOKEN}"},
    files={"files": ("proof.html", io.BytesIO(b"<html><body>wstg html</body></html>"), "text/html")},
    data={"message": "html upload"},
    timeout=10,
)
submit.raise_for_status()
path = submit.json()["milestone"]["deliverables"][0]["files"][0]["path"]

fetch = requests.get(f"{BASE}{path}", timeout=10)
print("Path:", path)
print("Fetch:", fetch.status_code, fetch.headers.get("Content-Type"), fetch.text[:80])
assert fetch.status_code == 200
assert fetch.headers.get("Content-Type", "").startswith("text/html")
print("\n[VULNERABLE] HTML upload is reachable from the application origin")
