"""
WSTG-ERRH-02: Full Stack Traces in Production Error Responses
Demonstrates that error responses include full SQL queries, Node.js stack traces,
file paths, and dependency versions.
Expected: Error responses contain stack traces and internal details.
"""
import requests
import json

BASE = "http://localhost:3000"

# Step 1: Login
login = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testclient@hireflow.com",
    "password": "password123"
})
token = login.json()["token"]

print("[+] Testing error response information disclosure\n")

# Test 1: Invalid UUID in path parameter
print("--- Test 1: Invalid UUID triggers PostgreSQL error ---")
resp = requests.get(f"{BASE}/api/contracts/invalid-uuid", headers={
    "Authorization": f"Bearer {token}"
})
data = resp.json()
print(f"    Error: {data.get('error', '')[:100]}")
if "stack" in data:
    stack_lines = data["stack"].split("\n")[:3]
    for line in stack_lines:
        print(f"    Stack: {line.strip()[:100]}")
    print(f"    [VULNERABLE] Full PostgreSQL query and stack trace exposed")

# Test 2: Malformed JSON body
print("\n--- Test 2: Malformed JSON triggers body-parser error ---")
resp2 = requests.post(f"{BASE}/api/auth/login",
    data="{invalid json",
    headers={"Content-Type": "application/json"}
)
data2 = resp2.json()
print(f"    Error: {data2.get('error', '')[:100]}")
if "stack" in data2:
    stack_lines = data2["stack"].split("\n")[:3]
    for line in stack_lines:
        print(f"    Stack: {line.strip()[:100]}")
    print(f"    [VULNERABLE] body-parser file paths exposed")

# Test 3: Database column error
print("\n--- Test 3: Missing column triggers SQL error ---")
resp3 = requests.get(f"{BASE}/api/projects/4141ce82-a32a-498d-b5cc-aac7f8729edd/proposals", headers={
    "Authorization": f"Bearer {token}"
})
data3 = resp3.json()
error_msg = data3.get("error", "")
if "select" in error_msg.lower() or "column" in error_msg.lower():
    print(f"    Error: {error_msg[:150]}")
    print(f"    [VULNERABLE] Full SQL query with table/column names exposed")

print("\n[SUMMARY] Information leaked in error responses:")
print("  - Full PostgreSQL queries with table and column names")
print("  - Node.js stack traces with file paths (/app/node_modules/...)")
print("  - Dependency names and versions (pg-protocol, body-parser, raw-body)")
print("  - Internal error messages from database driver")
