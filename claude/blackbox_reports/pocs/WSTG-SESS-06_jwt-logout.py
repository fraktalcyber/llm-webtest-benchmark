"""
WSTG-SESS-06: JWT Not Invalidated on Logout
Demonstrates that JWT tokens remain valid after the user logs out,
meaning stolen tokens cannot be revoked.
Expected: Token still works after logout.
"""
import requests

BASE = "http://localhost:3000"

# Step 1: Login and get a JWT token
login = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testclient@hireflow.com",
    "password": "password123"
})
token = login.json()["token"]
user = login.json()["user"]
print(f"[+] Logged in as: {user['email']}")
print(f"[+] Token: {token[:50]}...")

# Step 2: Verify the token works
me_resp = requests.get(f"{BASE}/api/auth/me", headers={
    "Authorization": f"Bearer {token}"
})
assert me_resp.status_code == 200, "Token should work before logout"
print(f"[+] Pre-logout: /api/auth/me returns {me_resp.status_code} — token valid")

# Step 3: Logout
logout_resp = requests.post(f"{BASE}/api/auth/logout", headers={
    "Authorization": f"Bearer {token}"
})
print(f"[+] Logout response: {logout_resp.json()}")

# Step 4: Try to use the same token after logout
me_after = requests.get(f"{BASE}/api/auth/me", headers={
    "Authorization": f"Bearer {token}"
})
print(f"[+] Post-logout: /api/auth/me returns {me_after.status_code}")

if me_after.status_code == 200:
    data = me_after.json()
    print(f"    User email: {data['user']['email']}")
    print(f"\n[VULNERABLE] JWT token still valid after logout!")
    print(f"    Impact: Stolen tokens remain usable even after user logs out.")
    print(f"    Combined with 7-day expiry, this is a significant attack window.")
else:
    print(f"\n[NOT VULNERABLE] Token was properly invalidated on logout")
