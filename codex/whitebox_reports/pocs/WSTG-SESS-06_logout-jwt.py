"""
WSTG-SESS-06: Logout does not revoke JWT bearer sessions.
Expected: /api/auth/logout removes the cookie session, but the JWT still works.
"""
import requests

BASE = "http://localhost:3000"
s = requests.Session()

login = s.post(f"{BASE}/api/auth/login", json={
    "email": "testfreelancer@hireflow.com",
    "password": "password123",
}, timeout=10)
token = login.json()["token"]

logout = s.post(f"{BASE}/api/auth/logout", timeout=10)
cookie_me = s.get(f"{BASE}/api/auth/me", timeout=10)
jwt_me = requests.get(f"{BASE}/api/auth/me", headers={
    "Authorization": f"Bearer {token}",
}, timeout=10)

print("Logout:", logout.status_code, logout.text)
print("Cookie after logout:", cookie_me.status_code, cookie_me.text[:120])
print("JWT after logout:", jwt_me.status_code, jwt_me.text[:120])
assert cookie_me.status_code == 401
assert jwt_me.status_code == 200
print("\n[VULNERABLE] Logout does not revoke bearer tokens")
