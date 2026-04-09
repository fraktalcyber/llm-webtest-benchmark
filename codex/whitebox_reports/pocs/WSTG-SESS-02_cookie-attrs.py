"""
WSTG-SESS-02: Missing Secure and SameSite on session cookie.
Expected: login sets connect.sid with HttpOnly only.
"""
import requests

r = requests.post("http://localhost:3000/api/auth/login", json={
    "email": "testfreelancer@hireflow.com",
    "password": "password123",
}, timeout=10)
cookie = r.headers.get("Set-Cookie", "")
print(cookie)
assert "connect.sid=" in cookie
assert "HttpOnly" in cookie
assert "Secure" not in cookie
assert "SameSite" not in cookie
print("\n[VULNERABLE] Session cookie lacks Secure and SameSite")
