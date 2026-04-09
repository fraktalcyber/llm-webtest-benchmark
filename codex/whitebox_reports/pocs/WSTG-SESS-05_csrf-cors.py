"""
WSTG-SESS-05 / WSTG-CONF-08: CSRF enabled by reflected CORS + credentialed sessions.
Expected: arbitrary Origin is reflected and a cookie-authenticated profile update succeeds.
"""
import requests

base = "http://localhost:3000"
s = requests.Session()
login = s.post(f"{base}/api/auth/login", json={
    "email": "testfreelancer@hireflow.com",
    "password": "password123",
}, timeout=10)
user = login.json()["user"]

probe = requests.get(f"{base}/api/health", headers={"Origin": "https://evil.example.com"}, timeout=10)
print("CORS:", probe.headers.get("Access-Control-Allow-Origin"), probe.headers.get("Access-Control-Allow-Credentials"))
assert probe.headers.get("Access-Control-Allow-Origin") == "https://evil.example.com"
assert probe.headers.get("Access-Control-Allow-Credentials") == "true"

csrf = s.put(f"{base}/api/users/{user['id']}", json={
    "display_name": user["display_name"]
}, headers={"Origin": "https://evil.example.com"}, timeout=10)
print("CSRF update:", csrf.status_code, csrf.text[:160])
assert csrf.status_code == 200
print("\n[VULNERABLE] Cross-site credentialed request was accepted")
