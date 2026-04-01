"""
WSTG-CONF-08: Wildcard Origin Reflection with Credentials
Demonstrates that the server reflects any Origin header in Access-Control-Allow-Origin
and sets Access-Control-Allow-Credentials: true, allowing cross-origin attacks.
Expected: Response includes reflected evil origin with credentials allowed.
"""
import requests

BASE = "http://localhost:3000"

# Step 1: Login to get a valid token
login = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testclient@hireflow.com",
    "password": "password123"
})
token = login.json()["token"]
print(f"[+] Logged in, got token")

# Step 2: Send request with evil Origin header
evil_origin = "https://evil.example.com"
resp = requests.get(
    f"{BASE}/api/auth/me",
    headers={
        "Authorization": f"Bearer {token}",
        "Origin": evil_origin
    }
)

acao = resp.headers.get("Access-Control-Allow-Origin", "")
acac = resp.headers.get("Access-Control-Allow-Credentials", "")

print(f"[+] Request with Origin: {evil_origin}")
print(f"    Access-Control-Allow-Origin: {acao}")
print(f"    Access-Control-Allow-Credentials: {acac}")

# Step 3: Test preflight
preflight = requests.options(
    f"{BASE}/api/auth/me",
    headers={
        "Origin": evil_origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization,Content-Type"
    }
)

methods = preflight.headers.get("Access-Control-Allow-Methods", "")
print(f"[+] Preflight allowed methods: {methods}")

# Verify vulnerability
assert acao == evil_origin, f"Expected reflected origin, got: {acao}"
assert acac.lower() == "true", f"Expected credentials allowed, got: {acac}"
print("\n[VULNERABLE] CORS reflects arbitrary origin with credentials=true")
print("Impact: Any malicious website can make authenticated API requests")
print("and read responses on behalf of logged-in users.")
