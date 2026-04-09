"""
WSTG-IDNT-04: Account enumeration via forgot-password.
Expected: existing and non-existing emails produce different status codes/messages.
"""
import time
import requests

base = "http://localhost:3000"
existing = requests.post(f"{base}/api/auth/forgot-password", json={
    "email": "testfreelancer@hireflow.com"
}, timeout=10)
missing = requests.post(f"{base}/api/auth/forgot-password", json={
    "email": f"nope_{int(time.time())}@example.com"
}, timeout=10)

print("Existing:", existing.status_code, existing.text)
print("Missing:", missing.status_code, missing.text)
assert existing.status_code == 200
assert missing.status_code == 404
print("\n[VULNERABLE] Forgot-password endpoint enumerates valid accounts")
