"""
WSTG-ATHN-03: No Account Lockout or Rate Limiting
Demonstrates that the login endpoint has no brute force protection —
unlimited failed login attempts are allowed without lockout or rate limiting.
Expected: All 30 attempts return 401 with no lockout, then correct password works.
"""
import requests
import time

BASE = "http://localhost:3000"
TARGET_EMAIL = "testclient@hireflow.com"
WRONG_PASSWORD = "wrongpassword"
CORRECT_PASSWORD = "password123"
ATTEMPTS = 30

print(f"[+] Testing brute force protection on {TARGET_EMAIL}")
print(f"[+] Sending {ATTEMPTS} failed login attempts...")

start = time.time()
statuses = []
for i in range(1, ATTEMPTS + 1):
    resp = requests.post(f"{BASE}/api/auth/login", json={
        "email": TARGET_EMAIL,
        "password": WRONG_PASSWORD
    })
    statuses.append(resp.status_code)
    if resp.status_code != 401:
        print(f"    Attempt {i}: {resp.status_code} (unexpected!)")

elapsed = time.time() - start
print(f"[+] {ATTEMPTS} attempts completed in {elapsed:.1f}s")
print(f"    All returned 401: {all(s == 401 for s in statuses)}")

# Check for rate limiting indicators
unique_statuses = set(statuses)
print(f"    Unique status codes: {unique_statuses}")

# Verify account is not locked
print(f"\n[+] Attempting login with correct password...")
resp = requests.post(f"{BASE}/api/auth/login", json={
    "email": TARGET_EMAIL,
    "password": CORRECT_PASSWORD
})
print(f"    Status: {resp.status_code}")

if resp.status_code == 200:
    print(f"    User: {resp.json()['user']['email']}")
    print(f"\n[VULNERABLE] No brute force protection!")
    print(f"    - {ATTEMPTS} failed attempts: no lockout")
    print(f"    - No rate limiting (all attempts succeeded immediately)")
    print(f"    - Account still accessible with correct password")
    print(f"    - Enables offline/online password brute forcing")
else:
    print(f"\n[NOT VULNERABLE] Account appears to be locked or rate limited")
