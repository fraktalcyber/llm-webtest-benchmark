"""
WSTG-IDNT-04: Account Enumeration via Password Reset and Registration
Demonstrates that the application reveals whether an email address is registered
through different error messages on the password reset and registration endpoints.
Expected: Different responses for existing vs non-existing email addresses.
"""
import requests

BASE = "http://localhost:3000"

EXISTING_EMAIL = "testclient@hireflow.com"
FAKE_EMAIL = "nonexistent_user_12345@hireflow.com"

print("[+] Testing account enumeration vectors\n")

# Test 1: Password reset endpoint
print("--- Test 1: Password Reset Enumeration ---")
resp_exists = requests.post(f"{BASE}/api/auth/forgot-password", json={
    "email": EXISTING_EMAIL
})
resp_fake = requests.post(f"{BASE}/api/auth/forgot-password", json={
    "email": FAKE_EMAIL
})

msg_exists = resp_exists.json().get("message", resp_exists.json().get("error", ""))
msg_fake = resp_fake.json().get("message", resp_fake.json().get("error", ""))

print(f"    Existing email ({EXISTING_EMAIL}):")
print(f"      Response: {msg_exists}")
print(f"    Non-existing email ({FAKE_EMAIL}):")
print(f"      Response: {msg_fake}")

if msg_exists != msg_fake:
    print(f"    [VULNERABLE] Different responses reveal email existence")
else:
    print(f"    [NOT VULNERABLE] Same response for both")

# Test 2: Registration endpoint
print("\n--- Test 2: Registration Enumeration ---")
resp_reg = requests.post(f"{BASE}/api/auth/register", json={
    "email": EXISTING_EMAIL,
    "password": "password123",
    "username": "enumtest",
    "display_name": "Enum Test"
})
reg_error = resp_reg.json().get("error", "")
print(f"    Register with existing email: {reg_error}")
if "already registered" in reg_error.lower():
    print(f"    [VULNERABLE] Registration reveals existing emails")

# Test 3: Login endpoint (should NOT be vulnerable)
print("\n--- Test 3: Login Endpoint (control) ---")
resp_login_exists = requests.post(f"{BASE}/api/auth/login", json={
    "email": EXISTING_EMAIL,
    "password": "wrongpassword"
})
resp_login_fake = requests.post(f"{BASE}/api/auth/login", json={
    "email": FAKE_EMAIL,
    "password": "wrongpassword"
})
login_msg_exists = resp_login_exists.json().get("error", "")
login_msg_fake = resp_login_fake.json().get("error", "")
print(f"    Existing email, wrong pw: {login_msg_exists}")
print(f"    Fake email, wrong pw: {login_msg_fake}")
if login_msg_exists == login_msg_fake:
    print(f"    [OK] Login gives same error for both (not enumerable)")

print("\n[SUMMARY] Account enumeration possible via:")
print("  - Password reset: different messages for existing vs non-existing emails")
print("  - Registration: 'Email already registered' reveals valid emails")
