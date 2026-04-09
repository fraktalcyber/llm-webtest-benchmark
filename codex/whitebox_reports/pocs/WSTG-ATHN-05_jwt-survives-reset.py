"""
WSTG-ATHN-05 / WSTG-SESS-06: JWTs survive password resets.
Expected: a pre-reset bearer token still works after the password is changed.
"""
import quopri
import re
import time

import requests

BASE = "http://localhost:3000"
MAILHOG = "http://localhost:8025"

stamp = str(int(time.time()))
email = f"wstg_reset_{stamp}@example.com"
username = f"wstgreset{stamp}"

reg = requests.post(f"{BASE}/api/auth/register", json={
    "email": email,
    "username": username,
    "password": "password123",
    "role": "freelancer",
    "display_name": "WSTG Reset",
}, timeout=10)
token = reg.json()["token"]

requests.post(f"{BASE}/api/auth/forgot-password", json={"email": email}, headers={
    "Host": "evil.example.com",
}, timeout=10)

mail = requests.get(f"{MAILHOG}/api/v2/messages?limit=100", timeout=10).json()
reset_token = None
for item in mail["items"]:
    headers = item.get("Content", {}).get("Headers", {})
    if email in "".join(headers.get("To", [])):
        body = quopri.decodestring(item["Content"]["Body"]).decode(errors="ignore")
        match = re.search(r"token=([A-Za-z0-9\-]+)", body)
        if match:
            reset_token = match.group(1)
            break

assert reset_token, "reset token not found"

reset = requests.post(f"{BASE}/api/auth/reset-password", json={
    "token": reset_token,
    "password": "newpass123",
}, timeout=10)
print("Reset:", reset.status_code, reset.text)
assert reset.status_code == 200

old_token = requests.get(f"{BASE}/api/auth/me", headers={
    "Authorization": f"Bearer {token}",
}, timeout=10)
print("Old JWT:", old_token.status_code, old_token.text[:160])
assert old_token.status_code == 200

print("\n[VULNERABLE] Password reset does not invalidate existing JWTs")
