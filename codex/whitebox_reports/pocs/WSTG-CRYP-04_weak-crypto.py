"""
WSTG-CRYP-04: Weak bcrypt cost and predictable reset token format.
Expected: source shows SALT_ROUNDS = 4 and MailHog exposes a timestamp-hash reset token.
"""
import pathlib
import re
import requests

service = pathlib.Path("src/auth/auth.service.js").read_text()
assert "const SALT_ROUNDS = 4;" in service
print("Confirmed weak bcrypt cost factor 4 in source")

requests.post("http://localhost:3000/api/auth/forgot-password", json={
    "email": "testfreelancer@hireflow.com"
}, timeout=10)
messages = requests.get("http://localhost:8025/api/v2/messages?limit=20", timeout=10).json()["items"]
body = next(item["Content"]["Body"] for item in messages
            if item["Content"]["Headers"]["To"][0] == "testfreelancer@hireflow.com"
            and item["Content"]["Headers"]["Subject"][0] == "HireFlow - Password Reset")
match = re.search(r"token=3D([a-z0-9\-]+)", body)
assert match, "Reset token not found"
token = match.group(1)
print("Reset token:", token)
assert re.fullmatch(r"[a-z0-9]+-[a-f0-9]{16}", token)
print("\n[VULNERABLE] Weak crypto design confirmed")
