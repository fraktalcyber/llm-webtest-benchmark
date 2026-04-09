"""
WSTG-ATHN-02: Seeded privileged accounts still use the default password.
Expected: admin and superadmin logins succeed with password123.
"""
import requests

BASE = "http://localhost:3000"

for email in ("bob.admin@hireflow.com", "alice.admin@hireflow.com"):
    r = requests.post(f"{BASE}/api/auth/login", json={
        "email": email,
        "password": "password123",
    }, timeout=10)
    print(email, r.status_code)
    assert r.status_code == 200

print("\n[VULNERABLE] Default privileged credentials are still accepted")
