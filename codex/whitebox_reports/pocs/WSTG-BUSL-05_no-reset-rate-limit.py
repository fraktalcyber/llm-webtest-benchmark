"""
WSTG-BUSL-05 / WSTG-BUSL-07: Password reset requests are effectively unlimited.
Expected: repeated POST /api/auth/forgot-password calls keep returning 200, not 429.
"""
import requests

BASE = "http://localhost:3000"

codes = []
for _ in range(25):
    r = requests.post(f"{BASE}/api/auth/forgot-password", json={
        "email": "testclient@hireflow.com",
    }, timeout=10)
    codes.append(r.status_code)

print("Codes:", codes)
assert set(codes) == {200}
print("\n[VULNERABLE] Forgot-password is not rate limited in practice")
