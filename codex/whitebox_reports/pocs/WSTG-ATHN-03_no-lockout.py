"""
WSTG-ATHN-03: No effective login lockout/rate limit.
Expected: 25 bad password attempts do not trigger 429 or account lockout.
"""
import requests

base = "http://localhost:3000/api/auth/login"
statuses = []
for i in range(25):
    r = requests.post(base, json={
        "email": "testfreelancer@hireflow.com",
        "password": "wrongpass"
    }, timeout=10)
    statuses.append(r.status_code)

print(statuses)
assert all(code == 401 for code in statuses)
print("\n[VULNERABLE] Repeated bad logins never triggered lockout or 429")
