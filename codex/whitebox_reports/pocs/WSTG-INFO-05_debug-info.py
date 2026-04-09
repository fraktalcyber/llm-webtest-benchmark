"""
WSTG-INFO-05: Unauthenticated debug information disclosure.
Expected: /api/debug/info returns runtime and internal service details.
"""
import requests

r = requests.get("http://localhost:3000/api/debug/info", timeout=10)
data = r.json()
print("Status:", r.status_code)
print(data)
assert r.status_code == 200
for key in ("environment", "db_host", "redis_host", "mongo_uri"):
    assert key in data
print("\n[VULNERABLE] Debug endpoint leaks internal architecture details")
