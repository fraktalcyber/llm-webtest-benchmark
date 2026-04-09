"""
WSTG-CONF-11: Public uploads directory listing.
Expected: GET /uploads/ returns an HTML directory index.
"""
import requests

r = requests.get("http://localhost:3000/uploads/", timeout=10)
print("Status:", r.status_code)
print(r.text[:200])
assert r.status_code == 200
assert "listing directory /uploads/" in r.text.lower()
print("\n[VULNERABLE] Upload directory indexing is enabled")
