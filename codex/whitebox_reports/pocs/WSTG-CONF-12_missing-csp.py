"""
WSTG-CONF-12: Missing Content Security Policy.
Expected: Response lacks a Content-Security-Policy header.
"""
import requests

r = requests.get("http://localhost:3000/", timeout=10)
print("Status:", r.status_code)
print("CSP header:", r.headers.get("Content-Security-Policy"))
assert r.status_code == 200
assert "Content-Security-Policy" not in r.headers
print("\n[VULNERABLE] No CSP header is set")
