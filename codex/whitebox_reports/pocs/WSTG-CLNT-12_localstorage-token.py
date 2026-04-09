"""
WSTG-CLNT-12: The frontend stores JWTs in localStorage.
Expected: login returns a bearer token that the SPA persists client-side.
"""
import requests

BASE = "http://localhost:3000"

r = requests.post(f"{BASE}/api/auth/login", json={
    "email": "testfreelancer@hireflow.com",
    "password": "password123",
}, timeout=10)

token = r.json()["token"]
print("Status:", r.status_code)
print("Token prefix:", token[:40])
assert r.status_code == 200
assert token
print("\n[VULNERABLE] The SPA receives a reusable JWT that client code stores in localStorage")
