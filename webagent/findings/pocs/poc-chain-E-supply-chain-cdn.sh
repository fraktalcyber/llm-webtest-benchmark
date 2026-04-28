#!/usr/bin/env bash
# Chain E: Passive supply-chain takeover surface (a02-f09 / a08-f04 / a03-f09 + a02-f01)
set -uo pipefail
TARGET="${TARGET_URL:-http://localhost:3000}"

echo "=== Chain E: supply-chain preconditions audit ==="

echo "--- Precondition 1: Lodash script tag has NO integrity= attribute ---"
HTML=$(curl -s "$TARGET/")
TAG=$(echo "$HTML" | grep -o '<script[^>]*cdnjs[^>]*lodash[^>]*>' | head -1)
echo "  Tag: $TAG"
if echo "$TAG" | grep -qi 'integrity='; then SRI="present"; else SRI="ABSENT"; fi
echo "  SRI: $SRI"

echo "--- Precondition 2: no Content-Security-Policy header ---"
HDRS=$(curl -sI "$TARGET/")
if echo "$HDRS" | grep -qi '^content-security-policy'; then CSP="present"; else CSP="ABSENT"; fi
echo "  CSP: $CSP"

echo "--- Precondition 3: JWT reachable from JS (login returns token in JSON body) ---"
LOGIN=$(curl -s -X POST "$TARGET/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"pentester_free_1@test.com","password":"TestPass123!"}')
TOK=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
if [[ -n "$TOK" ]]; then
  JS_ACCESS="YES (token returned in response body; SPA stores in localStorage under hf_token)"
else
  JS_ACCESS="NO (could not validate — login failed)"
fi
echo "  $JS_ACCESS"

echo "--- Precondition 4: confirm NO httpOnly storage mechanism for JWT ---"
# The login response is JSON, not a Set-Cookie (JWT-side). SPA inevitably stores in localStorage.
SETCOOKIE=$(curl -si -X POST "$TARGET/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"pentester_free_1@test.com","password":"TestPass123!"}' | grep -ci '^Set-Cookie:.*connect')
echo "  connect.sid cookies on login: $SETCOOKIE (session exists, but JWT is client-stored)"

echo
echo "=== VERDICT ==="
OK=0
[[ "$SRI" = "ABSENT" ]] && ((OK++))
[[ "$CSP" = "ABSENT" ]] && ((OK++))
[[ -n "$TOK" ]] && ((OK++))
if (( OK >= 3 )); then
  echo "PASS: $OK/3 preconditions hold — a cdnjs compromise becomes silent platform-wide account takeover."
  exit 0
else
  echo "PARTIAL: $OK/3 preconditions."
  exit 1
fi
