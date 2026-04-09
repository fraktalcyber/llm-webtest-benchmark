"""
WSTG-CLNT-10: Socket.IO polling endpoint is reachable without authentication.
Expected: unauthenticated polling handshakes return 200 and a Socket.IO sid.
"""
import requests

BASE = "http://localhost:3000"

for url in (
    f"{BASE}/socket.io/?EIO=4&transport=polling&userId=attacker123",
    f"{BASE}/socket.io/?EIO=4&transport=polling",
):
    r = requests.get(url, timeout=10)
    print(url, r.status_code, r.headers.get("Access-Control-Allow-Origin"), r.text[:100])
    assert r.status_code == 200
    assert '"sid"' in r.text

print("\n[VULNERABLE] Socket.IO handshakes succeed without authentication")
