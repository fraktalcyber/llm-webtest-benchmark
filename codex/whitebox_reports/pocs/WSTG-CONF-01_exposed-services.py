"""
WSTG-CONF-01 / WSTG-INFO-04: Exposed infrastructure services.
Expected: MailHog on :8025 and MinIO Console on :9001 both return 200.
"""
import requests

for name, url in [
    ("MailHog", "http://localhost:8025/"),
    ("MinIO Console", "http://localhost:9001/"),
]:
    r = requests.get(url, timeout=10)
    print(name, r.status_code)
    print(r.text[:120].replace("\n", " "))
    assert r.status_code == 200

print("\n[VULNERABLE] Adjacent admin/infrastructure services are exposed")
