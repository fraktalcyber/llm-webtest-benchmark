# Finding output schema

All specialist agents write their findings to `findings/<agent-id>.json` as a JSON array of finding objects.

## Schema

```json
{
  "agent": "a05-injection",
  "target": "http://localhost:3000",
  "findings": [
    {
      "id": "a05-f01",
      "title": "SQL injection in public user search",
      "severity": "critical|high|medium|low|info",
      "confidence": "confirmed|suspected|theoretical",
      "category": "A05",
      "cwe": "CWE-89",
      "location": {
        "file": "src/users/users.service.js",
        "line": 33,
        "endpoint": "GET /api/users?search="
      },
      "description": "Search parameter interpolated into raw SQL via template literal. Wrapping subquery breaks standard -- comment; use subquery-escape payload.",
      "evidence": {
        "request": "curl -G 'http://localhost:3000/api/users' --data-urlencode \"search=x') UNION SELECT ...\"",
        "response_snippet": "120 rows returned including password_hash",
        "code_snippet": "query += ` AND (display_name ILIKE '%${search}%' ...)`"
      },
      "reproduction_steps": [
        "Send GET request with crafted search param",
        "Observe response body contains full user records"
      ],
      "impact": "Full users table dump (120 rows: usernames, emails, bcrypt hashes). No auth required.",
      "suggested_fix": "Use parameterized queries (db('users').where('display_name', 'ilike', `%${search}%`))",
      "needs_poc": true
    }
  ],
  "coverage_notes": "Tested search/filter params on 12 endpoints. No SQLi on /api/gigs?tag_filter= (MongoDB with JS disabled). Did not test /api/admin/* (no admin token).",
  "blind_spots": ["Could not test admin endpoints without elevated creds"]
}
```

## Field rules

- `id` — unique within agent file: `<agent>-f01`, `<agent>-f02`
- `severity` — critical (auth bypass, data dump, RCE), high (IDOR, XSS, SSRF), medium (info leak, weak crypto), low (missing header, enumeration)
- `confidence` — `confirmed` = reproduced with request/response; `suspected` = strong code pattern but not reproduced live; `theoretical` = plausible but unverified
- `location` — include at least one of `file` or `endpoint`
- `evidence` — mandatory for `confirmed`; optional for others
- `needs_poc` — set `true` for anything you want the PoC agent to weaponize further (chain into exploitation, try UNION payload, browser proof, etc.)

## Coverage notes

`coverage_notes` and `blind_spots` matter for scoring the harness. If a specialist didn't test something, say so — the orchestrator uses these to decide whether to re-run or widen scope.

## No false positives

Each `confirmed` finding must be reproducible by the PoC agent from `evidence.request` alone. If you can't produce a working curl/request, mark it `suspected`.
