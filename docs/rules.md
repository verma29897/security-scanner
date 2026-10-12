# Security rules

| Rule | Category | What it reports | Important limitation |
|---|---|---|---|
| CA-SECRET-001 v1.1.0 | secrets | credential-like assignment with a quoted value | live status cannot be established statically; test/fixture and placeholder contexts are retained as informational, low-confidence findings |
| CA-GO-TLS-001 v1.0.0 | cryptography | `InsecureSkipVerify: true` | surrounding test-only context needs review |
| CA-GO-CMD-001 v1.0.0 | command injection | shell `-c` execution | does not prove input is attacker-controlled |
| CA-WEB-XSS-001 v1.0.0 | XSS | common explicit HTML-escaping bypasses | trusted/static content can be safe |
| CA-DEBUG-001 v1.0.0 | configuration | common enabled debug setting | environment and deployment overrides are unresolved |

Severity describes potential impact; confidence describes evidence strength. All current matches use `partial_or_weak` because exploitability and effective compensating controls require semantic or manual analysis.
