# Security

This project gives whoever controls the dashboard or an MCP token **shell access to your servers**. Treat it accordingly.

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub: **Security → Report a vulnerability** on this repository
(https://github.com/mbeigi88/ssh-mcp-server/security/advisories/new). Do not open a public issue. You should get an answer within a few days.

## Operating it safely

* Use long, unique values for `ENCRYPTION_KEY` and `SESSION_SECRET` (32+ characters) and keep a private copy of `ENCRYPTION_KEY` —
  losing it means the stored SSH credentials cannot be decrypted.
* Complete first-run setup right after deploying; until then anyone who knows your `SETUP_TOKEN` could create the admin password.
* Prefer a non-root SSH user and the **read-only** policy for agents you do not fully trust; keep auto-approve `off` unless you accept the risk.
* Revoke MCP tokens you no longer use (Dashboard → MCP). Consider Cloudflare Access in front of the dashboard (`AUTH_MODE=both`).
* Never set `DEV_ALLOW_PRIVATE_TARGETS` or `DEV_INSECURE_COOKIES` on a deployed Worker.
* `test/fixtures/keys/` contains throw-away keys used only by the local test sshd; they grant access to nothing.

See the "Security summary" section of the README for the built-in protections.
