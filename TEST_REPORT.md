# TEST_REPORT — cf-ssh-mcp

Run date: 2026-11-12. Environment: Debian 13 (arm64) sandbox, Node 22, wrangler 4.160.0, `@cloudflare/vitest-plugin` 1.7 (workerd),
vitest 4.1, **OpenSSH_10.0p2** (real `sshd` on 127.0.0.1:2222 via `test/sshd/start.sh`), Chromium for the browser E2E.
Raw outputs are written to `test-output/` (git-ignored, because live runs contain deployment URLs).

## Summary

| Suite | Runtime | Result |
|---|---|---|
| Typecheck (`tsc --noEmit`, strict) | — | ✅ clean |
| Unit (crypto incl. **v1 key compatibility + HKDF passphrase keys + fixed test vector**, config checks, setup rules, policy, quoting, SSRF, validation, Access JWT, redaction, auto-approve) | Node | ✅ **222 / 222** |
| Worker (auth, CSRF, sessions, rate limit, headers, CRUD & secrecy, SSRF, MCP protocol, auto-approve, **first-run setup: token required / wrong token / per-IP rate limit / CSRF + Origin / disabled after setup / locked if the hash disappears / race / secret-hash precedence / v1 legacy password / change password / weak-secret 503s / passphrase secrets end to end**) | workerd | ✅ **37 / 37** |
| Integration vs REAL OpenSSH (SSH client running inside workerd) | workerd → sshd | ✅ **33 / 33** |
| Browser E2E (`wrangler dev` ×2 + real sshd + Chromium; **setup page en + phone fa, wrong token, mismatch, create → signed in, reload, login afterwards**; settings explains secret-based password; all previous dashboard flows) | workerd + Chromium | ✅ **23 / 23** |
| `wrangler deploy --dry-run` | — | ✅ 2577.94 KiB / gzip 514.94 KiB (limit 64 MiB) |
| Clean clone (`git clone` → `npm ci` (postinstall patch-ssh2) → `npm run build` → `tsc` → unit → worker → `wrangler deploy --dry-run`) | — | ✅ |
| Fresh install over HTTPS (clean clone, `scripts/deploy.sh` with a throw-away Worker + new D1, passphrase secrets + SETUP_TOKEN) | Cloudflare edge | ✅ **16 / 16**, then Worker and D1 deleted |

**Total automated tests: 315 passed, 0 failed** (222 + 37 + 33 + 23).

## Fresh-install test (Cloudflare, 2026-11-12)

Throw-away Worker `ssh-mcp-installtest` with its own new D1 `ssh-mcp-installtest-db`, deployed from a fresh clone with
`WORKER_NAME=ssh-mcp-installtest DB_NAME=ssh-mcp-installtest-db bash scripts/deploy.sh` and word-list passphrases for
`ENCRYPTION_KEY` / `SESSION_SECRET` / `SETUP_TOKEN` (uploaded with `wrangler deploy --secrets-file`, stored as `secret_text`).

* D1 created, migrations 0001 + 0002 applied by the script; a second run reused the database ("No migrations to apply"),
  kept both keys ("already set — kept (never overwritten)") and redeployed.
* HTTPS checks: `/` 200 · `/api/auth/me` → `setup: available` (setup page) · setup without CSRF → 403 · wrong token → 401 ·
  right token → 200 + session · setup again → 403 · `/api/setup` → `done` · wrong password → 401 · login with the new password → 200 ·
  password source `d1` · MCP token created · `/mcp` without token → 401 · `initialize` → 200 + session · `tools/list` → **25 tools**.
* `wrangler delete` + `wrangler d1 delete` → both gone (D1 list and Workers script list no longer contain them; URL → 404).

## Upgrade of an existing deployment

An existing Worker created before the repo became generic was redeployed with
`WORKER_NAME=<old name> DB_NAME=<old db> bash scripts/deploy.sh` (same Worker, same D1, same secrets; nothing in the repo changed):
no new migrations were needed, "all secrets already set", `/` 200, login page (setup `done`, password source `secret`),
login with the existing password 200, server count unchanged (1), all pre-existing audit rows present, `/mcp` without token 401,
login page rendered in Chromium (en desktop, fa phone) with 0 console errors and no overflow.
