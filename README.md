# cf-ssh-mcp — SSH MCP server + web dashboard on one Cloudflare Worker

A real SSH-2 client running **inside a Cloudflare Worker** (outbound TCP via `cloudflare:sockets`),
exposed two ways:

* **`/mcp`** — a Model Context Protocol server (official `@modelcontextprotocol/sdk`, Streamable HTTP,
  bearer-token auth) with 25 tools for commands, files (SFTP), metrics and Docker.
* **`/`** — a mobile-first dark dashboard (English by default, with a full Persian/RTL option in the language toggle) to manage servers,
  approve host keys, run commands, browse files, approve destructive operations and issue MCP tokens.

No agent runs on your VPS. It is plain SSH to your server's `sshd`. Everything runs in **your own** Cloudflare
account; you never paste a token into a third-party site.

---

## Install

Pick one of three ways. All of them end with the same [first-run setup](#first-run-setup).

### A. Deploy to Cloudflare button (easiest, works from a phone)

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/robamad1396-dev/cf-ssh-mcp)

1. Tap the button and sign in to Cloudflare (a free account is enough to start; see [limits](#2-limits-that-apply-verified-november-2026)).
2. Connect GitHub / GitLab when asked — Cloudflare copies this repository into **your** account and builds it from there.
3. Keep the suggested names (or choose your own Worker and database names). The D1 database and both Durable Objects are created for you.
4. Fill in the three secrets. **Any long passphrase works** — no special format, nothing to generate:

   | Secret | What to type |
   |---|---|
   | `ENCRYPTION_KEY` | a passphrase of **32+ characters** (e.g. six random words). Keep a copy; never change it after adding servers. |
   | `SESSION_SECRET` | another, different passphrase of **32+ characters**. |
   | `SETUP_TOKEN` | a phrase of **12+ characters** that only you know. You type it once to create the admin password. |

5. Deploy. The deploy command applies the D1 migrations (`npm run deploy` = `wrangler d1 migrations apply DB --remote && wrangler deploy`).
6. Open the `https://<worker>.<your-subdomain>.workers.dev` URL shown at the end and continue with [first-run setup](#first-run-setup).

### B. GitHub Actions (your fork, no local tools)

1. Fork this repository (or *Use this template*).
2. In your fork: **Settings → Secrets and variables → Actions → New repository secret**:
   * `CLOUDFLARE_API_TOKEN` — create at *dash.cloudflare.com → My Profile → API Tokens → Create Token → Custom*, permissions
     **Account › Workers Scripts › Edit** and **Account › D1 › Edit** (add **Account Settings › Read** if `wrangler whoami` complains).
   * `CLOUDFLARE_ACCOUNT_ID` — shown on *Workers & Pages* (right sidebar).
   * `SETUP_TOKEN` (recommended) — 12+ characters, used once in the dashboard.
   * `ADMIN_PASSWORD_HASH` (optional) — output of `npm run hash-password`; skips first-run setup.
   * `ENCRYPTION_KEY`, `SESSION_SECRET` (optional) — your own 32+ character passphrases; otherwise random values are generated on the first run.
3. **Actions → Deploy to Cloudflare → Run workflow** (you can change the Worker / database name in the form).

The workflow (`.github/workflows/deploy.yml`) runs `npm ci` and `scripts/deploy.sh`. Re-running it is safe: the database is found by
name and reused, migrations are applied, `ENCRYPTION_KEY` / `SESSION_SECRET` are set **only if absent** (from your repo secrets or random; never overwritten, never
printed), and no admin password is ever created or printed in CI — you create it in the dashboard.

### C. Local command line

```bash
git clone https://github.com/robamad1396-dev/cf-ssh-mcp && cd cf-ssh-mcp
npm ci                        # also patches ssh2 for Workers (postinstall)
npx wrangler login            # or export CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=…
npm run deploy:full           # = bash scripts/deploy.sh
```

Optional environment for `scripts/deploy.sh`: `WORKER_NAME` (default `cf-ssh-mcp`), `DB_NAME` (default `cf-ssh-mcp-db`),
`SETUP_TOKEN`, `ADMIN_PASSWORD_HASH`, and `ENCRYPTION_KEY` / `SESSION_SECRET` (used only if the Worker does not have them yet). When neither an admin password nor a setup token exists and you run it on a terminal,
the script generates a setup token and writes it to `./SETUP_TOKEN.txt` (mode 600, git-ignored) — it is never printed.
(Earlier versions generated an admin password into `ADMIN_CREDENTIALS.txt`; that is replaced by first-run setup.)

### First-run setup

1. Open your Worker URL. A fresh deployment shows **Create admin password** instead of the login form.
2. Enter your `SETUP_TOKEN` and a new admin password (12+ characters), then **Create password and sign in**.
3. That's it: the password is stored as a PBKDF2 hash in D1 and setup is **permanently disabled** for this deployment.

Protection: the setup endpoint needs the `SETUP_TOKEN` (constant-time comparison), a CSRF double-submit token and same-origin
`Origin`, and is rate-limited (5/min and 20/h per IP, 60 per 10 min globally). Two concurrent attempts cannot both win.
If `SETUP_TOKEN` is missing or too short the page explains how to add it
(*dash.cloudflare.com → Workers & Pages → your Worker → Settings → Variables and Secrets → Add → Secret*, or `npx wrangler secret put SETUP_TOKEN`).
If a secret such as `ENCRYPTION_KEY` is missing or too weak, the dashboard shows a "Configuration needed" page instead of crashing.

Admin password rules:
* An `ADMIN_PASSWORD_HASH` secret, when set, wins over the password created in setup (use it to **recover** a forgotten password:
  `printf '%s' 'new long password' | npm run -s hash-password | npx wrangler secret put ADMIN_PASSWORD_HASH`). Setup is then disabled.
* A password created in setup can be changed in **Settings → Change admin password**. When the password comes from the secret,
  Settings explains that it must be changed through the secret.
* Upgrading from v1: a password you changed in the v1 dashboard keeps working (it still overrides the secret, as before).

### Connect an MCP client

In the dashboard open **MCP → Create token** (shown once), then use `https://<worker>.<subdomain>.workers.dev/mcp` with the header
`Authorization: Bearer <token>`. For **Claude** (web/desktop "Add custom connector"), the dashboard shows the exact steps. Examples:

**Cursor** (`~/.cursor/mcp.json`):

```json
{ "mcpServers": { "my-ssh": { "url": "https://cf-ssh-mcp.example.workers.dev/mcp",
  "headers": { "Authorization": "Bearer sshmcp_XXXXXXXX" } } } }
```

**Claude Desktop** (`claude_desktop_config.json`, via the `mcp-remote` bridge):

```json
{ "mcpServers": { "my-ssh": { "command": "npx",
  "args": ["-y", "mcp-remote", "https://cf-ssh-mcp.example.workers.dev/mcp", "--header", "Authorization:Bearer ${MCP_TOKEN}"],
  "env": { "MCP_TOKEN": "sshmcp_XXXXXXXX" } } } }
```

**Claude Code**: `claude mcp add --transport http my-ssh https://cf-ssh-mcp.example.workers.dev/mcp --header "Authorization: Bearer sshmcp_XXXXXXXX"`

Then in the dashboard: **Servers → Add server** (host, port, user, password or private key), **Connect**, compare the host-key
fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server and **Approve host key**.

---

## 1. Architecture

```
 MCP client ──Bearer──▶ /mcp ──▶ McpSession DO (one per Mcp-Session-Id) ─┐
 Browser ──cookie+CSRF─▶ /api ───────────────────────────────────────────┤
                                                                         ▼
                                 services/ops.ts (policy, confirmations, audit)
                                                                         ▼
                      SshSession DO (one per server) ── ssh2 ── cloudflare:sockets ──TCP──▶ sshd
                                                                         │
                                                 D1: servers, settings, audit_log, …
```

| Piece | File | Notes |
|---|---|---|
| Router, security headers, `/mcp` routing | `src/index.ts` | Hono. CSP with per-request nonce, HSTS, XFO, nosniff, no-referrer, COOP/CORP |
| Dashboard API | `src/api/routes.ts` | Session cookie + CSRF, zod validation, rate limits |
| Dashboard UI | `src/ui/dashboard.ts`, `styles.ts`, `client.ts`, `font.ts` | HTML shell + stylesheet + client script inlined under the CSP nonce, inline SVG icons/illustrations, self-hosted Vazirmatn (Arabic-script subset, 44 KB, SIL OFL) at `/assets/vazirmatn.woff2`; no `innerHTML` with data, no inline style/handler attributes |
| SSH session Durable Object | `src/do/ssh-session.ts` | Holds the live SSH + SFTP connection, TOFU host-key logic, running-command registry (cancel), idle-timeout alarm |
| MCP session Durable Object | `src/do/mcp-session.ts` | `McpServer` + `WebStandardStreamableHTTPServerTransport`; session pinned to its token; survives DO eviction |
| MCP tools | `src/mcp/tools.ts` | 25 tools, zod schemas, per-tool timeout, output cap (200 000 chars) |
| SSH client | `src/ssh/client.ts`, `socket-bridge.ts`, `crypto-polyfill.ts` | ssh2 1.17 over a `cloudflare:sockets` ⇄ Node `Duplex` bridge |
| Policy / classifier | `src/lib/policy.ts` | read / modify / destructive, per-server mode |
| Crypto | `src/lib/crypto.ts`, `src/lib/config.ts` | AES-256-GCM (WebCrypto) with AAD=`server:<id>`, key versions, v1 raw keys or HKDF-derived passphrase keys, PBKDF2-SHA256 (100k), secret checks |
| First-run setup | `src/lib/setup.ts` | SETUP_TOKEN-gated admin password creation, stored in D1 `settings` (no new table/migration needed) |
| SSRF | `src/lib/ssrf.ts` | Blocks private/loopback/link-local/metadata/CGNAT/ULA/mapped/NAT64; DoH resolution; connects to the **validated IP** (anti-rebinding) |
| Migrations | `migrations/0001_init.sql`, `0002_auto_approve.sql` | servers, settings, audit_log, connection_history, command_results, mcp_tokens, sessions, rate_limits, pending_confirmations; auto-approve level + audit flags |
| Auto-approve | `src/lib/auto-approve.ts` | levels off / safe / all, catastrophic list |

### Why ssh2 (patched) and not a hand-written client

Research (sources in §8) and local verification in workerd showed:

* `ssh2` 1.17 (pure JS, mature, SFTP v3, OpenSSH key formats incl. bcrypt-pbkdf encrypted keys) **runs in
  workerd** once four load-time blockers are patched (`scripts/patch-ssh2.mjs`, applied by `postinstall`):
  1. `require('./crypto/build/Release/sshcrypto.node')` (native addon) → removed.
  2. `require('cpu-features')` (native addon) → removed.
  3. eager `chacha20-poly1305` WASM instantiation — workerd forbids runtime WASM compilation
     ("Wasm code generation disallowed by embedder", ssh2 issue #1494) → made lazy; chacha20 is never offered.
  4. `agent.js` uses `__dirname` at module load → replaced (Pageant is Windows-only).
* Two **workerd `node:crypto` bugs** found and worked around (verified with probes in local workerd):
  * the *default* export of `node:crypto` (what CJS `require('crypto')` gets) lacks `diffieHellman`
    although the named export exists → `src/ssh/crypto-polyfill.ts` copies it over;
  * `crypto.diffieHellman()` with an X25519 key imported via `createPublicKey` throws
    *"Failed to derive shared diffie-hellman secret"* → `curve25519-sha256` key exchange is computed with
    **`@noble/curves` x25519** (audited, pure JS, sync) via patch step 6.
  * `createDecipheriv('aes-*-gcm')` followed by `update()` **before** `setAuthTag()` throws
    *"No auth tag provided"* in workerd → **AES-GCM is not offered** (also reported in ssh2 #1494).
* Negotiated algorithms (`src/ssh/client.ts`):
  * KEX: `curve25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256/384/521`, `diffie-hellman-group16-sha512`, `diffie-hellman-group14-sha256`
  * Host keys: `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `rsa-sha2-512`, `rsa-sha2-256` (no SHA-1 `ssh-rsa`)
  * Ciphers: `aes128-ctr`, `aes192-ctr`, `aes256-ctr`; MACs: `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256`, `hmac-sha2-512`
  * User auth: password, publickey (ed25519, RSA with rsa-sha2, ECDSA, OpenSSH/PEM formats, passphrase-encrypted).
  * This is compatible with stock OpenSSH 7.x–10.x (tested against **OpenSSH_10.0p2**).

### Host-key verification (TOFU, never disabled)

1. First connect: the Worker captures the server's key fingerprint (`SHA256:…`, identical to
   `ssh-keygen -lf`) and **refuses** the connection (`HOSTKEY_UNKNOWN`). Status becomes `hostkey_pending`.
2. The dashboard shows the fingerprint; the admin verifies it on the server and clicks **Approve host key**
   (the API only accepts the exact pending fingerprint).
3. Every later connect must match; a mismatch is a hard failure (`HOSTKEY_MISMATCH`), audited, status
   `hostkey_mismatch`. Changing host/port resets trust. You can also pre-pin a fingerprint when adding a server.

### Execution policy

`src/lib/policy.ts` splits a command line into segments (`;`, `&&`, `||`, `|`, `&`, newlines, `$( )`, backticks — quote-aware,
keeps `2>&1` intact) and classifies the whole as the worst segment:

* **destructive** — `rm -r/-rf`, `--no-preserve-root`, `mkfs*`, `wipefs/fdisk/parted/shred`, `dd of=/dev/…`, redirects onto block devices,
  `DROP DATABASE/TABLE/SCHEMA`, `TRUNCATE TABLE`, any non-read access to `sshd_config`, `authorized_keys`, `sudoers`, `/etc/passwd|shadow|group`,
  `passwd/chpasswd/usermod/visudo`, `ufw disable/reset`, `iptables -F/-X/-P … ACCEPT`, `nft flush`, stopping ssh/firewall services,
  `docker volume rm|prune`, `docker system|container|image|network prune`, forced `docker rm/rmi`, `compose down -v`,
  `shutdown/reboot/poweroff/halt`, `init 0/6`, `systemctl reboot…`, fork bombs, `userdel`, `crontab -r`, `kill -9 1`,
  `find -delete/-exec rm`, `curl|sh`, recursive chmod/chown on `/`, …
* **modify** — anything that writes (redirection, `tee`, `sed -i`, `cp/mv/touch/mkdir`, package managers, service restarts, unknown commands, any `sudo`).
* **read** — an allow-list of read-only commands/sub-commands (`ls`, `cat`, `grep`, `df`, `ps`, `journalctl`, `systemctl status`, `docker ps/logs/inspect`, …).

Per-server policy: **read-only** (only `read` runs; SFTP writes blocked), **allow modify** (default), and
**allow sudo package installs** (otherwise `sudo apt/yum/dnf/apk/pacman/pip/npm install…` is blocked).

**Destructive operations** (and **every `delete_file`**) are never executed directly from MCP: the tool returns
`confirmation_required` with a one-time `confirmation_id` (TTL default 15 min). A human then either
**approves it in the dashboard → Approvals** (the agent re-calls the tool with `confirmation_id`), or clicks
**Show one-time token** and gives that token to the agent (`confirm_token`). The *stored* operation is executed
exactly once (atomic status transition); arguments of the re-call are ignored; every step is audited.
In the dashboard terminal the human confirms in a dialog.

This is a guard-rail, not a sandbox: a shell that may modify can always be abused. Use read-only mode and a
non-root SSH user for agents you do not fully trust.

### Auto-approve (per server, November 2026)

Tired of approving every destructive operation? Each server has an **Auto-approve** level
(`servers.auto_approve`, migration `0002_auto_approve.sql`; existing servers stay `off`):

| Level | Effect |
|---|---|
| `off` (default) | unchanged: every destructive operation and every `delete_file` waits for a human |
| `safe` | destructive operations run immediately (deleting files/dirs, `rm -rf` of normal paths, `docker rm`, prunes without volumes, reboots, `DROP TABLE`, …) **except the catastrophic list**, which still needs approval |
| `all` | everything runs without approval — the UI shows a red warning and requires typing **CONFIRM** / **تأیید** (the API enforces the same word) |

Catastrophic list (`src/lib/auto-approve.ts`): `mkfs*`; `wipefs/fdisk/sfdisk/parted/sgdisk/gdisk/blkdiscard/shred` on `/dev/*`;
`dd of=/dev/*` (not `/dev/null`); redirects onto block devices; `rm -r` of `/`, `/*`, `~`, `$HOME` or a top-level system dir
(`/bin /boot /dev /etc /home /lib* /opt /proc /root /sbin /srv /sys /usr /var`) and `--no-preserve-root`; `find / -delete`; fork bombs;
`shutdown/poweroff/halt`, `systemctl poweroff|halt`, `init 0`; any change to `sshd_config(.d)`, `authorized_keys`, `sudoers`,
`/etc/passwd|shadow|group`, or `PasswordAuthentication/PermitRootLogin/PubkeyAuthentication`; `ufw disable/reset`, `iptables -F/-X/-P`,
`nft flush`, stopping ssh/firewall services; `DROP DATABASE/SCHEMA`; `docker volume rm|prune`, `docker system prune --volumes`,
`compose down -v`; `kill -9 1|-1`; recursive `chmod/chown` on `/`; `mv /`. For `delete_file`: system directories and the lock-out files above.

Rules: auto-approve only turns *confirm* into *allow* — it never overrides a *block*: **read-only mode still blocks every
modification**, disabled sudo installs stay blocked, recursive deletes of system directories via `delete_file` are still refused.
Every auto-approved execution is written to `audit_log` with `auto_approved = 1` and `auto_level`, and shown with an
**Auto / خودکار** badge in Audit and Overview → Recent activity. MCP results carry `auto_approved: true`, `auto_approve_level`
and a note; when auto-approve does not cover a request the `confirmation_required` result lists the `catastrophic` reasons.
The dashboard terminal follows the same level.

Where to set it: the server edit sheet (segmented control), a quick switch on each server card and on the Approvals page
(`POST /api/servers/:id/auto-approve {level, confirm_text?}` — does not drop the SSH session), and **Settings → Auto-approve for new
servers** (`default_auto_approve`). The Approvals page also has one-tap **Approve**, **Approve all** (with a confirmation sheet,
`POST /api/confirmations/approve-all`) and **Approve all for this server** (`{server_id}`); approved items run when the agent
re-calls the tool with its `confirmation_id`.

### Dashboard design (v2, November 2026)

* **Phones** (< 768 px): sticky top bar, bottom tab bar (Overview · Servers · Terminal · Files · MCP) with ≥ 44 px targets and
  safe-area insets; Approvals / Settings / Audit / language / logout live in the ⋯ sheet (bell shows pending approvals).
  Dialogs are bottom sheets; tables turn into cards; the tab bar hides while the keyboard is up. No horizontal overflow (tested).
* **Tablet / desktop**: collapsible sidebar (icon rail by default at 768–1199 px, remembered), multi-column grids.
* **Bilingual (English default, Persian/RTL optional)**: logical CSS properties throughout; every IP, host, command, path, fingerprint, token and config is an
  LTR island (`dir="ltr"` + `unicode-bidi:isolate`), the terminal and editor are always LTR, the server picker sets its own direction.
* **Terminal**: full-height, stdout / stderr colours, exit-code badge, quick-command chips, ↑/↓ history + history sheet, cancel.
* **Files**: LTR breadcrumb, list / grid, long-press or ⋯ action sheet on phones, upload progress bar (XHR, same CSRF), editor with line numbers, Ctrl+S.
* **MCP**: big copy buttons for URL and token, step-by-step *Add custom connector* card for Claude (No sign-in, header
  `Authorization: Bearer <token>`), tabs for Claude Desktop / Cursor / Claude Code configs.
* Skeleton loaders, illustrated empty states, toasts, focus rings, `prefers-reduced-motion` honoured.

---

## 2. Limits that apply (verified November 2026)

| Limit | Value | Impact here |
|---|---|---|
| Outbound TCP | `connect()` from `cloudflare:sockets`; blocked: Cloudflare IP ranges, port 25, private/localhost addresses | SSH to public hosts only; a VPS behind Cloudflare's own IPs cannot be reached |
| CPU time per request | Free **10 ms**, Paid 30 s default (configurable to 5 min) | ssh handshake ≈ few ms of CPU (X25519 + Ed25519/RSA verify); **bcrypt-pbkdf decryption of an encrypted key costs ~1–2 s CPU (16 rounds)** → needs the **Paid** plan or an unencrypted key |
| Durable Object CPU | 30 s per request/WebSocket message (configurable to 5 min) | long commands are mostly I/O wait (not CPU) |
| Wall time | HTTP: unlimited while the client is connected; DO alarm 15 min | commands capped at 600 s by this app |
| Socket keeps DO alive | up to **15 min** per connection, after which normal eviction resumes | idle timeout default 300 s; if the DO is evicted the next call reconnects transparently |
| Simultaneous connections waiting for headers | 6 per invocation | one SSH socket per server DO |
| Memory | 128 MB per isolate | output capped per stream (default 256 KiB, max 4 MiB); downloads streamed in 64 KiB SFTP reads; uploads in ≤8 MiB chunks |
| Worker size | 64 MiB uncompressed (free & paid) | bundle is **2.52 MiB** (gzip 515 KiB), startup 46 ms |
| PBKDF2 in WebCrypto | max 100 000 iterations | admin password hash uses 100 000 |
| Runtime updates | live connections may be dropped (20 min grace) | the DO reconnects on next use |

Not supported (by design or runtime): interactive PTY shells, port forwarding, SSH agent forwarding,
`chacha20-poly1305` and AES-GCM ciphers, SHA-1 `ssh-rsa` host keys, DSA keys, keyboard-interactive/2FA,
jump hosts.

---
---

## 3. Secrets & variables

| Name | Kind | Purpose |
|---|---|---|
| `ENCRYPTION_KEY` | secret | AES-256-GCM key for SSH credentials. Either the v1 format — base64 of 32 random bytes, used **verbatim** — or **any passphrase of ≥ 32 characters**, from which a 256-bit key is derived with HKDF-SHA256 (fixed, domain-separated salt `cf-ssh-mcp/v1/encryption-key-salt`). Missing / shorter / trivially weak (< 6 distinct characters) → "Configuration needed" page and 503 on the API and `/mcp` |
| `ENCRYPTION_KEY_VERSION` | var/secret (optional) | integer version of the current key (default 1) |
| `ENCRYPTION_KEY_PREVIOUS` | secret (optional) | `v<n>:<old key>` (either format), for rotation (decrypt-only) |
| `SESSION_SECRET` | secret | ≥ 32 characters (random or passphrase); HMAC key for session ids, used as-is (unchanged from v1) |
| `SETUP_TOKEN` | secret | ≥ 12 characters; required once to create the first admin password in the dashboard |
| `ADMIN_PASSWORD_HASH` | secret (optional) | `pbkdf2$sha256$100000$<salt>$<hash>` from `npm run hash-password`; overrides the setup password (recovery) |
| `AUTH_MODE` | var | `password` (default), `access` (Cloudflare Access JWT only), `both` |
| `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` | var | for `access`/`both`: e.g. `myteam.cloudflareaccess.com` and the application AUD tag; the `Cf-Access-Jwt-Assertion` RS256 JWT is verified against the team JWKS (signature, aud, iss, exp, nbf) |

**Local development only** (never set these on a deployed Worker; they are deliberately *not* in `.dev.vars.example`, so the
Deploy button never asks for them):

| Name | Purpose |
|---|---|
| `DEV_ALLOW_PRIVATE_TARGETS=true` | allows loopback/private SSH targets so `wrangler dev` / tests can reach a local sshd |
| `DEV_INSECURE_COOKIES=true` | drops `Secure`/`__Host-` from the cookie for plain-HTTP dev on a non-localhost host |

Credentials are encrypted with AAD bound to the server id, are never returned by any API/MCP result/log/error,
and the edit form only shows "set — leave empty to keep unchanged". Audit details pass through a redactor.
MCP tokens (`sshmcp_…`, 256-bit) are shown once and stored as SHA-256 hashes.

---

## 4. Local development

```bash
npm ci                                   # also patches ssh2 (postinstall)
cp .dev.vars.example .dev.vars           # fill in ENCRYPTION_KEY, SESSION_SECRET, SETUP_TOKEN
echo 'DEV_ALLOW_PRIVATE_TARGETS=true' >> .dev.vars   # only if you want to SSH to 127.0.0.1 / LAN hosts locally
npm run db:migrate:local                 # = wrangler d1 migrations apply DB --local
npm run dev                              # http://localhost:8787 -> first-run setup page
```

Tests:

```bash
npm run typecheck
npm test                 # unit (Node) + worker (workerd via @cloudflare/vitest-plugin)
npm run test:integration # REAL OpenSSH server on 127.0.0.1:2222 (test/sshd/setup.sh installs openssh-server + a test user; needs sudo)
npm run build            # bundles the dashboard and syntax-checks its script (dist/dashboard.js)
npx wrangler deploy --dry-run --outdir dist   # bundle/size check
# Chromium E2E against `wrangler dev` + the local sshd (desktop + phone, en + fa, overflow/bidi checks, screenshots).
# SETUP_BASE: a second `wrangler dev` with a fresh database and SETUP_TOKEN (no ADMIN_PASSWORD_HASH) to test first-run setup.
BASE=http://localhost:8787 ADMIN_PASSWORD=… SETUP_BASE=http://localhost:8788 SETUP_TOKEN=… npm run test:e2e
BASE=https://<worker>.workers.dev node scripts/smoke.mjs   # HTTPS smoke test of a deployment (optional ADMIN_PASSWORD, MCP_TOKEN)
```

**Last full run (2026-11-12, see [TEST_REPORT.md](TEST_REPORT.md)):** typecheck clean · unit **222/222** · worker **37/37** ·
integration vs real OpenSSH 10.0p2 **33/33** · browser E2E **23/23** · `wrangler deploy --dry-run` 2577.94 KiB (gzip 514.94 KiB) ·
fresh install from a clean clone over HTTPS **16/16** — **315 automated tests passed, 0 failed**.

The SSH keys in `test/fixtures/keys/` are **throw-away test keys** used only by the local test sshd; they grant access to nothing.

---

## 5. Deploy details

* `wrangler.jsonc` is generic and account-independent: worker `cf-ssh-mcp`, D1 binding `DB` → `cf-ssh-mcp-db` with a placeholder id
  (`00000000-…`) that the Deploy button replaces. `npm run deploy` migrates **by binding name** (`DB`), so it works whatever the database is called.
* `scripts/deploy.sh` never edits tracked files. Each run it looks the database up by name (creating it if needed), writes the git-ignored
  `wrangler.deploy.jsonc` with the real id and the chosen worker name, applies migrations (`d1 migrations apply DB --remote -c wrangler.deploy.jsonc`)
  and deploys with only the *missing* secrets (`wrangler deploy --secrets-file`, a 0600 temp file; values never printed).
* **Existing deployments with other names** (e.g. a Worker created before this repo was made generic): run the same script with your names —
  `WORKER_NAME=my-old-worker DB_NAME=my-old-worker-db npm run deploy:full`. Nothing in the repository has to change, secrets already set are kept,
  and new migrations are applied to that database.
* Token permissions: *Workers Scripts: Edit*, *D1: Edit* (+ *Account Settings: Read*).
* After deploying, consider putting the dashboard behind **Cloudflare Access** (`AUTH_MODE=both`) and leaving `/mcp` bypassed
  (it has its own bearer auth).

---

## 6. MCP endpoint

Official SDK smoke test: `MCP_URL=…/mcp MCP_TOKEN=… node scripts/mcp-smoke.mjs`.

### Tools

`list_servers`, `get_server_status`, `test_ssh_connection`, `get_server_info`, `execute_command`, `execute_commands`,
`get_command_result`, `list_directory`, `read_file`, `write_file`, `upload_file`, `download_file`, `create_directory`,
`rename_file`, `delete_file`, `get_cpu_usage`, `get_memory_usage`, `get_disk_usage`, `get_system_uptime`,
`get_running_processes`, `get_network_interfaces`, `get_service_status`, `docker_ps`, `docker_logs`, `docker_inspect`.
Every tool takes an optional `server` (name or id; defaults to the default server). Tool-built commands quote
every argument (`shQuote`) and validate service/container names.

---


---

## 7. Security summary

Dashboard: PBKDF2 password, `__Host-` HttpOnly Secure SameSite=Strict cookie, HMAC'd session ids with expiry,
CSRF token + Origin check on every state-changing request, login rate limit (5/min, 30/h per IP), API rate limit,
optional Cloudflare Access JWT. First-run setup: `SETUP_TOKEN` required (SHA-256 digests compared in constant time),
CSRF double-submit + Origin check, rate limits, minimum password length/strength, atomic one-time insert, permanently disabled afterwards.
MCP: bearer tokens (hashed), per-token rate limit, sessions bound to their token,
failed-auth rate limit. Strict CSP (nonce, `default-src 'none'`, no inline scripts/styles/handlers), HSTS, XFO DENY, nosniff, no-referrer, COOP/CORP,
`no-store`. SSRF filter + IP pinning. TOFU host keys with hard-fail on mismatch. Root login only per-server opt-in.
Audit log for logins, setup, server changes, host-key events, commands, file ops, confirmations, token changes.
See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## 8. License

MIT — see [LICENSE](LICENSE). Bundled font: Vazirmatn (SIL Open Font License, `assets/Vazirmatn-OFL.txt`).

## 9. Research sources (verified)

* Workers TCP sockets — https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/ (SSH listed; blocked destinations; DO socket keeps object alive up to 15 min)
* `node:net` (built on `connect()`; `net.Server` unsupported) — https://developers.cloudflare.com/workers/runtime-apis/nodejs/net/
* `node:crypto` (fully supported except DH/DSA keygen, argon2, ed448/x448; nodejs_compat default from compat date 2026-08-04) — https://developers.cloudflare.com/workers/runtime-apis/nodejs/crypto/
* Workers limits (CPU 10 ms free / 5 min paid, memory 128 MB, 6 connections, size 64 MiB) — https://developers.cloudflare.com/workers/platform/limits/
* Durable Objects limits (30 s→5 min CPU per request, unlimited wall time while connected) — https://developers.cloudflare.com/durable-objects/platform/limits/
* ssh2 + workerd WASM / AES-GCM problems — https://github.com/mscdex/ssh2/issues/1494
* Prior art using ssh2 over `cloudflare:sockets` (password + exec only) — https://github.com/Octolus/CloudFlare-Worker-SSH
* Vitest integration — https://developers.cloudflare.com/workers/testing/vitest-integration/configuration/

Our own findings (not in the docs, reproduced locally in workerd): the `node:crypto` default-export
`diffieHellman` omission and the X25519 `diffieHellman` failure described above.

---


---

## فارسی (Persian)

### این پروژه چیست؟
یک سرور **MCP** و یک **داشبورد وب** که هر دو روی **یک Cloudflare Worker** در حساب کلادفلر خودتان اجرا می‌شوند و از طریق
**SSH واقعی** (کتابخانهٔ ssh2 روی سوکت TCP خروجی `cloudflare:sockets`) به سرورهای شما وصل می‌شوند.
هیچ برنامه‌ای روی VPS نصب نمی‌شود و لازم نیست هیچ توکنی را در سایت شخص ثالث وارد کنید.

### نصب
سه روش وجود دارد؛ هر سه با «راه‌اندازی اولیه» (پایین) تمام می‌شوند.

**الف) دکمهٔ Deploy to Cloudflare (ساده‌ترین، حتی با گوشی):** روی دکمهٔ بالای همین صفحه بزنید، وارد کلادفلر شوید و GitHub را وصل کنید.
پایگاه‌دادهٔ D1 و Durable Objectها خودکار ساخته می‌شوند. سه راز را وارد کنید — **هر عبارت عبور بلند کافی است**، قالب خاصی لازم نیست:
* `ENCRYPTION_KEY`: عبارتی با **حداقل ۳۲ نویسه** (مثلاً شش کلمهٔ تصادفی). یک نسخه نگه دارید و بعد از افزودن سرور هرگز عوضش نکنید.
* `SESSION_SECRET`: عبارت دیگری با **حداقل ۳۲ نویسه**.
* `SETUP_TOKEN`: عبارتی با **حداقل ۱۲ نویسه** که فقط خودتان می‌دانید؛ یک بار برای ساخت رمز مدیر لازم است.

سپس Deploy کنید (مهاجرت‌های D1 در همان فرمان استقرار اجرا می‌شوند) و آدرس `workers.dev` را باز کنید.

**ب) GitHub Actions:** مخزن را fork کنید؛ در Settings ← Secrets and variables ← Actions رازهای `CLOUDFLARE_API_TOKEN`
(مجوزهای Workers Scripts: Edit و D1: Edit)، `CLOUDFLARE_ACCOUNT_ID` و ترجیحاً `SETUP_TOKEN` را بگذارید؛ سپس در Actions
گردش‌کار **Deploy to Cloudflare** را اجرا کنید. اجرای دوباره بی‌خطر است: پایگاه‌داده دوباره استفاده می‌شود، رازهای موجود هرگز بازنویسی
یا چاپ نمی‌شوند و رمز مدیر در CI ساخته نمی‌شود.

**ج) خط فرمان:**
```bash
npm ci
npx wrangler login                 # یا CLOUDFLARE_API_TOKEN و CLOUDFLARE_ACCOUNT_ID
npm run deploy:full                # ساخت/یافتن D1، مهاجرت‌ها، استقرار، تولید رازهای ناموجود
```
اگر نه رمز مدیر و نه توکن راه‌اندازی وجود داشته باشد، اسکریپت یک توکن راه‌اندازی می‌سازد و فقط در `SETUP_TOKEN.txt` (دسترسی 600) می‌نویسد.

### راه‌اندازی اولیه
1. آدرس Worker را باز کنید؛ به‌جای فرم ورود صفحهٔ **ساخت رمز مدیر** نمایش داده می‌شود (زبان از دکمهٔ بالا قابل تغییر است).
2. `SETUP_TOKEN` و رمز جدید مدیر (حداقل ۱۲ نویسه) را وارد کنید.
3. رمز به‌صورت هش PBKDF2 در D1 ذخیره و این صفحه **برای همیشه غیرفعال** می‌شود. تغییر رمز بعداً از **تنظیمات** ممکن است.

اگر `SETUP_TOKEN` تنظیم نشده باشد، صفحه توضیح می‌دهد چطور آن را اضافه کنید؛ اگر رازی مثل `ENCRYPTION_KEY` وجود نداشته باشد یا خیلی ضعیف باشد،
صفحهٔ «نیاز به پیکربندی» نمایش داده می‌شود. راز `ADMIN_PASSWORD_HASH` (در صورت وجود) بر رمز ساخته‌شده در راه‌اندازی مقدم است و راه بازیابی رمز فراموش‌شده است.

### پس از ورود
1. **سرورها ← افزودن سرور**: میزبان، پورت، نام کاربری، رمز یا کلید خصوصی (و عبارت عبور).
2. **اتصال** ← اثر انگشت کلید میزبان نمایش داده می‌شود؛ آن را روی سرور با
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` مقایسه و سپس **تأیید** کنید.
3. **MCP ← ساخت توکن** و قرار دادن آدرس `/mcp` و توکن در Claude / Cursor (مراحل دقیق در داشبورد نمایش داده می‌شود).

### امکانات
* **داشبورد** (`/`): طراحی موبایل‌محور با نوار پایین، تم تیره، فونت وزیرمتن، انگلیسی به‌صورت پیش‌فرض و فارسی راست‌به‌چپ از طریق کلید زبان؛ دستورات، مسیرها، IPها و توکن‌ها همیشه چپ‌به‌راست نمایش داده می‌شوند:
  نمای کلی، مدیریت سرورها، ترمینال، مدیر فایل SFTP، صفحهٔ تأییدها، صفحهٔ MCP، تنظیمات و گزارش رویدادها.
* **MCP** (`/mcp`): ۲۵ ابزار (اجرای دستور، فایل، CPU/حافظه/دیسک، فرایندها، شبکه، سرویس‌ها، Docker).
* **امنیت**: رمزنگاری AES-256-GCM اطلاعات ورود؛ تأیید کلید میزبان (TOFU)؛ محافظت SSRF؛ CSRF؛ محدودیت نرخ؛ کوکی امن؛ هدرهای امنیتی؛
  دستورات مخرب فقط پس از **تأیید انسان** اجرا می‌شوند (مگر تأیید خودکار را فعال کنید).

### تأیید خودکار
برای هر سرور سه حالت: **خاموش** (پیش‌فرض)، **ایمن** (عملیات مخرب عادی بی‌درنگ اجرا می‌شوند ولی موارد فاجعه‌بار همچنان تأیید می‌خواهند)،
**همه** (بدون تأیید؛ باید کلمهٔ «تأیید» را تایپ کنید). حالت فقط‌خواندنی همیشه مقدم است و هر اجرای خودکار در گزارش رویدادها با نشان **خودکار** ثبت می‌شود.

### محدودیت‌ها
* فقط اتصال به آدرس‌های عمومی (آدرس‌های خصوصی و IPهای کلادفلر و پورت ۲۵ توسط خود کلادفلر مسدودند).
* در پلن رایگان سقف CPU هر درخواست ۱۰ میلی‌ثانیه است؛ کلیدهای رمزگذاری‌شده (bcrypt) به پلن پولی نیاز دارند.
* پوستهٔ تعاملی (PTY)، فوروارد پورت و رمزهای AES-GCM / chacha20 پشتیبانی نمی‌شوند.
* کلیدهای SSH داخل `test/fixtures/keys/` فقط برای آزمایش محلی‌اند و به هیچ سروری دسترسی نمی‌دهند.
