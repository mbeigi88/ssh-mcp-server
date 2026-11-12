#!/usr/bin/env bash
# Idempotent deploy for cf-ssh-mcp — works locally and in CI (GitHub Actions).
#
#   Auth:   `npx wrangler login`, or CLOUDFLARE_API_TOKEN (+ CLOUDFLARE_ACCOUNT_ID) in the environment.
#           Token permissions: Account › Workers Scripts: Edit, Account › D1: Edit (+ Account Settings: Read).
#   Names:  WORKER_NAME (default: "name" in wrangler.jsonc), DB_NAME (default: database_name in wrangler.jsonc).
#   Secrets (all optional): ENCRYPTION_KEY, SESSION_SECRET — used only if not yet set on the Worker (else generated);
#           SETUP_TOKEN, ADMIN_PASSWORD_HASH — uploaded when set in the environment.
#
# Every run: find or create the D1 database by name -> write wrangler.deploy.jsonc (git-ignored; wrangler.jsonc is
# never modified) -> apply D1 migrations (remote) -> deploy, uploading only the secrets that are missing.
# ENCRYPTION_KEY / SESSION_SECRET are set once (from the environment or random) and never overwritten. No secret value is ever printed.
# The admin password is NOT created here: open the dashboard and use first-run setup with your SETUP_TOKEN.
# Run locally on a terminal with neither password nor token, a SETUP_TOKEN is generated into ./SETUP_TOKEN.txt (600).
set -euo pipefail
cd "$(dirname "$0")/.."
W="npx --no-install wrangler"
H="node scripts/deploy-helper.mjs"
WORKER_NAME="${WORKER_NAME:-$($H config-get name)}"
DB_NAME="${DB_NAME:-$($H config-get database_name)}"
CFG="wrangler.deploy.jsonc"
if [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ ! -t 0 ]; then INTERACTIVE_LOCAL=0; else INTERACTIVE_LOCAL=1; fi

echo "==> Worker '$WORKER_NAME', D1 database '$DB_NAME'"
echo "==> Checking Cloudflare authentication"
$W whoami >/dev/null

echo "==> Ensuring D1 database exists"
DB_ID="$($W d1 list --json 2>/dev/null | $H d1-id "$DB_NAME")"
if [ -z "$DB_ID" ]; then
  $W d1 create "$DB_NAME" >/dev/null
  DB_ID="$($W d1 list --json 2>/dev/null | $H d1-id "$DB_NAME")"
  [ -n "$DB_ID" ] || { echo "ERROR: could not create or find D1 database '$DB_NAME'" >&2; exit 1; }
  echo "    created $DB_ID"
else
  echo "    exists $DB_ID"
fi
$H write-config "$WORKER_NAME" "$DB_NAME" "$DB_ID"

echo "==> Applying D1 migrations (remote)"
$W d1 migrations apply DB --remote -c "$CFG"

echo "==> Checking existing secrets"
TMP="$(mktemp -d)"; chmod 700 "$TMP"; trap 'rm -rf "$TMP"' EXIT
$W secret list --format json -c "$CFG" > "$TMP/existing.json" 2>/dev/null || echo '[]' > "$TMP/existing.json"
HAS_DB_PASSWORD=0
if $W d1 execute DB --remote -c "$CFG" --json \
     --command "SELECT count(*) AS n FROM settings WHERE key IN ('secret:admin_password_hash','secret:admin_password_hash_local')" 2>/dev/null \
   | grep -q '"n": *[1-9]'; then HAS_DB_PASSWORD=1; fi
HAS_DB_PASSWORD=$HAS_DB_PASSWORD INTERACTIVE_LOCAL=$INTERACTIVE_LOCAL $H secrets "$TMP/existing.json" "$TMP/secrets.json"

echo "==> Deploying Worker"
# Secret values are passed via the 0600 temp file only; unset them from the environment wrangler sees.
if [ "$(cat "$TMP/secrets.json")" != "{}" ]; then
  env -u SETUP_TOKEN -u ADMIN_PASSWORD_HASH -u ENCRYPTION_KEY -u SESSION_SECRET $W deploy -c "$CFG" --secrets-file "$TMP/secrets.json"
else
  env -u SETUP_TOKEN -u ADMIN_PASSWORD_HASH -u ENCRYPTION_KEY -u SESSION_SECRET $W deploy -c "$CFG"
fi
echo "Done. Open the workers.dev URL printed above: the dashboard is at /, the MCP endpoint at /mcp."
