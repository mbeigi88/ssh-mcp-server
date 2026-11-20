-- OAuth 2.1 authorization server for MCP clients (Gemini, Claude, ChatGPT, MCP Inspector, ...).
-- Dynamic client registration (RFC 7591), authorization code + PKCE S256, refresh-token rotation.
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,            -- NULL for public clients (token_endpoint_auth_method = none)
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,        -- JSON array
  token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT,
  grant_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

-- One row per approved grant; access + refresh tokens rotate inside it.
CREATE TABLE IF NOT EXISTS oauth_grants (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT,
  access_token_hash TEXT,
  access_expires_at INTEGER,
  refresh_token_hash TEXT,
  refresh_expires_at INTEGER,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_access ON oauth_grants (access_token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_refresh ON oauth_grants (refresh_token_hash);
