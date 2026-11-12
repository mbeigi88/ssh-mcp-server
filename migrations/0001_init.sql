-- cf-ssh-mcp initial schema
CREATE TABLE IF NOT EXISTS servers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  username TEXT NOT NULL,
  auth_method TEXT NOT NULL CHECK (auth_method IN ('password', 'key')),
  -- AES-256-GCM encrypted JSON {password?, privateKey?, passphrase?}; AAD = server id
  cred_ciphertext TEXT,
  cred_iv TEXT,
  cred_key_version INTEGER NOT NULL DEFAULT 1,
  has_password INTEGER NOT NULL DEFAULT 0,
  has_private_key INTEGER NOT NULL DEFAULT 0,
  has_passphrase INTEGER NOT NULL DEFAULT 0,
  host_key_fingerprint TEXT,          -- approved SHA256:... fingerprint (OpenSSH format)
  host_key_algo TEXT,
  pending_fingerprint TEXT,           -- fingerprint seen on first contact, awaiting approval
  pending_fingerprint_algo TEXT,
  labels TEXT NOT NULL DEFAULT '[]',
  is_default INTEGER NOT NULL DEFAULT 0,
  allow_root INTEGER NOT NULL DEFAULT 0,
  policy_mode TEXT NOT NULL DEFAULT 'modify' CHECK (policy_mode IN ('read_only', 'modify')),
  allow_sudo_install INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'disconnected',
  last_error TEXT,
  last_connected_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  server_id TEXT,
  outcome TEXT NOT NULL DEFAULT 'ok',
  detail TEXT,
  ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts DESC);

CREATE TABLE IF NOT EXISTS connection_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  event TEXT NOT NULL,
  detail TEXT,
  duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_connhist_server ON connection_history (server_id, ts DESC);

CREATE TABLE IF NOT EXISTS command_results (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  command TEXT NOT NULL,
  classification TEXT NOT NULL,
  status TEXT NOT NULL,
  exit_code INTEGER,
  signal TEXT,
  stdout TEXT,
  stderr TEXT,
  stdout_truncated INTEGER NOT NULL DEFAULT 0,
  stderr_truncated INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_cmd_server ON command_results (server_id, started_at DESC);

CREATE TABLE IF NOT EXISTS mcp_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,               -- HMAC-SHA256(SESSION_SECRET, cookie token)
  csrf_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT
);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (key, window_start)
);

CREATE TABLE IF NOT EXISTS pending_confirmations (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  operation TEXT NOT NULL,           -- exact JSON of the operation that will run once approved
  classification TEXT NOT NULL,
  reason TEXT NOT NULL,
  confirm_token_hash TEXT NOT NULL,  -- one-time human token shown only in the dashboard
  status TEXT NOT NULL DEFAULT 'pending',
  requested_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  decided_at INTEGER,
  executed_at INTEGER,
  result_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_confirmations (status, created_at DESC);
