import type { SshSession } from './do/ssh-session';
import type { McpSession } from './do/mcp-session';

export interface Env {
  DB: D1Database;
  SSH_SESSION: DurableObjectNamespace<SshSession>;
  MCP_SESSION: DurableObjectNamespace<McpSession>;

  /** base64 of 32 bytes (v1 format) or a passphrase of >= 32 chars; AES-256-GCM credential encryption (secret). */
  ENCRYPTION_KEY: string;
  /** Optional previous key for rotation: "v<version>:<base64>" (secret). */
  ENCRYPTION_KEY_PREVIOUS?: string;
  /** Version number of ENCRYPTION_KEY (default 1). */
  ENCRYPTION_KEY_VERSION?: string;
  /** PBKDF2 hash "pbkdf2$sha256$<iter>$<salt>$<hash>" of the admin password (secret). */
  ADMIN_PASSWORD_HASH?: string;
  /** One-time token the installer chose; required to create the first admin password in the dashboard (secret). */
  SETUP_TOKEN?: string;
  /** HMAC key for session ids (secret). */
  SESSION_SECRET: string;

  /** "password" (default) | "access" | "both" */
  AUTH_MODE?: string;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD?: string;

  /** Only for local dev/test: allow loopback/private SSH targets. NEVER set in production. */
  DEV_ALLOW_PRIVATE_TARGETS?: string;
  /** Only for local dev/test: allow non-HTTPS cookies. */
  DEV_INSECURE_COOKIES?: string;
}

export type Actor = { kind: 'admin'; label: string } | { kind: 'mcp'; label: string; tokenId: string };
