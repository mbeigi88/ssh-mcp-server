// Start-up configuration checks. A deployment with a missing / short / trivially weak secret must show a
// clear explanation (dashboard) or a clean 503 (API, MCP) instead of crashing with an exception.
import type { Env } from '../env';
import { encryptionKeyProblem, MIN_SECRET_LENGTH, passphraseProblem } from './crypto';

export interface ConfigIssue {
  /** secret / variable name */
  name: 'ENCRYPTION_KEY' | 'SESSION_SECRET' | 'ENCRYPTION_KEY_PREVIOUS';
  problem: 'missing' | 'too_short' | 'too_weak' | 'invalid_format';
}

/**
 * SESSION_SECRET: unchanged from v1 — any value of >= 32 characters is used as-is as the HMAC key
 * (so every existing deployment keeps its sessions); a passphrase is fine. Trivially weak values
 * (fewer than 6 distinct characters, e.g. "aaaa…") are rejected.
 * ENCRYPTION_KEY: base64 of 32 bytes (v1 format, used verbatim) or a passphrase of >= 32 characters.
 */
export function configIssues(env: Partial<Env>): ConfigIssue[] {
  const out: ConfigIssue[] = [];
  const ek = encryptionKeyProblem(env.ENCRYPTION_KEY);
  if (ek) out.push({ name: 'ENCRYPTION_KEY', problem: ek });
  const ss = sessionSecretProblem(env.SESSION_SECRET);
  if (ss) out.push({ name: 'SESSION_SECRET', problem: ss });
  if (env.ENCRYPTION_KEY_PREVIOUS) {
    const m = /^v(\d+):(.+)$/.exec(env.ENCRYPTION_KEY_PREVIOUS.trim());
    if (!m || encryptionKeyProblem(m[2])) out.push({ name: 'ENCRYPTION_KEY_PREVIOUS', problem: 'invalid_format' });
  }
  return out;
}

export function sessionSecretProblem(v: string | undefined | null): 'missing' | 'too_short' | 'too_weak' | null {
  // v1 accepted any string of >= 32 chars without trimming; keep that exact rule for the length check.
  if (!v) return 'missing';
  if (v.length < MIN_SECRET_LENGTH) return 'too_short';
  return passphraseProblem(v) === 'too_weak' ? 'too_weak' : null;
}

export function describeIssues(issues: ConfigIssue[]): string {
  return issues
    .map((i) => `${i.name} is ${i.problem.replace('_', ' ')}` + (i.problem === 'invalid_format' ? ' (expected "v<n>:<old key>")' : ` (use a random value or a passphrase of at least ${MIN_SECRET_LENGTH} characters)`))
    .join('; ');
}
