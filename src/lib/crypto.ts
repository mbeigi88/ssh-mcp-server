// WebCrypto helpers: AES-256-GCM credential encryption, PBKDF2 password hashing,
// HMAC, SHA-256, random tokens, constant-time comparison.

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64encode(buf: ArrayBuffer | Uint8Array): string {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
}
export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function b64url(buf: Uint8Array): string {
  return b64encode(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return b64decode(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
}
export function hex(buf: ArrayBuffer | Uint8Array): string {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
export function randomToken(bytes = 32): string {
  return b64url(randomBytes(bytes));
}
export function randomId(prefix = ''): string {
  return prefix + b64url(randomBytes(12));
}

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const d = typeof data === 'string' ? enc.encode(data) : data;
  return hex(await crypto.subtle.digest('SHA-256', d));
}

export async function hmacHex(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

/** Constant-time string comparison (length is not secret here). */
export function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  let diff = ab.length ^ bb.length;
  const n = Math.max(ab.length, bb.length);
  for (let i = 0; i < n; i++) diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  return diff === 0;
}

// ---------------- AES-256-GCM ----------------

export interface EncryptedBlob {
  ciphertext: string; // base64
  iv: string; // base64 (12 bytes)
  keyVersion: number;
}

export class KeyRing {
  private keys = new Map<number, Promise<CryptoKey>>();
  readonly currentVersion: number;

  constructor(current: string, currentVersion = 1, previous?: string) {
    if (!current) throw new Error('ENCRYPTION_KEY is not configured');
    this.currentVersion = currentVersion;
    this.keys.set(currentVersion, importAesKey(current));
    if (previous) {
      const m = /^v(\d+):(.+)$/.exec(previous.trim());
      if (m) this.keys.set(Number(m[1]), importAesKey(m[2]));
    }
  }

  static fromEnv(env: { ENCRYPTION_KEY: string; ENCRYPTION_KEY_VERSION?: string; ENCRYPTION_KEY_PREVIOUS?: string }): KeyRing {
    return new KeyRing(env.ENCRYPTION_KEY, Number(env.ENCRYPTION_KEY_VERSION || '1'), env.ENCRYPTION_KEY_PREVIOUS);
  }

  async encrypt(plaintext: string, aad: string): Promise<EncryptedBlob> {
    const key = await this.keys.get(this.currentVersion)!;
    const iv = randomBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, enc.encode(plaintext));
    return { ciphertext: b64encode(ct), iv: b64encode(iv), keyVersion: this.currentVersion };
  }

  async decrypt(blob: EncryptedBlob, aad: string): Promise<string> {
    const kp = this.keys.get(blob.keyVersion);
    if (!kp) throw new Error(`No encryption key available for key version ${blob.keyVersion}`);
    const key = await kp;
    try {
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64decode(blob.iv), additionalData: enc.encode(aad) },
        key,
        b64decode(blob.ciphertext),
      );
      return dec.decode(pt);
    } catch {
      throw new Error('Credential decryption failed (wrong key or tampered data)');
    }
  }
}

/**
 * ENCRYPTION_KEY accepts two formats:
 *  1. the original one: base64 of exactly 32 random bytes -> used as the raw AES-256 key, byte for byte
 *     (unchanged behaviour, so existing deployments keep decrypting their data);
 *  2. any other value of >= 32 characters (a long passphrase typed in a deploy form, e.g. on a phone)
 *     -> a 256-bit key is derived with HKDF-SHA256 and a fixed, domain-separated salt.
 * Anything else (missing, short, trivially weak) is rejected with a clear error.
 */
export const MIN_SECRET_LENGTH = 32;
const ENC_KEY_SALT = enc.encode('cf-ssh-mcp/v1/encryption-key-salt');
const ENC_KEY_INFO = enc.encode('cf-ssh-mcp/v1/aes-256-gcm credential key');

/** Returns the 32 raw key bytes when the value is in the original base64-of-32-bytes format, else null. */
export function legacyRawKey(value: string): Uint8Array | null {
  try {
    const raw = b64decode(value.trim());
    return raw.length === 32 ? raw : null;
  } catch {
    return null;
  }
}

/** null when the value is acceptable as a passphrase-style secret, else a short reason code. */
export function passphraseProblem(value: string | undefined | null): 'missing' | 'too_short' | 'too_weak' | null {
  const v = (value ?? '').trim();
  if (!v) return 'missing';
  if (v.length < MIN_SECRET_LENGTH) return 'too_short';
  if (new Set(v).size < 6) return 'too_weak';
  return null;
}

/** Why an ENCRYPTION_KEY value is unusable (null = usable). */
export function encryptionKeyProblem(value: string | undefined | null): 'missing' | 'too_short' | 'too_weak' | null {
  if (value && legacyRawKey(value)) return null;
  return passphraseProblem(value);
}

export async function deriveEncryptionKeyBytes(passphrase: string): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey('raw', enc.encode(passphrase.trim()), 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: ENC_KEY_SALT, info: ENC_KEY_INFO }, ikm, 256));
}

export async function encryptionKeyBytes(value: string): Promise<Uint8Array> {
  const legacy = legacyRawKey(value);
  if (legacy) return legacy;
  const p = encryptionKeyProblem(value);
  if (p) throw new Error(p === 'missing' ? 'ENCRYPTION_KEY is not configured' : `ENCRYPTION_KEY is ${p.replace('_', ' ')} (use at least ${MIN_SECRET_LENGTH} characters)`);
  return deriveEncryptionKeyBytes(value);
}

async function importAesKey(value: string): Promise<CryptoKey> {
  const raw = await encryptionKeyBytes(value);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ---------------- PBKDF2 password hashing ----------------
// Workers' WebCrypto caps PBKDF2 at 100,000 iterations.
export const PBKDF2_ITERATIONS = 100_000;

export async function hashPassword(password: string, iterations = PBKDF2_ITERATIONS): Promise<string> {
  const salt = randomBytes(16);
  const bits = await pbkdf2(password, salt, iterations);
  return `pbkdf2$sha256$${iterations}$${b64encode(salt)}$${b64encode(bits)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 5 || parts[0] !== 'pbkdf2' || parts[1] !== 'sha256') return false;
  const iterations = Number(parts[2]);
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > PBKDF2_ITERATIONS) return false;
  const salt = b64decode(parts[3]);
  const expected = parts[4];
  const bits = await pbkdf2(password, salt, iterations);
  return timingSafeEqualStr(b64encode(bits), expected);
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
}
