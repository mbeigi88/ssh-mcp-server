import { describe, expect, it } from 'vitest';
import { KeyRing, hashPassword, verifyPassword, b64encode, randomBytes, timingSafeEqualStr, encryptionKeyBytes, encryptionKeyProblem, legacyRawKey } from '../../src/lib/crypto';
import { configIssues } from '../../src/lib/config';
import { passwordProblem, setupTokenProblem } from '../../src/lib/setup';
import { redact } from '../../src/lib/db';

const key = b64encode(randomBytes(32));
const KDF_VECTOR = 'f544b02c13601622feeb5591fdc9080f8852b47f47e141b2c7eb7326ec499e65'; // HKDF-SHA256 computed independently with node:crypto hkdfSync

describe('AES-256-GCM credential encryption', () => {
  it('round-trips with AAD', async () => {
    const ring = new KeyRing(key, 1);
    const blob = await ring.encrypt('{"password":"s3cr3t"}', 'server:abc');
    expect(blob.ciphertext).not.toContain('s3cr3t');
    expect(blob.keyVersion).toBe(1);
    expect(await ring.decrypt(blob, 'server:abc')).toBe('{"password":"s3cr3t"}');
  });
  it('uses a fresh IV each time', async () => {
    const ring = new KeyRing(key, 1);
    const a = await ring.encrypt('x', 'a');
    const b = await ring.encrypt('x', 'a');
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });
  it('fails with wrong AAD (blob moved to another server)', async () => {
    const ring = new KeyRing(key, 1);
    const blob = await ring.encrypt('x', 'server:a');
    await expect(ring.decrypt(blob, 'server:b')).rejects.toThrow(/decryption failed/);
  });
  it('fails on tampered ciphertext', async () => {
    const ring = new KeyRing(key, 1);
    const blob = await ring.encrypt('hello world', 'a');
    const raw = Buffer.from(blob.ciphertext, 'base64');
    raw[0] ^= 1;
    await expect(ring.decrypt({ ...blob, ciphertext: raw.toString('base64') }, 'a')).rejects.toThrow(/decryption failed/);
  });
  it('fails with a different key', async () => {
    const blob = await new KeyRing(key, 1).encrypt('x', 'a');
    await expect(new KeyRing(b64encode(randomBytes(32)), 1).decrypt(blob, 'a')).rejects.toThrow();
  });
  it('supports key rotation via previous key', async () => {
    const old = b64encode(randomBytes(32));
    const blob = await new KeyRing(old, 1).encrypt('legacy', 'a');
    const ring = new KeyRing(key, 2, `v1:${old}`);
    expect(await ring.decrypt(blob, 'a')).toBe('legacy');
    expect((await ring.encrypt('new', 'a')).keyVersion).toBe(2);
  });
  it('rejects malformed keys', async () => {
    await expect(new KeyRing(b64encode(randomBytes(16)), 1).encrypt('x', 'a')).rejects.toThrow(/too short/);
    expect(() => new KeyRing('', 1)).toThrow(/not configured/);
  });
});

describe('PBKDF2 password hashing', () => {
  it('verifies correct and rejects wrong passwords', async () => {
    const h = await hashPassword('correct horse battery staple', 1000);
    expect(h).toMatch(/^pbkdf2\$sha256\$1000\$/);
    expect(await verifyPassword('correct horse battery staple', h)).toBe(true);
    expect(await verifyPassword('wrong', h)).toBe(false);
  });
  it('rejects malformed hashes and over-limit iteration counts', async () => {
    expect(await verifyPassword('x', 'plain')).toBe(false);
    expect(await verifyPassword('x', 'pbkdf2$sha256$999999$AAAA$AAAA')).toBe(false);
  });
  it('timingSafeEqualStr', () => {
    expect(timingSafeEqualStr('abc', 'abc')).toBe(true);
    expect(timingSafeEqualStr('abc', 'abd')).toBe(false);
    expect(timingSafeEqualStr('abc', 'abcd')).toBe(false);
  });
});

describe('redaction', () => {
  it('removes secrets from audit details', () => {
    const r = redact({ password: 'x', nested: { private_key: 'y', host: 'h' }, note: '-----BEGIN OPENSSH PRIVATE KEY-----abc', token: 't' }) as Record<string, unknown>;
    expect(JSON.stringify(r)).not.toMatch(/"x"|"y"|"t"|BEGIN/);
    expect((r.nested as Record<string, unknown>).host).toBe('h');
  });
});

describe('ENCRYPTION_KEY formats (backward compatible)', () => {
  it('uses a v1 base64-of-32-bytes key verbatim', async () => {
    const raw = randomBytes(32);
    const v1 = b64encode(raw);
    expect(Array.from(await encryptionKeyBytes(v1))).toEqual(Array.from(raw));
    expect(Array.from(await encryptionKeyBytes(v1 + '\n'))).toEqual(Array.from(raw)); // trimmed like v1
    expect(legacyRawKey(v1)).not.toBeNull();
  });
  it('decrypts data written by the v1 implementation (raw AES key import)', async () => {
    const raw = randomBytes(32);
    const v1Key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = randomBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('server:s1') }, v1Key, new TextEncoder().encode('{"password":"old"}'));
    const ring = new KeyRing(b64encode(raw), 1);
    expect(await ring.decrypt({ ciphertext: b64encode(ct), iv: b64encode(iv), keyVersion: 1 }, 'server:s1')).toBe('{"password":"old"}');
  });
  it('derives a stable 32-byte key from a long passphrase (HKDF, domain separated)', async () => {
    const pp = 'six random words make a fine passphrase here';
    const a = await encryptionKeyBytes(pp);
    const b = await encryptionKeyBytes(pp);
    expect(a.length).toBe(32);
    expect(Array.from(a)).toEqual(Array.from(b));
    expect(Array.from(await encryptionKeyBytes(pp + 'x'))).not.toEqual(Array.from(a));
    // fixed test vector: guards against accidental changes of salt/info, which would orphan stored data
    expect(Buffer.from(a).toString('hex')).toBe(KDF_VECTOR);
    const ring = new KeyRing(pp, 1);
    const blob = await ring.encrypt('hello', 'server:x');
    expect(await new KeyRing(pp, 1).decrypt(blob, 'server:x')).toBe('hello');
  });
  it('supports a passphrase as the previous key during rotation', async () => {
    const oldPp = 'the old passphrase that we used before rotation';
    const blob = await new KeyRing(oldPp, 1).encrypt('x', 'a');
    const ring = new KeyRing(b64encode(randomBytes(32)), 2, `v1:${oldPp}`);
    expect(await ring.decrypt(blob, 'a')).toBe('x');
  });
  it('rejects missing, short and trivially weak values with a reason', async () => {
    expect(encryptionKeyProblem(undefined)).toBe('missing');
    expect(encryptionKeyProblem('short passphrase')).toBe('too_short');
    expect(encryptionKeyProblem('a'.repeat(40))).toBe('too_weak');
    await expect(encryptionKeyBytes('short')).rejects.toThrow(/too short/);
  });
});

describe('config checks', () => {
  const good = { ENCRYPTION_KEY: b64encode(randomBytes(32)), SESSION_SECRET: 'x'.repeat(10) + 'abcdefghijklmnopqrstuvwxyz' };
  it('accepts v1 secrets and passphrases', () => {
    expect(configIssues(good)).toEqual([]);
    expect(configIssues({ ENCRYPTION_KEY: 'correct horse battery staple and more words', SESSION_SECRET: 'yet another passphrase of decent length' })).toEqual([]);
  });
  it('reports each problem by name', () => {
    expect(configIssues({ ...good, SESSION_SECRET: 'short' })).toEqual([{ name: 'SESSION_SECRET', problem: 'too_short' }]);
    expect(configIssues({ ...good, SESSION_SECRET: 'z'.repeat(64) })).toEqual([{ name: 'SESSION_SECRET', problem: 'too_weak' }]);
    expect(configIssues({ SESSION_SECRET: good.SESSION_SECRET })).toEqual([{ name: 'ENCRYPTION_KEY', problem: 'missing' }]);
    expect(configIssues({ ...good, ENCRYPTION_KEY_PREVIOUS: 'garbage' })).toEqual([{ name: 'ENCRYPTION_KEY_PREVIOUS', problem: 'invalid_format' }]);
  });
  it('setup token and admin password rules', () => {
    expect(setupTokenProblem(undefined)).toBe('missing');
    expect(setupTokenProblem('elevenchars')).toBe('too_short');
    expect(setupTokenProblem('aaaaaaaaaaaaaaaa')).toBe('too_weak');
    expect(setupTokenProblem('my setup token 42')).toBeNull();
    const env = { SETUP_TOKEN: 'my setup token 42' } as never;
    expect(passwordProblem('short', env)).toMatch(/12/);
    expect(passwordProblem('bbbbbbbbbbbbbbbb', env)).toMatch(/simple/);
    expect(passwordProblem('my setup token 42', env)).toMatch(/different/);
    expect(passwordProblem('a fine admin password', env)).toBeNull();
  });
});
