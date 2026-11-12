import { describe, expect, it } from 'vitest';
import { classifyIP, isValidHost, resolveAndCheckTarget } from '../../src/lib/ssrf';
import { serverCreateSchema, serverUpdateSchema, settingsSchema } from '../../src/lib/validation';
import { generateKeyPairSync } from 'node:crypto';
import { verifyAccessJwt, _resetJwksCacheForTests } from '../../src/lib/auth';

describe('SSRF IP classification', () => {
  it.each([
    ['127.0.0.1', 'loopback'], ['10.1.2.3', 'private'], ['172.16.0.1', 'private'], ['172.31.255.255', 'private'], ['192.168.1.1', 'private'],
    ['169.254.169.254', 'metadata'], ['100.64.0.1', 'NAT'], ['0.0.0.0', 'this-network'], ['224.0.0.1', 'multicast'],
    ['::1', 'loopback'], ['::', 'unspecified'], ['fe80::1', 'link-local'], ['fd00::1', 'unique local'], ['::ffff:127.0.0.1', 'IPv4-mapped'], ['::ffff:10.0.0.1', 'IPv4-mapped'],
    ['64:ff9b::a9fe:a9fe', 'NAT64'], ['fd00:ec2::254', 'unique local'],
  ])('blocks %s', (ip, frag) => {
    const r = classifyIP(ip);
    expect(r).toBeTruthy();
    expect(r!.toLowerCase()).toContain(frag.toLowerCase());
  });
  it.each(['8.8.8.8', '1.1.1.1', '172.32.0.1', '2606:4700:4700::1111', '203.0.114.1'])('allows public %s', (ip) => expect(classifyIP(ip)).toBeNull());

  it('rejects private targets unless allowed', async () => {
    await expect(resolveAndCheckTarget('127.0.0.1', false)).rejects.toThrow(/blocked/);
    await expect(resolveAndCheckTarget('169.254.169.254', false)).rejects.toThrow(/metadata/);
    expect((await resolveAndCheckTarget('127.0.0.1', true)).connectHost).toBe('127.0.0.1');
    await expect(resolveAndCheckTarget('localhost', false)).rejects.toThrow(/internal name/);
    await expect(resolveAndCheckTarget('metadata.google.internal', false)).rejects.toThrow();
  });
  it('blocks hostnames that resolve to private addresses and pins the validated IP', async () => {
    const evil = async () => ['93.184.216.34', '10.0.0.5'];
    await expect(resolveAndCheckTarget('rebind.example.com', false, evil)).rejects.toThrow(/10\.0\.0\.5/);
    const good = async () => ['2606:4700::1', '93.184.216.34'];
    const r = await resolveAndCheckTarget('example.com', false, good);
    expect(r.connectHost).toBe('93.184.216.34'); // connect to the checked IP, never re-resolve
    await expect(resolveAndCheckTarget('nx.example.com', false, async () => [])).rejects.toThrow(/did not resolve/);
  });
  it('validates host syntax', () => {
    expect(isValidHost('example.com')).toBe(true);
    expect(isValidHost('1.2.3.4')).toBe(true);
    expect(isValidHost('[2001:db8::1]')).toBe(true);
    expect(isValidHost('exa mple.com')).toBe(false);
    expect(isValidHost('http://example.com')).toBe(false);
    expect(isValidHost('-bad.com')).toBe(false);
  });
});

describe('input validation (zod)', () => {
  const base = { name: 'web', host: 'example.com', port: 22, username: 'deploy', auth_method: 'password', password: 'pw' };
  it('accepts a valid server', () => expect(serverCreateSchema.safeParse(base).success).toBe(true));
  it('requires password / key for the auth method', () => {
    expect(serverCreateSchema.safeParse({ ...base, password: undefined }).success).toBe(false);
    expect(serverCreateSchema.safeParse({ ...base, auth_method: 'key', password: undefined }).success).toBe(false);
    expect(serverCreateSchema.safeParse({ ...base, auth_method: 'key', private_key: 'not a key' }).success).toBe(false);
  });
  it('requires explicit allow_root for root', () => {
    expect(serverCreateSchema.safeParse({ ...base, username: 'root' }).success).toBe(false);
    expect(serverCreateSchema.safeParse({ ...base, username: 'root', allow_root: true }).success).toBe(true);
  });
  it('rejects bad hosts, ports, usernames, fingerprints, labels', () => {
    expect(serverCreateSchema.safeParse({ ...base, host: 'a b' }).success).toBe(false);
    expect(serverCreateSchema.safeParse({ ...base, port: 70000 }).success).toBe(false);
    expect(serverCreateSchema.safeParse({ ...base, username: 'a;rm' }).success).toBe(false);
    expect(serverCreateSchema.safeParse({ ...base, host_key_fingerprint: 'MD5:aa' }).success).toBe(false);
    expect(serverCreateSchema.safeParse({ ...base, host_key_fingerprint: 'SHA256:' + 'A'.repeat(43) }).success).toBe(true);
    expect(serverCreateSchema.safeParse({ ...base, labels: ['ok', 'bad label'] }).success).toBe(false);
  });
  it('partial updates do not inject defaults (regression: PATCH reset port/labels)', () => {
    const r = serverUpdateSchema.parse({ policy_mode: 'read_only' });
    expect(r).toEqual({ policy_mode: 'read_only' });
  });
  it('update schema is strict', () => {
    expect(serverUpdateSchema.safeParse({ name: 'x', evil: 1 }).success).toBe(false);
    expect(settingsSchema.safeParse({ idle_timeout_seconds: 5 }).success).toBe(false);
  });
});

describe('Cloudflare Access JWT verification', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
  const env = { ACCESS_TEAM_DOMAIN: 'team.cloudflareaccess.com', ACCESS_AUD: 'aud123' };
  const fetcher = async () => ({ keys: [{ kid: 'k1', kty: 'RSA', n: jwk.n, e: jwk.e }] });
  async function sign(payload: object, kid = 'k1') {
    const { createSign } = await import('node:crypto');
    const b = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const data = `${b({ alg: 'RS256', kid })}.${b(payload)}`;
    const sig = createSign('RSA-SHA256').update(data).sign(privateKey).toString('base64url');
    return `${data}.${sig}`;
  }
  const req = (jwt: string) => new Request('https://x/', { headers: { 'cf-access-jwt-assertion': jwt } });
  const now = Math.floor(Date.now() / 1000);
  const good = { aud: ['aud123'], iss: 'https://team.cloudflareaccess.com', exp: now + 600, email: 'a@b.c' };
  it('accepts a valid token', async () => {
    _resetJwksCacheForTests();
    expect(await verifyAccessJwt(env, req(await sign(good)), fetcher)).toEqual({ email: 'a@b.c' });
  });
  it('rejects wrong aud / issuer / expired / bad signature / unknown kid', async () => {
    _resetJwksCacheForTests();
    expect(await verifyAccessJwt(env, req(await sign({ ...good, aud: ['other'] })), fetcher)).toBeNull();
    expect(await verifyAccessJwt(env, req(await sign({ ...good, iss: 'https://evil.com' })), fetcher)).toBeNull();
    expect(await verifyAccessJwt(env, req(await sign({ ...good, exp: now - 10 })), fetcher)).toBeNull();
    const t = await sign(good);
    expect(await verifyAccessJwt(env, req(t.slice(0, -4) + 'AAAA'), fetcher)).toBeNull();
    expect(await verifyAccessJwt(env, req(await sign(good, 'nope')), fetcher)).toBeNull();
    expect(await verifyAccessJwt(env, new Request('https://x/'), fetcher)).toBeNull();
  });
});
