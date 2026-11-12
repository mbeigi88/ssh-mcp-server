// Thin, promise-based wrapper around ssh2 (patched for workerd) running over
// cloudflare:sockets. Only Worker-safe algorithms are offered (see README "Limits").
import './crypto-polyfill';
import { Client, utils, type ClientChannel, type SFTPWrapper } from 'ssh2';
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { openTcpDuplex } from './socket-bridge';

export const ALGORITHMS = {
  kex: [
    'curve25519-sha256',
    'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp256',
    'ecdh-sha2-nistp384',
    'ecdh-sha2-nistp521',
    'diffie-hellman-group16-sha512',
    'diffie-hellman-group14-sha256',
  ],
  // AES-GCM is NOT offered: workerd's node:crypto rejects ssh2's decipher call order
  // (update() before setAuthTag()) with "No auth tag provided". chacha20-poly1305 needs a WASM
  // module that workerd cannot compile at runtime. AES-CTR + HMAC-SHA2 (ETM preferred) is used.
  cipher: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr'],
  hmac: ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512'],
  serverHostKey: ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256'],
  compress: ['none'],
} as const;

export type SshErrorCode =
  | 'HOSTKEY_UNKNOWN'
  | 'HOSTKEY_MISMATCH'
  | 'AUTH_FAILED'
  | 'KEY_INVALID'
  | 'CONNECT_FAILED'
  | 'TIMEOUT'
  | 'DISCONNECTED'
  | 'PROTOCOL';

export class SshError extends Error {
  code: SshErrorCode;
  fingerprint?: string;
  algo?: string;
  constructor(code: SshErrorCode, message: string, extra?: { fingerprint?: string; algo?: string }) {
    super(message);
    this.name = 'SshError';
    this.code = code;
    this.fingerprint = extra?.fingerprint;
    this.algo = extra?.algo;
  }
}

export function fingerprintOf(keyBlob: Buffer): string {
  return 'SHA256:' + createHash('sha256').update(keyBlob).digest('base64').replace(/=+$/, '');
}
export function keyAlgoOf(keyBlob: Buffer): string {
  if (keyBlob.length < 4) return 'unknown';
  const len = keyBlob.readUInt32BE(0);
  return keyBlob.subarray(4, 4 + Math.min(len, 64)).toString('latin1');
}

export interface ConnectOptions {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
  passphrase?: string;
  /** Approved fingerprint; null => TOFU capture (connection is refused until approved). */
  expectedFingerprint: string | null;
  readyTimeoutMs: number;
  keepaliveIntervalMs?: number;
}

export interface Connected {
  client: Client;
  fingerprint: string;
  algo: string;
}

/** Validates / decrypts a private key up front so the user gets a precise error. */
export function checkPrivateKey(privateKey: string, passphrase?: string): void {
  const parsed = utils.parseKey(privateKey, passphrase);
  if (parsed instanceof Error) {
    const msg = parsed.message;
    if (/encrypted/i.test(msg) && !passphrase) throw new SshError('KEY_INVALID', 'private key is encrypted: a passphrase is required');
    if (/bad decrypt|integrity|passphrase|Invalid key/i.test(msg) && passphrase) throw new SshError('KEY_INVALID', 'could not decrypt private key: wrong passphrase?');
    throw new SshError('KEY_INVALID', `invalid private key: ${msg}`);
  }
  const key = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!key || !key.isPrivateKey()) throw new SshError('KEY_INVALID', 'the supplied key is not a private key');
}

export async function connectSsh(o: ConnectOptions): Promise<Connected> {
  if (o.privateKey) checkPrivateKey(o.privateKey, o.passphrase);

  const deadline = Date.now() + o.readyTimeoutMs;
  let sock;
  try {
    sock = await openTcpDuplex({ hostname: o.host, port: o.port, connectTimeoutMs: o.readyTimeoutMs });
  } catch (e) {
    const msg = (e as Error).message || String(e);
    if (/timeout/i.test(msg)) throw new SshError('TIMEOUT', `TCP connection to ${o.host}:${o.port} timed out`);
    throw new SshError('CONNECT_FAILED', `TCP connection to ${o.host}:${o.port} failed: ${msg}`);
  }

  const client = new Client();
  let seenFp = '';
  let seenAlgo = '';
  let hostKeyFailure: SshError | null = null;

  return new Promise<Connected>((resolve, reject) => {
    let settled = false;
    const finish = (err: Error | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) {
        try { client.end(); } catch { /* ignore */ }
        try { sock.destroy(); } catch { /* ignore */ }
        reject(err);
      } else {
        resolve({ client, fingerprint: seenFp, algo: seenAlgo });
      }
    };
    const timer = setTimeout(
      () => finish(new SshError('TIMEOUT', `SSH handshake/authentication timed out after ${o.readyTimeoutMs}ms`)),
      Math.max(1000, deadline - Date.now()),
    );

    client.on('ready', () => finish(null));
    client.on('error', (err: Error & { level?: string }) => {
      if (hostKeyFailure) return finish(hostKeyFailure);
      const msg = err.message || String(err);
      if (err.level === 'client-authentication' || /All configured authentication methods failed/i.test(msg)) {
        return finish(new SshError('AUTH_FAILED', 'authentication failed (wrong username, password or key)'));
      }
      if (/timed out/i.test(msg)) return finish(new SshError('TIMEOUT', msg));
      if (/handshake|no matching/i.test(msg)) return finish(new SshError('PROTOCOL', `SSH negotiation failed: ${msg}`));
      finish(new SshError('CONNECT_FAILED', msg));
    });
    client.on('close', () => finish(hostKeyFailure ?? new SshError('DISCONNECTED', 'connection closed before authentication completed')));

    try {
      client.connect({
        sock: sock as never,
        username: o.username,
        password: o.password,
        privateKey: o.privateKey,
        passphrase: o.passphrase,
        tryKeyboard: false,
        readyTimeout: o.readyTimeoutMs,
        keepaliveInterval: o.keepaliveIntervalMs ?? 15000,
        keepaliveCountMax: 3,
        algorithms: {
          kex: [...ALGORITHMS.kex] as never,
          cipher: [...ALGORITHMS.cipher] as never,
          hmac: [...ALGORITHMS.hmac] as never,
          serverHostKey: [...ALGORITHMS.serverHostKey] as never,
          compress: [...ALGORITHMS.compress] as never,
        },
        hostVerifier: (key: Buffer) => {
          seenFp = fingerprintOf(key);
          seenAlgo = keyAlgoOf(key);
          if (!o.expectedFingerprint) {
            hostKeyFailure = new SshError(
              'HOSTKEY_UNKNOWN',
              `host key ${seenAlgo} ${seenFp} is not yet trusted; approve this fingerprint in the dashboard after verifying it on the server (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub)`,
              { fingerprint: seenFp, algo: seenAlgo },
            );
            return false;
          }
          if (o.expectedFingerprint !== seenFp) {
            hostKeyFailure = new SshError(
              'HOSTKEY_MISMATCH',
              `HOST KEY MISMATCH: expected ${o.expectedFingerprint} but server presented ${seenAlgo} ${seenFp}. Possible man-in-the-middle attack or the server was reinstalled. Connection refused.`,
              { fingerprint: seenFp, algo: seenAlgo },
            );
            return false;
          }
          return true;
        },
      });
    } catch (e) {
      finish(new SshError('CONNECT_FAILED', (e as Error).message));
    }
  });
}

// ---------------------------------------------------------------- exec

export interface ExecOptions {
  timeoutMs: number;
  maxBytes: number;
  onStdout?: (chunk: Buffer) => void;
  onStderr?: (chunk: Buffer) => void;
}

export interface ExecResult {
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  stdoutBytes: number;
  stderrBytes: number;
  timedOut: boolean;
  cancelled: boolean;
  durationMs: number;
}

export interface RunningExec {
  done: Promise<ExecResult>;
  cancel: (reason?: 'cancel' | 'timeout') => void;
}

class BoundedBuffer {
  private chunks: Buffer[] = [];
  size = 0;
  total = 0;
  constructor(private max: number) {}
  push(b: Buffer) {
    this.total += b.length;
    if (this.size >= this.max) return;
    const take = Math.min(b.length, this.max - this.size);
    this.chunks.push(take === b.length ? b : b.subarray(0, take));
    this.size += take;
  }
  get truncated() { return this.total > this.size; }
  toString() { return Buffer.concat(this.chunks).toString('utf8'); }
}

export function startExec(client: Client, command: string, o: ExecOptions): Promise<RunningExec> {
  return new Promise((resolveStart, rejectStart) => {
    const started = Date.now();
    client.exec(command, (err, ch: ClientChannel) => {
      if (err) return rejectStart(new SshError('PROTOCOL', `could not open exec channel: ${err.message}`));
      const out = new BoundedBuffer(o.maxBytes);
      const errb = new BoundedBuffer(o.maxBytes);
      let exitCode: number | null = null;
      let signal: string | null = null;
      let timedOut = false;
      let cancelled = false;
      let resolveDone!: (r: ExecResult) => void;
      const done = new Promise<ExecResult>((r) => (resolveDone = r));
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        resolveDone({
          exitCode, signal,
          stdout: out.toString(), stderr: errb.toString(),
          stdoutTruncated: out.truncated, stderrTruncated: errb.truncated,
          stdoutBytes: out.total, stderrBytes: errb.total,
          timedOut, cancelled, durationMs: Date.now() - started,
        });
      };
      const cancel = (reason: 'cancel' | 'timeout' = 'cancel') => {
        if (finished) return;
        if (reason === 'timeout') timedOut = true; else cancelled = true;
        try { ch.signal('TERM'); } catch { /* ignore */ }
        try { ch.signal('KILL'); } catch { /* ignore */ }
        try { ch.close(); } catch { /* ignore */ }
        // if the server never confirms the close, resolve anyway
        setTimeout(finish, 2000);
      };
      const timer = setTimeout(() => cancel('timeout'), o.timeoutMs);
      ch.on('data', (d: Buffer) => { out.push(d); o.onStdout?.(d); });
      ch.stderr.on('data', (d: Buffer) => { errb.push(d); o.onStderr?.(d); });
      ch.on('exit', (code: number | null, sig?: string) => {
        if (typeof code === 'number') exitCode = code;
        if (sig) signal = sig;
      });
      ch.on('close', finish);
      ch.on('error', finish);
      resolveStart({ done, cancel });
    });
  });
}

// ---------------------------------------------------------------- SFTP

export function openSftp(client: Client): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => client.sftp((err, s) => (err ? reject(new SshError('PROTOCOL', `SFTP subsystem unavailable: ${err.message}`)) : resolve(s))));
}

export interface DirEntry {
  name: string;
  type: 'file' | 'directory' | 'symlink' | 'other';
  size: number;
  mode: string;
  mtime: number;
  uid: number;
  gid: number;
  longname?: string;
}

function typeOf(mode: number): DirEntry['type'] {
  const t = mode & 0o170000;
  if (t === 0o040000) return 'directory';
  if (t === 0o100000) return 'file';
  if (t === 0o120000) return 'symlink';
  return 'other';
}
export function modeString(mode: number): string {
  return '0' + (mode & 0o7777).toString(8);
}

const p = <T>(fn: (cb: (err: Error | null | undefined, v?: T) => void) => void): Promise<T> =>
  new Promise((res, rej) => fn((err, v) => (err ? rej(sftpErr(err)) : res(v as T))));

function sftpErr(err: Error & { code?: number }): Error {
  const map: Record<number, string> = { 2: 'no such file or directory', 3: 'permission denied', 4: 'failure', 8: 'operation unsupported' };
  return new Error(err.code && map[err.code] ? `${map[err.code]} (${err.message})` : err.message);
}

export const sftpOps = {
  async list(s: SFTPWrapper, path: string): Promise<DirEntry[]> {
    const list = await p<Array<{ filename: string; longname: string; attrs: { mode: number; size: number; mtime: number; uid: number; gid: number } }>>((cb) => s.readdir(path, cb as never));
    return list
      .map((e) => ({ name: e.filename, type: typeOf(e.attrs.mode), size: e.attrs.size, mode: modeString(e.attrs.mode), mtime: e.attrs.mtime, uid: e.attrs.uid, gid: e.attrs.gid, longname: e.longname }))
      .sort((a, b) => (a.type === 'directory' ? 0 : 1) - (b.type === 'directory' ? 0 : 1) || a.name.localeCompare(b.name));
  },
  async stat(s: SFTPWrapper, path: string) {
    const st = await p<{ mode: number; size: number; mtime: number; atime: number; uid: number; gid: number }>((cb) => s.lstat(path, cb as never));
    return { path, type: typeOf(st.mode), size: st.size, mode: modeString(st.mode), mtime: st.mtime, atime: st.atime, uid: st.uid, gid: st.gid };
  },
  async realpath(s: SFTPWrapper, path: string): Promise<string> {
    return p<string>((cb) => s.realpath(path, cb as never));
  },
  async mkdir(s: SFTPWrapper, path: string) {
    await p((cb) => s.mkdir(path, cb as never));
  },
  async rename(s: SFTPWrapper, from: string, to: string) {
    await p((cb) => s.rename(from, to, cb as never));
  },
  async unlink(s: SFTPWrapper, path: string) {
    await p((cb) => s.unlink(path, cb as never));
  },
  async rmdir(s: SFTPWrapper, path: string) {
    await p((cb) => s.rmdir(path, cb as never));
  },
  /** Reads [offset, offset+length) — bounded memory. */
  async read(s: SFTPWrapper, path: string, offset: number, length: number): Promise<{ data: Buffer; eof: boolean; size: number }> {
    const st = await p<{ size: number; mode: number }>((cb) => s.stat(path, cb as never));
    if (typeOf(st.mode) === 'directory') throw new Error('path is a directory');
    const handle = await p<Buffer>((cb) => s.open(path, 'r', cb as never));
    try {
      const want = Math.max(0, Math.min(length, st.size - offset));
      const buf = Buffer.alloc(want);
      let got = 0;
      while (got < want) {
        const n = await new Promise<number>((res, rej) =>
          s.read(handle, buf, got, Math.min(32768, want - got), offset + got, (err, bytesRead) => (err ? rej(sftpErr(err)) : res(bytesRead))),
        );
        if (n === 0) break;
        got += n;
      }
      return { data: buf.subarray(0, got), eof: offset + got >= st.size, size: st.size };
    } finally {
      await p((cb) => s.close(handle, cb as never)).catch(() => {});
    }
  },
  /** Writes data at offset. mode 'truncate' creates/truncates, 'append-at' opens for writing at offset. */
  async write(s: SFTPWrapper, path: string, data: Buffer, offset: number, truncate: boolean): Promise<number> {
    const handle = await p<Buffer>((cb) => s.open(path, truncate ? 'w' : 'r+', cb as never));
    try {
      let written = 0;
      while (written < data.length) {
        const n = Math.min(32768, data.length - written);
        await new Promise<void>((res, rej) => s.write(handle, data, written, n, offset + written, (err) => (err ? rej(sftpErr(err)) : res())));
        written += n;
      }
      return written;
    } finally {
      await p((cb) => s.close(handle, cb as never)).catch(() => {});
    }
  },
};
