// One Durable Object per configured server. It owns the live SSH connection (and its SFTP
// channel), serializes connection setup, enforces host-key trust, tracks running commands
// for cancellation, and disconnects after an idle timeout (alarm).
import { DurableObject } from 'cloudflare:workers';
import { Buffer } from 'node:buffer';
import type { Client, SFTPWrapper } from 'ssh2';
import type { Env } from '../env';
import { connectSsh, openSftp, sftpOps, SshError, startExec, type DirEntry, type ExecResult, type RunningExec } from '../ssh/client';
import { allowPrivateTargets, audit, decryptCredentials, getServer, getSettings, recordConnectionEvent, type ServerRow } from '../lib/db';
import { resolveAndCheckTarget, TargetBlockedError } from '../lib/ssrf';
import { randomId } from '../lib/crypto';

export interface ConnectResult {
  ok: boolean;
  code?: string;
  message?: string;
  fingerprint?: string;
  algo?: string;
  reused?: boolean;
}

export interface ExecRequest {
  serverId: string;
  command: string;
  timeoutMs: number;
  maxBytes: number;
  actor: string;
  classification: string;
  resultId?: string;
}

export interface StoredExecResult extends ExecResult {
  id: string;
  status: 'completed' | 'failed' | 'timeout' | 'cancelled';
  error?: string;
}

type Status = { connected: boolean; connectedAt: number | null; lastActivity: number | null; running: string[]; fingerprint: string | null };

export class SshSession extends DurableObject<Env> {
  private client: Client | null = null;
  private sftp: SFTPWrapper | null = null;
  private serverId: string | null = null;
  private connectedAt: number | null = null;
  private lastActivity: number | null = null;
  private fingerprint: string | null = null;
  private connecting: Promise<ConnectResult> | null = null;
  private running = new Map<string, RunningExec>();

  // ------------------------------------------------------------- lifecycle

  status(): Status {
    return { connected: !!this.client, connectedAt: this.connectedAt, lastActivity: this.lastActivity, running: [...this.running.keys()], fingerprint: this.fingerprint };
  }

  async openSession(serverId: string): Promise<ConnectResult> {
    this.serverId = serverId;
    if (this.client) {
      this.touch();
      return { ok: true, reused: true, fingerprint: this.fingerprint ?? undefined };
    }
    if (!this.connecting) {
      this.connecting = this.doConnect(serverId).finally(() => { this.connecting = null; });
    }
    return this.connecting;
  }

  private async doConnect(serverId: string): Promise<ConnectResult> {
    const started = Date.now();
    const row = await getServer(this.env, serverId);
    if (!row) return { ok: false, code: 'NOT_FOUND', message: 'server not found' };
    if (row.username === 'root' && !row.allow_root) {
      return this.fail(row, 'POLICY', 'root login is disabled for this server (enable "allow root login" explicitly)', started);
    }
    const settings = await getSettings(this.env);
    let target;
    try {
      target = await resolveAndCheckTarget(row.host, allowPrivateTargets(this.env, settings));
    } catch (e) {
      const msg = e instanceof TargetBlockedError ? e.message : `target check failed: ${(e as Error).message}`;
      return this.fail(row, 'TARGET_BLOCKED', msg, started);
    }
    let creds;
    try {
      creds = await decryptCredentials(this.env, row);
    } catch (e) {
      return this.fail(row, 'CREDENTIALS', (e as Error).message, started);
    }
    try {
      const c = await connectSsh({
        host: target.connectHost,
        port: row.port,
        username: row.username,
        password: row.auth_method === 'password' ? creds.password : undefined,
        privateKey: row.auth_method === 'key' ? creds.privateKey : undefined,
        passphrase: row.auth_method === 'key' ? creds.passphrase : undefined,
        expectedFingerprint: row.host_key_fingerprint,
        readyTimeoutMs: 15000,
      });
      this.client = c.client;
      this.fingerprint = c.fingerprint;
      this.connectedAt = Date.now();
      this.touch();
      c.client.on('close', () => this.onClosed('closed by remote'));
      c.client.on('error', (err: Error) => this.onClosed(`connection error: ${err.message}`));
      await this.env.DB.prepare("UPDATE servers SET status = 'connected', last_error = NULL, last_connected_at = ?, host_key_algo = COALESCE(host_key_algo, ?) WHERE id = ?")
        .bind(this.connectedAt, c.algo, row.id)
        .run();
      await recordConnectionEvent(this.env, row.id, 'connect', `${row.username}@${row.host}:${row.port} ${c.algo}`, Date.now() - started);
      await this.scheduleIdleAlarm();
      return { ok: true, fingerprint: c.fingerprint, algo: c.algo };
    } catch (e) {
      const err = e instanceof SshError ? e : new SshError('CONNECT_FAILED', (e as Error).message);
      if (err.code === 'HOSTKEY_UNKNOWN') {
        await this.env.DB.prepare("UPDATE servers SET status = 'hostkey_pending', pending_fingerprint = ?, pending_fingerprint_algo = ?, last_error = ?, updated_at = ? WHERE id = ?")
          .bind(err.fingerprint ?? null, err.algo ?? null, err.message, Date.now(), row.id)
          .run();
        await recordConnectionEvent(this.env, row.id, 'hostkey_pending', `${err.algo} ${err.fingerprint}`);
        await audit(this.env, { actor: 'system', action: 'hostkey.pending', server_id: row.id, outcome: 'pending', detail: { fingerprint: err.fingerprint, algo: err.algo } });
        return { ok: false, code: err.code, message: err.message, fingerprint: err.fingerprint, algo: err.algo };
      }
      if (err.code === 'HOSTKEY_MISMATCH') {
        await audit(this.env, { actor: 'system', action: 'hostkey.mismatch', server_id: row.id, outcome: 'blocked', detail: { expected: row.host_key_fingerprint, presented: err.fingerprint, algo: err.algo } });
        const r = await this.fail(row, err.code, err.message, started, 'hostkey_mismatch');
        return { ...r, fingerprint: err.fingerprint, algo: err.algo };
      }
      return this.fail(row, err.code, err.message, started);
    }
  }

  private async fail(row: ServerRow, code: string, message: string, started: number, status = 'error'): Promise<ConnectResult> {
    await this.env.DB.prepare('UPDATE servers SET status = ?, last_error = ?, updated_at = ? WHERE id = ?').bind(status, message.slice(0, 1000), Date.now(), row.id).run();
    await recordConnectionEvent(this.env, row.id, code === 'HOSTKEY_MISMATCH' ? 'hostkey_mismatch' : 'error', `${code}: ${message}`, Date.now() - started);
    return { ok: false, code, message };
  }

  private onClosed(reason: string) {
    if (!this.client) return;
    const sid = this.serverId;
    this.client = null;
    this.sftp = null;
    this.connectedAt = null;
    for (const r of this.running.values()) r.cancel('cancel');
    this.running.clear();
    if (sid) {
      this.ctx.waitUntil(
        (async () => {
          await this.env.DB.prepare("UPDATE servers SET status = 'disconnected', last_error = CASE WHEN ? LIKE 'connection error%' THEN ? ELSE last_error END WHERE id = ?").bind(reason, reason, sid).run();
          await recordConnectionEvent(this.env, sid, 'disconnect', reason);
        })().catch(() => {}),
      );
    }
  }

  async disconnect(reason = 'manual disconnect'): Promise<{ ok: true }> {
    if (this.client) {
      const c = this.client;
      this.onClosed(reason);
      try { c.end(); } catch { /* ignore */ }
    }
    return { ok: true };
  }

  private touch() {
    this.lastActivity = Date.now();
  }

  private async scheduleIdleAlarm() {
    const s = await getSettings(this.env);
    await this.ctx.storage.setAlarm(Date.now() + s.idle_timeout_seconds * 1000);
  }

  async alarm(): Promise<void> {
    if (!this.client) return;
    const s = await getSettings(this.env);
    const idleMs = s.idle_timeout_seconds * 1000;
    const idleFor = Date.now() - (this.lastActivity ?? 0);
    if (this.running.size === 0 && idleFor >= idleMs) {
      await this.disconnect(`idle timeout (${s.idle_timeout_seconds}s)`);
    } else {
      await this.ctx.storage.setAlarm(Date.now() + Math.max(5000, idleMs - idleFor));
    }
  }

  private async requireClient(serverId: string): Promise<Client> {
    const r = await this.openSession(serverId);
    if (!r.ok || !this.client) throw new Error(`[${r.code}] ${r.message}`);
    this.touch();
    return this.client;
  }

  private async requireSftp(serverId: string): Promise<SFTPWrapper> {
    const c = await this.requireClient(serverId);
    if (!this.sftp) this.sftp = await openSftp(c);
    this.touch();
    return this.sftp;
  }

  // ------------------------------------------------------------- exec

  private async insertResult(req: ExecRequest, id: string, started: number) {
    await this.env.DB.prepare("INSERT INTO command_results (id, server_id, actor, command, classification, status, started_at) VALUES (?, ?, ?, ?, ?, 'running', ?)")
      .bind(id, req.serverId, req.actor, req.command.slice(0, 16384), req.classification, started)
      .run();
  }

  private async storeResult(id: string, r: ExecResult, status: StoredExecResult['status'], error?: string) {
    await this.env.DB.prepare(
      'UPDATE command_results SET status = ?, exit_code = ?, signal = ?, stdout = ?, stderr = ?, stdout_truncated = ?, stderr_truncated = ?, error = ?, finished_at = ?, duration_ms = ? WHERE id = ?',
    )
      .bind(status, r.exitCode, r.signal, r.stdout, r.stderr, r.stdoutTruncated ? 1 : 0, r.stderrTruncated ? 1 : 0, error ?? null, Date.now(), r.durationMs, id)
      .run();
  }

  /** Runs a command to completion (bounded output, timeout) and stores the result. */
  async exec(req: ExecRequest): Promise<StoredExecResult> {
    const id = req.resultId ?? randomId('cmd_');
    const started = Date.now();
    await this.insertResult(req, id, started);
    let client: Client;
    try {
      client = await this.requireClient(req.serverId);
    } catch (e) {
      const r = emptyResult(Date.now() - started);
      await this.storeResult(id, r, 'failed', (e as Error).message);
      return { ...r, id, status: 'failed', error: (e as Error).message };
    }
    const run = await startExec(client, req.command, { timeoutMs: req.timeoutMs, maxBytes: req.maxBytes });
    this.running.set(id, run);
    try {
      const r = await run.done;
      const status = r.timedOut ? 'timeout' : r.cancelled ? 'cancelled' : 'completed';
      await this.storeResult(id, r, status);
      return { ...r, id, status };
    } finally {
      this.running.delete(id);
      this.touch();
    }
  }

  /** Streams a command as NDJSON events; output beyond maxBytes is counted but not sent. */
  async execStream(req: ExecRequest): Promise<ReadableStream<Uint8Array>> {
    const id = req.resultId ?? randomId('cmd_');
    const started = Date.now();
    await this.insertResult(req, id, started);
    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
    const writer = writable.getWriter();
    const enc = new TextEncoder();
    let sent = 0;
    const send = (o: unknown) => writer.write(enc.encode(JSON.stringify(o) + '\n')).catch(() => {});
    const self = this;

    (async () => {
      send({ type: 'start', id });
      let client: Client;
      try {
        client = await self.requireClient(req.serverId);
      } catch (e) {
        const r = emptyResult(Date.now() - started);
        await self.storeResult(id, r, 'failed', (e as Error).message);
        await send({ type: 'error', id, error: (e as Error).message });
        await writer.close().catch(() => {});
        return;
      }
      const emit = (type: 'stdout' | 'stderr') => (d: Buffer) => {
        if (sent >= req.maxBytes) return;
        const chunk = d.subarray(0, req.maxBytes - sent);
        sent += chunk.length;
        send({ type, data: chunk.toString('utf8') });
        if (sent >= req.maxBytes) send({ type: 'truncated', limit: req.maxBytes });
      };
      let run: RunningExec;
      try {
        run = await startExec(client, req.command, { timeoutMs: req.timeoutMs, maxBytes: req.maxBytes, onStdout: emit('stdout'), onStderr: emit('stderr') });
      } catch (e) {
        await send({ type: 'error', id, error: (e as Error).message });
        await writer.close().catch(() => {});
        return;
      }
      self.running.set(id, run);
      try {
        const r = await run.done;
        const status = r.timedOut ? 'timeout' : r.cancelled ? 'cancelled' : 'completed';
        await self.storeResult(id, r, status);
        await send({ type: 'exit', id, status, exitCode: r.exitCode, signal: r.signal, durationMs: r.durationMs, stdoutTruncated: r.stdoutTruncated, stderrTruncated: r.stderrTruncated });
      } finally {
        self.running.delete(id);
        self.touch();
        await writer.close().catch(() => {});
      }
    })();
    return readable;
  }

  cancel(execId: string): { ok: boolean } {
    const r = this.running.get(execId);
    if (!r) return { ok: false };
    r.cancel('cancel');
    return { ok: true };
  }

  // ------------------------------------------------------------- SFTP

  async sftpList(serverId: string, path: string, offset = 0, limit = 500): Promise<{ path: string; entries: DirEntry[]; total: number; offset: number; limit: number }> {
    const s = await this.requireSftp(serverId);
    const real = await sftpOps.realpath(s, path).catch(() => path);
    const all = await sftpOps.list(s, real);
    return { path: real, entries: all.slice(offset, offset + limit).map(({ longname: _l, ...e }) => e), total: all.length, offset, limit };
  }

  async sftpStat(serverId: string, path: string) {
    const s = await this.requireSftp(serverId);
    return sftpOps.stat(s, path);
  }

  async sftpRead(serverId: string, path: string, offset: number, length: number): Promise<{ dataBase64: string; bytes: number; eof: boolean; size: number }> {
    const s = await this.requireSftp(serverId);
    const r = await sftpOps.read(s, path, offset, length);
    return { dataBase64: r.data.toString('base64'), bytes: r.data.length, eof: r.eof, size: r.size };
  }

  async sftpWrite(serverId: string, path: string, dataBase64: string, offset: number, truncate: boolean): Promise<{ bytes: number }> {
    const s = await this.requireSftp(serverId);
    const n = await sftpOps.write(s, path, Buffer.from(dataBase64, 'base64'), offset, truncate);
    return { bytes: n };
  }

  async sftpMkdir(serverId: string, path: string) {
    const s = await this.requireSftp(serverId);
    await sftpOps.mkdir(s, path);
    return { ok: true };
  }

  async sftpRename(serverId: string, from: string, to: string) {
    const s = await this.requireSftp(serverId);
    await sftpOps.rename(s, from, to);
    return { ok: true };
  }

  async sftpDelete(serverId: string, path: string) {
    const s = await this.requireSftp(serverId);
    const st = await sftpOps.stat(s, path);
    if (st.type === 'directory') await sftpOps.rmdir(s, path);
    else await sftpOps.unlink(s, path);
    return { ok: true, type: st.type };
  }

  /** Streams a remote file in 64 KiB chunks (memory stays bounded regardless of file size). */
  async sftpDownload(serverId: string, path: string): Promise<{ size: number; stream: ReadableStream<Uint8Array> }> {
    const s = await this.requireSftp(serverId);
    const st = await sftpOps.stat(s, path);
    if (st.type !== 'file') throw new Error('not a regular file');
    let offset = 0;
    const self = this;
    const stream = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const r = await sftpOps.read(s, path, offset, 65536);
          self.touch();
          if (r.data.length > 0) {
            controller.enqueue(new Uint8Array(r.data));
            offset += r.data.length;
          }
          if (r.eof || r.data.length === 0) controller.close();
        } catch (e) {
          controller.error(e);
        }
      },
    });
    return { size: st.size, stream };
  }
}

function emptyResult(durationMs: number): ExecResult {
  return { exitCode: null, signal: null, stdout: '', stderr: '', stdoutTruncated: false, stderrTruncated: false, stdoutBytes: 0, stderrBytes: 0, timedOut: false, cancelled: false, durationMs };
}
