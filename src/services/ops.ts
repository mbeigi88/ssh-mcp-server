// Service layer shared by the dashboard API and the MCP tools: policy enforcement,
// confirmation workflow, command execution and SFTP operations.
import type { Env } from '../env';
import { audit, getSettings, UserError, type ServerRow } from '../lib/db';
import { decide, decideOperation, type Classification, type PolicyDecision } from '../lib/policy';
import { randomId, randomToken, sha256Hex, timingSafeEqualStr } from '../lib/crypto';
import { shQuote, validateRemotePath } from '../lib/quote';
import type { StoredExecResult } from '../do/ssh-session';
import { autoApproveCommand, autoApproveDelete, normalizeLevel, type AutoApproval } from '../lib/auto-approve';

export function sshStub(env: Env, serverId: string) {
  return env.SSH_SESSION.get(env.SSH_SESSION.idFromName(serverId));
}

export function policyOf(server: ServerRow) {
  return { policy_mode: server.policy_mode, allow_sudo_install: !!server.allow_sudo_install };
}

export type Operation =
  | { type: 'exec'; command: string; timeout_seconds?: number }
  | { type: 'delete'; path: string; recursive: boolean };

export interface ConfirmOpts {
  /** id of a pending confirmation the human approved in the dashboard */
  confirmationId?: string;
  /** one-time token the human copied from the dashboard */
  confirmToken?: string;
  /** dashboard admin explicitly confirmed in the UI dialog (human in the loop) */
  adminConfirmed?: boolean;
}

export type OpOutcome<T> =
  | { kind: 'done'; value: T; classification: Classification; auto?: AutoApproval }
  | { kind: 'blocked'; reason: string; classification: Classification }
  | { kind: 'confirmation_required'; confirmation_id: string; expires_at: number; reason: string; classification: Classification; message: string; catastrophic?: string[] };

// ------------------------------------------------------------ confirmations

async function createPending(env: Env, server: ServerRow, tool: string, op: Operation, d: PolicyDecision & { action: 'confirm' }, actor: string) {
  const settings = await getSettings(env);
  const id = randomId('cfm_');
  const token = randomToken(9); // shown only in the dashboard
  const now = Date.now();
  const expires = now + settings.confirmation_ttl_seconds * 1000;
  await env.DB.prepare(
    "INSERT INTO pending_confirmations (id, server_id, tool, operation, classification, reason, confirm_token_hash, status, requested_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
  )
    .bind(id, server.id, tool, JSON.stringify(op), d.classification.classification, d.reason, await sha256Hex(token), actor, now, expires)
    .run();
  await audit(env, { actor, action: 'confirmation.requested', server_id: server.id, outcome: 'pending', detail: { id, tool, op, reason: d.reason } });
  return { id, expires };
}

interface PendingRow {
  id: string; server_id: string; tool: string; operation: string; classification: string; reason: string;
  confirm_token_hash: string; status: string; expires_at: number;
}

/** Validates and atomically consumes an approved (or token-confirmed) confirmation. Returns the stored operation. */
export async function consumeConfirmation(env: Env, server: ServerRow, id: string, token: string | undefined, actor: string): Promise<{ op: Operation; row: PendingRow }> {
  const row = await env.DB.prepare('SELECT * FROM pending_confirmations WHERE id = ?').bind(id).first<PendingRow>();
  if (!row || row.server_id !== server.id) throw new UserError('confirmation not found for this server', 404);
  if (row.expires_at < Date.now()) {
    await env.DB.prepare("UPDATE pending_confirmations SET status = 'expired' WHERE id = ? AND status IN ('pending','approved')").bind(id).run();
    throw new UserError('confirmation expired; request the operation again', 410);
  }
  if (row.status === 'pending' && token) {
    if (!timingSafeEqualStr(await sha256Hex(token), row.confirm_token_hash)) {
      await audit(env, { actor, action: 'confirmation.bad_token', server_id: server.id, outcome: 'denied', detail: { id } });
      throw new UserError('invalid confirmation token', 403);
    }
  } else if (row.status === 'pending') {
    throw new UserError('confirmation is still pending: a human must approve it in the dashboard (or provide the one-time confirm token shown there)', 409);
  } else if (row.status !== 'approved') {
    throw new UserError(`confirmation is ${row.status}`, 409);
  }
  const upd = await env.DB.prepare("UPDATE pending_confirmations SET status = 'executed', executed_at = ? WHERE id = ? AND status IN ('pending','approved')").bind(Date.now(), id).run();
  if (!upd.meta.changes) throw new UserError('confirmation already used', 409);
  await audit(env, { actor, action: 'confirmation.consumed', server_id: server.id, detail: { id, via: token ? 'token' : 'dashboard-approval' } });
  return { op: JSON.parse(row.operation) as Operation, row };
}

// ------------------------------------------------------------ commands

export async function runCommand(
  env: Env,
  actor: string,
  server: ServerRow,
  command: string,
  timeoutSeconds: number | undefined,
  confirm: ConfirmOpts = {},
  maxBytesOverride?: number,
): Promise<OpOutcome<StoredExecResult>> {
  if (confirm.confirmationId) {
    const { op } = await consumeConfirmation(env, server, confirm.confirmationId, confirm.confirmToken, actor);
    if (op.type !== 'exec') throw new UserError('confirmation is for a different operation');
    return executeApproved(env, actor, server, op, maxBytesOverride);
  }
  const d = decide(command, policyOf(server));
  if (d.action === 'block') {
    await audit(env, { actor, action: 'command.blocked', server_id: server.id, outcome: 'blocked', detail: { command, reason: d.reason } });
    return { kind: 'blocked', reason: d.reason, classification: d.classification };
  }
  let auto: AutoApproval | undefined;
  if (d.action === 'confirm' && !confirm.adminConfirmed) {
    const a = autoApproveCommand(normalizeLevel(server.auto_approve), command, d);
    if (a.auto) {
      auto = a.approval;
    } else {
      const p = await createPending(env, server, 'execute_command', { type: 'exec', command, timeout_seconds: timeoutSeconds }, d, actor);
      const cat = a.catastrophic.length ? ` Auto-approve does not cover it: catastrophic (${a.catastrophic.join('; ')}).` : '';
      return {
        kind: 'confirmation_required', confirmation_id: p.id, expires_at: p.expires, reason: d.reason, classification: d.classification, catastrophic: a.catastrophic.length ? a.catastrophic : undefined,
        message: `This command is classified as DESTRUCTIVE (${d.reason}).${cat} A human must approve confirmation ${p.id} in the dashboard (Approvals), then call the tool again with confirmation_id="${p.id}".`,
      };
    }
  }
  const value = await execOn(env, actor, server, command, d.classification.classification, timeoutSeconds, maxBytesOverride, auto);
  return { kind: 'done', value, classification: d.classification, auto };
}

async function executeApproved(env: Env, actor: string, server: ServerRow, op: Operation, maxBytesOverride?: number): Promise<OpOutcome<StoredExecResult>> {
  if (op.type !== 'exec') throw new UserError('not an exec operation');
  // Re-check hard blocks (read-only mode may have been enabled after the request).
  const d = decide(op.command, policyOf(server));
  if (d.action === 'block') return { kind: 'blocked', reason: d.reason, classification: d.classification };
  const value = await execOn(env, actor, server, op.command, 'destructive', op.timeout_seconds, maxBytesOverride);
  return { kind: 'done', value, classification: d.classification };
}

export async function execOn(env: Env, actor: string, server: ServerRow, command: string, classification: string, timeoutSeconds?: number, maxBytesOverride?: number, auto?: AutoApproval): Promise<StoredExecResult> {
  const settings = await getSettings(env);
  const timeoutMs = Math.min(600, timeoutSeconds ?? settings.default_command_timeout_seconds) * 1000;
  const maxBytes = Math.min(settings.max_output_bytes, maxBytesOverride ?? settings.max_output_bytes);
  const r = await sshStub(env, server.id).exec({ serverId: server.id, command, timeoutMs, maxBytes, actor, classification });
  await audit(env, {
    actor, action: 'command.exec', server_id: server.id, outcome: r.status, auto_level: auto?.level,
    detail: { command: command.slice(0, 500), classification, id: r.id, exit: r.exitCode, ...(auto ? { auto_approved: true, auto_level: auto.level, approval_reason: auto.reason } : {}) },
  });
  return r;
}

// ------------------------------------------------------------ files

export async function checkFileOp(env: Env, actor: string, server: ServerRow, kind: 'read' | 'modify', what: string) {
  const d = decideOperation(kind, what, policyOf(server));
  if (d.action === 'block') {
    await audit(env, { actor, action: 'file.blocked', server_id: server.id, outcome: 'blocked', detail: { what } });
    throw new UserError(d.reason, 403);
  }
}

export async function deleteFile(env: Env, actor: string, server: ServerRow, path: string, recursive: boolean, confirm: ConfirmOpts = {}): Promise<OpOutcome<{ deleted: string; via: string }>> {
  let op: Operation = { type: 'delete', path: validateRemotePath(path), recursive };
  let auto: AutoApproval | undefined;
  if (confirm.confirmationId) {
    const c = await consumeConfirmation(env, server, confirm.confirmationId, confirm.confirmToken, actor);
    if (c.op.type !== 'delete') throw new UserError('confirmation is for a different operation');
    op = c.op;
  } else {
    const d = decideOperation('destructive', `delete ${recursive ? 'recursively ' : ''}${path}`, policyOf(server));
    if (d.action === 'block') return { kind: 'blocked', reason: d.reason, classification: d.classification };
    if (!confirm.adminConfirmed) {
      const a = autoApproveDelete(normalizeLevel(server.auto_approve), op.path, recursive, d);
      if (a.auto) {
        auto = a.approval;
      } else {
        const p = await createPending(env, server, 'delete_file', op, d as PolicyDecision & { action: 'confirm' }, actor);
        const cat = a.catastrophic.length ? ` Auto-approve does not cover it: catastrophic (${a.catastrophic.join('; ')}).` : '';
        return {
          kind: 'confirmation_required', confirmation_id: p.id, expires_at: p.expires, reason: `delete ${path}`, classification: d.classification, catastrophic: a.catastrophic.length ? a.catastrophic : undefined,
          message: `Deleting ${path} requires human approval.${cat} Approve confirmation ${p.id} in the dashboard, then call delete_file again with confirmation_id="${p.id}".`,
        };
      }
    }
  }
  if (op.type !== 'delete') throw new UserError('bad operation');
  const cls: Classification = { classification: 'destructive', reasons: ['delete'], usesSudo: false, packageInstall: false };
  if (policyOf(server).policy_mode === 'read_only') return { kind: 'blocked', reason: 'server is in read-only mode', classification: cls };
  if (op.recursive) {
    if (/^\/+$|^\/+(?:bin|boot|dev|etc|lib|lib64|proc|root|sbin|sys|usr|var)\/*$/.test(op.path)) throw new UserError('refusing to recursively delete a system directory', 403);
    const r = await execOn(env, actor, server, `rm -rf -- ${shQuote(op.path)}`, 'destructive', 120, undefined, auto);
    if (r.status !== 'completed' || r.exitCode !== 0) throw new UserError(`delete failed: ${r.stderr || r.error || r.status}`);
  } else {
    await sshStub(env, server.id).sftpDelete(server.id, op.path);
  }
  await audit(env, {
    actor, action: 'file.delete', server_id: server.id, auto_level: auto?.level,
    detail: { path: op.path, recursive: op.recursive, ...(auto ? { auto_approved: true, auto_level: auto.level } : {}) },
  });
  return { kind: 'done', value: { deleted: op.path, via: op.recursive ? 'rm -rf' : 'sftp' }, classification: cls, auto };
}
