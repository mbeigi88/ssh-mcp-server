import { z } from 'zod';
import { isValidHost } from './ssrf';

const noCtl = (s: string) => !/[\0\r\n]/.test(s);

export const fingerprintSchema = z
  .string()
  .trim()
  .regex(/^SHA256:[A-Za-z0-9+/]{43}=?$/, 'fingerprint must look like SHA256:<base64> (as printed by ssh-keygen -lf)');

export const labelSchema = z.string().trim().min(1).max(32).regex(/^[\p{L}\p{N}_.:-]+$/u, 'labels may contain letters, digits, _ . : -');

const privateKeySchema = z
  .string()
  .max(16384)
  .refine((k) => /-----BEGIN (?:OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----/.test(k), 'private key must be PEM / OpenSSH format');

const serverFields = {
  name: z.string().trim().min(1).max(64).refine(noCtl, 'invalid characters'),
  host: z.string().trim().min(1).max(253).refine(isValidHost, 'host must be a valid hostname or IP address'),
  port: z.coerce.number().int().min(1).max(65535).default(22),
  username: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .regex(/^[A-Za-z0-9._][A-Za-z0-9._-]*\$?$/, 'invalid username'),
  auth_method: z.enum(['password', 'key']),
  password: z.string().max(1024).refine(noCtl, 'invalid characters').optional(),
  private_key: privateKeySchema.optional(),
  passphrase: z.string().max(1024).optional(),
  host_key_fingerprint: z.union([fingerprintSchema, z.literal('')]).optional(),
  labels: z.array(labelSchema).max(20).default([]),
  is_default: z.boolean().default(false),
  allow_root: z.boolean().default(false),
  policy_mode: z.enum(['read_only', 'modify']).default('modify'),
  allow_sudo_install: z.boolean().default(false),
  /** omitted -> the global default_auto_approve setting */
  auto_approve: z.enum(['off', 'safe', 'all']).optional(),
  /** typed confirmation required when setting auto_approve to "all" */
  auto_approve_confirm: z.string().max(32).optional(),
}

const serverUpdateFields = {
  name: z.string().trim().min(1).max(64).refine(noCtl, 'invalid characters'),
  host: z.string().trim().min(1).max(253).refine(isValidHost, 'host must be a valid hostname or IP address'),
  port: z.coerce.number().int().min(1).max(65535),
  username: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .regex(/^[A-Za-z0-9._][A-Za-z0-9._-]*\$?$/, 'invalid username'),
  auth_method: z.enum(['password', 'key']),
  password: z.string().max(1024).refine(noCtl, 'invalid characters').optional(),
  private_key: privateKeySchema.optional(),
  passphrase: z.string().max(1024).optional(),
  host_key_fingerprint: z.union([fingerprintSchema, z.literal('')]).optional(),
  labels: z.array(labelSchema).max(20),
  is_default: z.boolean(),
  allow_root: z.boolean(),
  policy_mode: z.enum(['read_only', 'modify']),
  allow_sudo_install: z.boolean(),
  auto_approve: z.enum(['off', 'safe', 'all']),
  auto_approve_confirm: z.string().max(32),
}

export const serverBaseSchema = z.object(serverFields);

export const serverCreateSchema = serverBaseSchema.superRefine((v, ctx) => {
  if (v.auth_method === 'password' && !v.password) ctx.addIssue({ code: 'custom', path: ['password'], message: 'password is required' });
  if (v.auth_method === 'key' && !v.private_key) ctx.addIssue({ code: 'custom', path: ['private_key'], message: 'private key is required' });
  if (v.username === 'root' && !v.allow_root) ctx.addIssue({ code: 'custom', path: ['allow_root'], message: 'root login must be explicitly allowed for this server' });
});

/** Update: every field optional; secrets omitted/empty mean "unchanged"; clear_* flags remove them. */
export const serverUpdateSchema = z
  .object(serverUpdateFields)
  .partial()
  .extend({
    clear_passphrase: z.boolean().optional(),
    reset_host_key: z.boolean().optional(),
  })
  .strict();

export const settingsSchema = z
  .object({
    allow_private_targets: z.boolean().optional(),
    idle_timeout_seconds: z.number().int().min(30).max(3600).optional(),
    default_command_timeout_seconds: z.number().int().min(1).max(600).optional(),
    max_output_bytes: z.number().int().min(1024).max(4 * 1024 * 1024).optional(),
    confirmation_ttl_seconds: z.number().int().min(60).max(86400).optional(),
    session_ttl_hours: z.number().int().min(1).max(168).optional(),
    default_auto_approve: z.enum(['off', 'safe', 'all']).optional(),
    default_auto_approve_confirm: z.string().max(32).optional(),
  })
  .strict();

export const loginSchema = z.object({ password: z.string().min(1).max(1024) });
export const setupSchema = z.object({ setup_token: z.string().min(1).max(1024), password: z.string().min(1).max(1024) });
export const changePasswordSchema = z.object({ current_password: z.string().min(1).max(1024), new_password: z.string().min(12).max(1024) });

export const execSchema = z.object({
  command: z.string().min(1).max(16384),
  timeout_seconds: z.number().int().min(1).max(600).optional(),
  confirmation_id: z.string().max(64).optional(),
});

export const pathSchema = z.string().min(1).max(4096).refine(noCtl, 'path must not contain NUL or line breaks');

export function formatZodError(e: z.ZodError): string {
  return e.issues.map((i) => `${i.path.join('.') || 'input'}: ${i.message}`).join('; ');
}

export const autoApproveSchema = z.object({ level: z.enum(['off', 'safe', 'all']), confirm_text: z.string().max(32).optional() }).strict();
export const approveAllSchema = z.object({ server_id: z.string().min(1).max(64).optional() }).strict();
