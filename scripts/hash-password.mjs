#!/usr/bin/env node
// Prints a PBKDF2-SHA256 hash (format used by ADMIN_PASSWORD_HASH) for a password read from
// stdin (preferred, so it never lands in shell history) or the ADMIN_PASSWORD env var.
//   printf '%s' 'my long password' | npm run -s hash-password
import { pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
let pw = process.env.ADMIN_PASSWORD;
if (!pw) { try { pw = readFileSync(0, 'utf8').replace(/\r?\n$/, ''); } catch { /* no stdin */ } }
if (!pw || pw.length < 12) { console.error('password must be at least 12 characters (pass via stdin)'); process.exit(1); }
const salt = randomBytes(16);
const hash = pbkdf2Sync(pw, salt, 100000, 32, 'sha256');
process.stdout.write(`pbkdf2$sha256$100000$${salt.toString('base64')}$${hash.toString('base64')}\n`);
