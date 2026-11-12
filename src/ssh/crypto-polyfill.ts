// workerd's `node:crypto` *default* export (what CommonJS `require('crypto')` resolves to
// after bundling) is missing `diffieHellman`, while the named export exists. ssh2 feature-
// detects curve25519 via `typeof crypto.diffieHellman`, so without this shim it silently
// drops curve25519-sha256 key exchange. This module MUST be imported before `ssh2`.
import nodeCrypto, { diffieHellman } from 'node:crypto';

const c = nodeCrypto as unknown as Record<string, unknown>;
if (typeof c.diffieHellman !== 'function' && typeof diffieHellman === 'function') {
  c.diffieHellman = diffieHellman;
}
export const cryptoPolyfillApplied = true;

// X25519 for curve25519-sha256 kex (see scripts/patch-ssh2.mjs step 6).
import { x25519 } from '@noble/curves/ed25519.js';
(globalThis as unknown as { __sshX25519: unknown }).__sshX25519 = {
  getPublicKey: (priv: Uint8Array) => x25519.getPublicKey(priv),
  getSharedSecret: (priv: Uint8Array, pub: Uint8Array) => x25519.getSharedSecret(priv, pub),
};
