// Idempotent patch that makes ssh2@1.17.x load inside workerd (Cloudflare Workers).
// 1. Removes the native `sshcrypto.node` require (not loadable/bundlable in Workers).
// 2. Removes the optional `cpu-features` native addon require.
// 3. Makes the chacha20-poly1305 WASM init lazy — workerd forbids runtime
//    WebAssembly compilation, so eager init crashes module evaluation
//    (see https://github.com/mscdex/ssh2/issues/1494). We never negotiate chacha20.
// 4. Hardens canUseCipher/canUseMAC against unknown names.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'node_modules', 'ssh2', 'lib', 'protocol');
const MARK = '/* cf-ssh-mcp patched */';

function patch(file, edits) {
  const p = join(root, file);
  if (!existsSync(p)) throw new Error('ssh2 not installed: ' + p);
  let src = readFileSync(p, 'utf8');
  if (src.startsWith(MARK)) return console.log('[patch-ssh2] already patched', file);
  for (const [from, to] of edits) {
    if (!src.includes(from)) throw new Error(`[patch-ssh2] pattern not found in ${file}: ${from.slice(0, 60)}`);
    src = src.replace(from, to);
  }
  writeFileSync(p, MARK + '\n' + src);
  console.log('[patch-ssh2] patched', file);
}

patch('crypto.js', [
  ["  binding = require('./crypto/build/Release/sshcrypto.node');", "  binding = undefined; throw 0;"],
  [
    "        POLY1305_WASM_MODULE = await require('./crypto/poly1305.js')();",
    "        // lazy: chacha20-poly1305 disabled in Workers build\n        return resolve();",
  ],
]);
patch('constants.js', [
  ["  cpuInfo = require('cpu-features')();", "  cpuInfo = undefined;"],
  ["return (name) => ciphers.includes(CIPHER_INFO[name].sslName);", "return (name) => !!CIPHER_INFO[name] && ciphers.includes(CIPHER_INFO[name].sslName);"],
  ["return (name) => hashes.includes(MAC_INFO[name].sslName);", "return (name) => !!MAC_INFO[name] && hashes.includes(MAC_INFO[name].sslName);"],
]);
// 5. agent.js computes a Windows Pageant path from __dirname at module load (undefined in Workers).
{
  const p = join(root, '..', 'agent.js');
  let src = readFileSync(p, 'utf8');
  if (!src.startsWith(MARK)) {
    const from = "const EXEPATH = resolve(__dirname, '..', 'util/pagent.exe');";
    if (!src.includes(from)) throw new Error('[patch-ssh2] agent.js pattern not found');
    src = MARK + '\n' + src.replace(from, "const EXEPATH = 'pagent.exe'; // not used in Workers");
    writeFileSync(p, src);
    console.log('[patch-ssh2] patched agent.js');
  }
}
// 6. curve25519 kex: workerd's node:crypto `diffieHellman` fails for X25519 keys imported via
//    createPublicKey ("Failed to derive shared diffie-hellman secret"), verified locally in
//    workerd. Replace the Curve25519 exchange with @noble/curves x25519 (pure JS, audited),
//    provided via globalThis.__sshX25519 by src/ssh/crypto-polyfill.ts.
{
  const p = join(root, 'kex.js');
  let src = readFileSync(p, 'utf8');
  if (!src.startsWith(MARK)) {
    const start = src.indexOf("    generateKeys() {\n      if (!this._keys)\n        this._keys = generateKeyPairSync('x25519');");
    const endMarker = "        }));\n      } catch (ex) {\n        return ex;\n      }\n    }\n  }\n\n  class ECDHExchange";
    const end = src.indexOf(endMarker, start);
    if (start < 0 || end < 0) throw new Error('[patch-ssh2] kex.js x25519 pattern not found');
    const replacement = `    generateKeys() {
      if (!this._keys) {
        const X = globalThis.__sshX25519;
        if (!X) throw new Error('x25519 implementation not installed');
        const priv = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32)));
        this._keys = { priv, pub: Buffer.from(X.getPublicKey(priv)) };
      }
    }
    getPublicKey() {
      this.generateKeys();
      return this._keys.pub;
    }
    convertPublicKey(key) {
      return key;
    }
    computeSecret(otherPublicKey) {
      this.generateKeys();
      try {
        if (otherPublicKey.length !== 32) throw new Error('Invalid X25519 public key length');
        const X = globalThis.__sshX25519;
        return convertToMpint(Buffer.from(X.getSharedSecret(this._keys.priv, otherPublicKey)));
      } catch (ex) {
        return ex;
      }
    }
  }

  class ECDHExchange`;
    src = MARK + '\n' + src.slice(0, start) + replacement + src.slice(end + endMarker.length);
    writeFileSync(p, src);
    console.log('[patch-ssh2] patched kex.js');
  }
}
