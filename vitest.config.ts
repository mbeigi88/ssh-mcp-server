import path from 'node:path';
import fs from 'node:fs';
import { pbkdf2Sync, randomBytes } from 'node:crypto';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export const TEST_ADMIN_PASSWORD = 'test-admin-password-123';

function hashPassword(pw: string) {
  const salt = randomBytes(16);
  const h = pbkdf2Sync(pw, salt, 100000, 32, 'sha256');
  return `pbkdf2$sha256$100000$${salt.toString('base64')}$${h.toString('base64')}`;
}

const keysDir = path.join(__dirname, 'test/fixtures/keys');
function readKeys() {
  const out: Record<string, string> = {};
  for (const f of ['id_ed25519', 'id_rsa', 'id_ed25519_enc', 'id_ecdsa', 'host_ed25519.pub', 'host_rsa.pub', 'host_ecdsa.pub']) {
    out[f] = fs.readFileSync(path.join(keysDir, f), 'utf8');
  }
  return JSON.stringify(out);
}

const workerProject = (name: string, include: string[], extraBindings: Record<string, unknown>, timeout: number) => ({
  plugins: [
    cloudflareTest(async () => ({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          TEST_MIGRATIONS: await readD1Migrations(path.join(__dirname, 'migrations')),
          ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64'),
          SESSION_SECRET: 'test-session-secret-0123456789abcdef0123456789',
          ADMIN_PASSWORD_HASH: hashPassword(TEST_ADMIN_PASSWORD),
          TEST_ADMIN_PASSWORD,
          ...extraBindings,
        },
      },
    })),
  ],
  test: { name, include, setupFiles: ['./test/setup/apply-migrations.ts'], testTimeout: timeout, hookTimeout: timeout },
});

// NOTE: run the worker and integration projects in SEPARATE vitest invocations (npm run test:all).
// The worker project pins DEV_ALLOW_PRIVATE_TARGETS=false so a local .dev.vars cannot weaken
// its SSRF assertions; only the integration project enables it (to reach the local sshd).
export default defineConfig({
  test: {
    projects: [
      { test: { name: 'unit', include: ['test/unit/**/*.test.ts'], environment: 'node' } },
      workerProject('worker', ['test/worker/**/*.test.ts'], { TEST_KEYS: readKeys(), DEV_ALLOW_PRIVATE_TARGETS: 'false' }, 30000),
      workerProject('integration', ['test/integration/**/*.test.ts'], { DEV_ALLOW_PRIVATE_TARGETS: 'true', TEST_KEYS: readKeys(), SSH_TEST_PORT: '2222' }, 90000),
    ],
  },
});
