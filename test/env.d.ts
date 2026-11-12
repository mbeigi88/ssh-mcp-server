import type { Env as AppEnv } from '../src/env';
declare global {
  namespace Cloudflare {
    interface Env extends AppEnv {
      TEST_MIGRATIONS: import('cloudflare:test').D1Migration[];
      TEST_ADMIN_PASSWORD: string;
      TEST_KEYS?: string;
      SSH_TEST_PORT?: string;
    }
  }
}
export {};
