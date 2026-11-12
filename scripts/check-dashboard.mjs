// Build-time check of the dashboard: bundles src/ui/dashboard.ts, renders the page and extracts the inline
// client script to dist/dashboard.js so `node --check` / tests can verify it parses. Used as `npm run build`.
import { build } from 'esbuild';
import fs from 'node:fs';
import vm from 'node:vm';
const r = await build({ entryPoints: ['src/ui/dashboard.ts'], bundle: true, format: 'esm', write: false, platform: 'neutral' });
const mod = await import('data:text/javascript;base64,' + Buffer.from(r.outputFiles[0].text).toString('base64'));
const html = mod.renderDashboard('NONCE');
const js = /<script nonce="NONCE">([\s\S]*)<\/script>/.exec(html)[1];
new vm.Script(js, { filename: 'dashboard.js' }); // throws on a syntax error
fs.mkdirSync('dist', { recursive: true });
fs.writeFileSync('dist/dashboard.js', js);
fs.writeFileSync('dist/dashboard.html', html);
console.log('dashboard OK, js bytes', js.length);
