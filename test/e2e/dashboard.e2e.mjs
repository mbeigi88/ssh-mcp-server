// Browser E2E of the dashboard against `wrangler dev` + the real local sshd.
// Usage: BASE=http://localhost:8787 ADMIN_PASSWORD=... [SETUP_BASE=http://localhost:8788 SETUP_TOKEN=...] node test/e2e/dashboard.e2e.mjs
// SETUP_BASE (optional): a second `wrangler dev` with a FRESH database, no ADMIN_PASSWORD_HASH and SETUP_TOKEN set,
// used to test the first-run "Create admin password" page.
// Covers every dashboard feature at desktop (1440) and phone (390x844) sizes, in English and Persian (RTL):
// layout overflow, bottom tab bar, bottom sheets, bidi isolation of LTR data, and no CSP/console errors.
import puppeteer from 'puppeteer-core';
import fs from 'node:fs';

const BASE = process.env.BASE ?? 'http://localhost:8787';
const PW = process.env.ADMIN_PASSWORD;
const OUT = process.env.SHOTS ?? 'test/e2e/screenshots';
fs.mkdirSync(OUT, { recursive: true });
for (const f of fs.readdirSync(OUT)) if (f.endsWith('.png')) fs.unlinkSync(`${OUT}/${f}`);
const results = [];
const step = async (name, fn) => {
  try { await fn(); results.push(['PASS', name]); console.log('PASS', name); }
  catch (e) { results.push(['FAIL', name, e.message]); console.log('FAIL', name, e.message); await page.screenshot({ path: `${OUT}/FAIL-${name.slice(0, 24).replace(/\W+/g, '_')}.png` }).catch(() => {}); }
};
const DESKTOP = { width: 1440, height: 900 };
const PHONE = { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true };

const browser = await puppeteer.launch({ executablePath: process.env.CHROME ?? '/usr/bin/chromium', args: ['--no-sandbox', '--disable-dev-shm-usage', '--lang=en-US'], headless: true });
const page = await browser.newPage();
await page.setViewport(DESKTOP);
const consoleErrors = [];
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
page.on('pageerror', (e) => consoleErrors.push('pageerror: ' + e.message));
page.on('dialog', async (d) => { consoleErrors.push('unexpected native dialog: ' + d.message()); await d.dismiss(); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shot = async (n) => { await sleep(350); await page.screenshot({ path: `${OUT}/${n}.png` }); };
const waitText = (text, timeout = 15000) => page.waitForFunction((t) => document.body.innerText.includes(t), { timeout }, text);
const click = async (sel, timeout = 15000) => {
  await page.waitForFunction((s) => { const e = document.querySelector(s); return e && e.offsetParent !== null && !e.disabled; }, { timeout }, sel);
  await page.evaluate((s) => document.querySelector(s).click(), sel);
};
const inCard = async (server, action) => click(`.card[data-server="${server}"] [data-action="${action}"]`);
const go = async (view) => {
  const mobile = await page.evaluate(() => innerWidth < 768);
  const sel = mobile ? `.tabbar [data-view="${view}"]` : `nav.side [data-view="${view}"]`;
  if (mobile && !['overview', 'servers', 'terminal', 'files', 'mcp'].includes(view)) {
    await click('[data-action="more"]'); await click(`.sheet-item[data-action="${view}"]`);
  } else await click(sel);
  await page.waitForFunction((v) => document.querySelector('main.v-' + v + ' .view'), { timeout: 15000 }, view);
};
const pickServer = (n) => page.evaluate((n) => { const sel = document.querySelector('main [data-role=server-picker]'); const o = [...sel.options].find((x) => x.text.includes(n)); sel.value = o.value; sel.dispatchEvent(new Event('change')); }, n);
// Elements sticking out of the viewport (excluding ones inside intentional scroll containers).
const overflow = () => page.evaluate(() => {
  const W = document.documentElement.clientWidth; const bad = [];
  const scroller = (el) => { for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) { const ox = getComputedStyle(p).overflowX; if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true; } return false; };
  for (const el of document.body.querySelectorAll('*')) {
    if (el.closest('svg') && el.tagName.toLowerCase() !== 'svg') continue;
    const r = el.getBoundingClientRect(); if (!r.width || !r.height) continue;
    if ((r.right > W + 1 || r.left < -1) && !scroller(el)) bad.push((el.className && el.className.baseVal === undefined ? el.tagName + '.' + el.className : el.tagName) + ' [' + Math.round(r.left) + ',' + Math.round(r.right) + ']');
  }
  return { docW: document.documentElement.scrollWidth, W, bad: bad.slice(0, 8) };
});
const assertNoOverflow = async (label) => { const o = await overflow(); if (o.bad.length || o.docW > o.W + 1) throw new Error(`${label}: horizontal overflow ${JSON.stringify(o)}`); };
const setLang = async (want) => {
  const cur = await page.evaluate(() => document.documentElement.lang);
  if (cur === want) return;
  const mobile = await page.evaluate(() => innerWidth < 768);
  if (mobile) { await click('[data-action="more"]'); await click('.sheet-item[data-action="lang"]'); }
  else await click('nav.side [data-action="lang"]');
  await page.waitForFunction((l) => document.documentElement.lang === l && document.documentElement.dir === (l === 'fa' ? 'rtl' : 'ltr'), {}, want);
};

// --- minimal MCP client (Streamable HTTP, JSON responses) used to create real pending approvals
let mcpSid = null;
const mcpPost = async (tok, body) => {
  const r = await fetch(BASE + '/mcp', { method: 'POST', headers: { authorization: 'Bearer ' + tok, accept: 'application/json, text/event-stream', 'content-type': 'application/json', 'mcp-protocol-version': '2025-06-18', ...(mcpSid ? { 'mcp-session-id': mcpSid } : {}) }, body: JSON.stringify(body) });
  const sid = r.headers.get('mcp-session-id'); if (sid) mcpSid = sid;
  const txt = await r.text();
  try { return JSON.parse(txt); } catch { const m = /data: (.*)/.exec(txt); return m ? JSON.parse(m[1]) : txt; }
};
const mcpTool = async (tok, name, args) => {
  if (!mcpSid) {
    await mcpPost(tok, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e2e', version: '1' } } });
    await mcpPost(tok, { jsonrpc: '2.0', method: 'notifications/initialized' });
  }
  const j = await mcpPost(tok, { jsonrpc: '2.0', id: Date.now(), method: 'tools/call', params: { name, arguments: args } });
  return JSON.parse(j.result.content[0].text);
};
const pageApi = (path) => page.evaluate(async (p) => (await fetch('/api' + p, { credentials: 'same-origin' })).json(), path);
const serverByName = async (n) => (await pageApi('/servers')).find((s) => s.name === n);

if (process.env.SETUP_BASE) {
  const SB = process.env.SETUP_BASE;
  const ST = process.env.SETUP_TOKEN;
  const NEWPW = 'e2e-setup-admin-pass-1';
  await step('first-run setup page: shown instead of login, wrong token rejected, fa toggle, create password', async () => {
    const ctx = await browser.createBrowserContext();
    const p = await ctx.newPage(); const errs = [];
    p.on('pageerror', (e) => errs.push('pageerror: ' + e.message));
    p.on('console', (m) => { if (m.type() === 'error' && !/status of (401|403)/.test(m.text())) errs.push(m.text()); });
    await p.setViewport(DESKTOP);
    await p.goto(SB + '/', { waitUntil: 'networkidle0' });
    await p.waitForSelector('h1[data-role="setup"]');
    if (await p.$('#pw')) throw new Error('login form shown on a fresh deployment');
    await sleep(300); await p.screenshot({ path: `${OUT}/00-setup-desktop-en.png` });
    await p.type('#setup-token', 'definitely-not-the-token');
    await p.type('#setup-pw', NEWPW); await p.type('#setup-pw2', NEWPW);
    await p.click('button[data-action="setup"]');
    await p.waitForFunction(() => document.querySelector('.login .error')?.textContent.includes('wrong setup token'), { timeout: 15000 });
    // mismatch is caught client-side
    await p.evaluate(() => { document.querySelector('#setup-pw2').value = 'something-else-123'; });
    await p.click('button[data-action="setup"]');
    await p.waitForFunction(() => document.querySelector('.login .error')?.textContent.includes('do not match'), { timeout: 5000 });
    // Persian via the toggle, on a phone
    await p.setViewport(PHONE); // isMobile change reloads the page
    await p.waitForSelector('h1[data-role="setup"] ~ * , h1[data-role="setup"]');
    await p.waitForSelector('[data-action="lang"]');
    await p.evaluate(() => document.querySelector('[data-action="lang"]').click());
    await p.waitForFunction(() => document.documentElement.lang === 'fa' && document.documentElement.dir === 'rtl' && document.querySelector('h1[data-role="setup"]')?.textContent.includes('رمز'));
    const o = await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1);
    if (!o) throw new Error('setup page overflows on a phone');
    await sleep(300); await p.screenshot({ path: `${OUT}/00-setup-mobile-fa.png` });
    await p.type('#setup-token', ST);
    await p.type('#setup-pw', NEWPW); await p.type('#setup-pw2', NEWPW);
    await p.click('button[data-action="setup"]');
    await p.waitForSelector('nav.tabbar, .tabbar', { timeout: 15000 });
    // reload: still signed in; setup endpoint now disabled
    await p.reload({ waitUntil: 'networkidle0' });
    await p.waitForSelector('.tabbar');
    const st = await p.evaluate(async () => (await fetch('/api/setup')).json());
    if (st.state !== 'done') throw new Error('setup still available: ' + JSON.stringify(st));
    // Settings: a D1-stored password can be changed here
    await p.evaluate(() => { location.hash = 'settings'; });
    await p.waitForSelector('[data-action="change-password"]', { timeout: 15000 });
    // log out -> the normal login page (not the setup page), and the new password works
    await p.evaluate(async () => { const me = await (await fetch('/api/auth/me')).json(); await fetch('/api/auth/logout', { method: 'POST', headers: { 'x-csrf-token': me.csrf } }); });
    await p.reload({ waitUntil: 'networkidle0' });
    await p.waitForSelector('#pw');
    if (await p.$('h1[data-role="setup"]')) throw new Error('setup page shown after setup');
    await p.type('#pw', NEWPW); await p.click('button[type=submit]');
    await p.waitForSelector('.tabbar');
    await ctx.close();
    if (errs.length) throw new Error(errs.join(' | '));
  });
}

await step('login page renders and login works', async () => {
  await page.goto(BASE + '/', { waitUntil: 'networkidle0' });
  await page.waitForSelector('input[type=password]');
  if (await page.evaluate(() => document.documentElement.lang) !== 'en') throw new Error('en browser should default to English');
  await shot('01-login-desktop-en');
  await page.type('input[type=password]', PW);
  await page.click('button[type=submit]');
  await page.waitForSelector('nav.side');
  const cookies = await page.cookies();
  const c = cookies.find((x) => x.name.includes('sshmcp_session'));
  if (!c || !c.httpOnly || c.sameSite !== 'Strict') throw new Error('session cookie flags wrong: ' + JSON.stringify(c));
  if (await page.evaluate(() => document.cookie.includes('sshmcp'))) throw new Error('cookie readable by JS');
  await waitText('Recent activity');
  const font = await page.evaluate(async () => { await document.fonts.ready; return getComputedStyle(document.body).fontFamily; });
  if (!font.includes('Vazirmatn')) throw new Error('font stack missing Vazirmatn: ' + font);
});

const name = 'e2e-' + Date.now();
await step('add server via form', async () => {
  await go('servers');
  await click('[data-action="add-server"]');
  await page.waitForSelector('.modal');
  const inputs = await page.$$('.modal input');
  await inputs[0].type(name);
  await inputs[1].type('127.0.0.1');
  await inputs[2].evaluate((el) => { el.value = '2222'; });
  await inputs[3].type('sshtest');
  await page.type('.modal input[type=password]', 'T3stPassw0rd!');
  await shot('03-add-server-desktop');
  await click('.modal [data-action="save"]');
  await page.waitForSelector(`.card[data-server="${name}"]`);
});

await step('TOFU: connect shows fingerprint, approve, test ok', async () => {
  await inCard(name, 'connect');
  await page.waitForSelector(`.card[data-server="${name}"] [data-action="approve-key"]`, { timeout: 15000 });
  const fp = await page.$eval(`.card[data-server="${name}"] [data-role=hostkey-pending] .mono`, (e) => ({ t: e.textContent, d: getComputedStyle(e).direction }));
  if (!/SHA256:/.test(fp.t) || fp.d !== 'ltr') throw new Error('fingerprint not shown LTR: ' + JSON.stringify(fp));
  await shot('04-hostkey-pending');
  await inCard(name, 'approve-key');
  await page.waitForFunction((n) => { const c = document.querySelector(`.card[data-server="${n}"]`); return c && !c.querySelector('[data-action="approve-key"]'); }, { timeout: 10000 }, name);
  await inCard(name, 'test');
  await page.waitForSelector(`.card[data-server="${name}"] .pill.s-connected`, { timeout: 15000 });
  await inCard(name, 'history');
  await page.waitForFunction((n) => document.querySelector(`.card[data-server="${n}"] table`), { timeout: 10000 }, name);
  await shot('05-servers-desktop');
});

await step('edit form never shows secrets', async () => {
  await inCard(name, 'edit');
  await page.waitForSelector('.modal');
  const pw = await page.$eval('.modal input[type=password]', (e) => ({ v: e.value, p: e.placeholder }));
  if (pw.v !== '' || !/unchanged/.test(pw.p)) throw new Error('password field: ' + JSON.stringify(pw));
  const html = await page.content();
  if (html.includes('T3stPassw0rd!')) throw new Error('password leaked into DOM');
  await click('.modal [data-action="cancel"]');
  await page.waitForFunction(() => !document.querySelector('.modal'));
});

await step('terminal runs a real command with separated stderr and exit code', async () => {
  await go('terminal');
  await page.waitForSelector('main .term');
  await pickServer(name);
  await page.type('main input[data-role=cmd]', 'echo hello-from-e2e; echo to-stderr >&2; uname -s; exit 4');
  await page.keyboard.press('Enter');
  await waitText('[completed');
  const errText = await page.$eval('.term', (t) => [...t.querySelectorAll('span.err')].map((s) => s.textContent).join(''));
  if (!errText.includes('to-stderr')) throw new Error('stderr not highlighted');
  const out = await page.$eval('.term', (t) => t.innerText);
  if (!out.includes('hello-from-e2e') || !out.includes('Linux')) throw new Error('stdout missing');
  const badge = await page.$eval('[data-role=exit]', (b) => ({ t: b.textContent, c: b.className }));
  if (!badge.t.includes('4') || !badge.c.includes('bad')) throw new Error('exit badge: ' + JSON.stringify(badge));
  await shot('07-terminal-desktop');
});

await step('terminal destructive command shows confirmation dialog', async () => {
  await page.type('main input[data-role=cmd]', 'rm -rf /tmp/e2e-nonexistent');
  await page.keyboard.press('Enter');
  await page.waitForSelector('.modal .dangerbox');
  await shot('08-destructive-confirm');
  await click('.modal [data-action="cancel"]');
  await page.waitForFunction(() => !document.querySelector('.modal'));
});

await step('terminal cancel stops a long command', async () => {
  await page.type('main input[data-role=cmd]', 'sleep 120');
  await page.keyboard.press('Enter');
  await sleep(1500);
  await click('[data-action="stop"]');
  await waitText('[cancelled', 15000);
});

await step('terminal quick-command chips and history sheet', async () => {
  await page.evaluate(() => [...document.querySelectorAll('.chip')].find((c) => c.textContent === 'uptime').click());
  if (await page.$eval('main input[data-role=cmd]', (i) => i.value) !== 'uptime') throw new Error('chip did not fill input');
  await page.$eval('main input[data-role=cmd]', (i) => { i.value = ''; });
  await click('[data-action="history"]');
  await page.waitForSelector('.modal .sheet-item');
  const n = await page.$$eval('.modal .sheet-item', (x) => x.map((e) => e.textContent));
  if (!n.some((x) => x.includes('sleep 120'))) throw new Error('history missing: ' + n.join('|'));
  await page.evaluate(() => [...document.querySelectorAll('.modal .sheet-item')].find((e) => e.textContent.includes('uname')).click());
  if (!(await page.$eval('main input[data-role=cmd]', (i) => i.value)).includes('uname')) throw new Error('history pick did not fill');
  await page.$eval('main input[data-role=cmd]', (i) => { i.value = ''; });
  await page.focus('main input[data-role=cmd]');
  await page.keyboard.press('ArrowUp');
  if (!(await page.$eval('main input[data-role=cmd]', (i) => i.value))) throw new Error('ArrowUp history empty');
  await page.$eval('main input[data-role=cmd]', (i) => { i.value = ''; });
});

const askText = async (value) => {
  await page.waitForSelector('.modal input[type=text]');
  await page.$eval('.modal input[type=text]', (i, v) => { i.value = v; }, value);
  await click('.modal [data-action="ok"]');
};
await step('file manager: browse, mkdir, upload, open/edit, rename, grid, delete', async () => {
  await go('files');
  await page.waitForSelector('main .flist');
  await pickServer(name);
  await page.waitForFunction(() => document.querySelector('[data-role=crumb]')?.innerText.replace(/\s/g, '').includes('/home/sshtest'), { timeout: 15000 });
  await click('[data-action="mkdir"]');
  await askText('e2e-dir');
  await page.waitForSelector('.frow[data-name="e2e-dir"]');
  await page.evaluate(() => document.querySelector('.frow[data-name="e2e-dir"] .fname').click());
  await page.waitForFunction(() => document.querySelector('[data-role=crumb]').innerText.replace(/\s/g, '').endsWith('/e2e-dir'), { timeout: 15000 });
  fs.writeFileSync('/tmp/e2e-upload.txt', 'uploaded via e2e\n');
  const input = await page.$('main input[type=file]');
  await input.uploadFile('/tmp/e2e-upload.txt');
  await page.waitForSelector('.frow[data-name="e2e-upload.txt"]', { timeout: 15000 });
  await page.evaluate(() => document.querySelector('.frow[data-name="e2e-upload.txt"] .fname').click());
  await page.waitForSelector('main [data-role=editor] textarea');
  const content = await page.$eval('main textarea', (t) => t.value);
  if (content !== 'uploaded via e2e\n') throw new Error('content: ' + JSON.stringify(content));
  if (!(await page.$eval('.editor .gutter', (g) => g.textContent)).startsWith('1\n')) throw new Error('no line numbers');
  await page.$eval('main textarea', (t) => { t.value = 'edited in browser\nline 2\n'; t.dispatchEvent(new Event('input')); });
  await click('[data-action="save-file"]');
  await sleep(800);
  await shot('09-files-desktop');
  await click('.frow[data-name="e2e-upload.txt"] [data-action="rename"]');
  await askText('/home/sshtest/e2e-dir/renamed.txt');
  await page.waitForSelector('.frow[data-name="renamed.txt"]', { timeout: 15000 });
  await page.evaluate(() => [...document.querySelectorAll('.seg button')].find((b) => b.dataset.value === 'grid').click());
  if (!(await page.$('.flist.gridmode'))) throw new Error('grid view not applied');
  await page.evaluate(() => [...document.querySelectorAll('.seg button')].find((b) => b.dataset.value === 'list').click());
  await click('[data-action="up"]');
  await page.waitForSelector('.frow[data-name="e2e-dir"] [data-action="delete"]', { timeout: 15000 });
  await click('.frow[data-name="e2e-dir"] [data-action="delete"]');
  await page.waitForSelector('.modal');
  await page.click('.modal input[type=checkbox]');
  await click('.modal [data-action="confirm-delete"]');
  await page.waitForFunction(() => !document.querySelector('.frow[data-name="e2e-dir"]'), { timeout: 10000 });
});

let token = '';
await step('MCP page: URL, token creation, Claude steps, config snippets', async () => {
  await go('mcp');
  await waitText('/mcp');
  await page.type('main [data-role=token-name]', 'e2e-token');
  await click('[data-action="create-token"]');
  await page.waitForSelector('[data-role=new-token] [data-copy=token]');
  token = await page.$eval('[data-copy=token]', (e) => e.textContent);
  if (!token.startsWith('sshmcp_')) throw new Error('token: ' + token.slice(0, 7));
  const cfg = await page.$eval('pre.code', (p) => p.textContent);
  if (!cfg.includes('Authorization') || !cfg.includes('/mcp')) throw new Error('config snippet missing');
  const hv = await page.$eval('[data-copy=header-value]', (e) => e.textContent);
  if (hv !== 'Bearer ' + token) throw new Error('header value not filled');
  if (await page.$eval('[data-copy=header-name]', (e) => e.textContent) !== 'Authorization') throw new Error('header name');
  if (!(await page.$eval('[data-role=claude-steps]', (e) => e.innerText)).includes('No sign-in')) throw new Error('Claude steps missing');
  await page.evaluate(() => [...document.querySelectorAll('.tabs button')].find((b) => b.dataset.k === 'code').click());
  if (!(await page.$eval('pre[data-cfg=code]', (p) => p.textContent)).startsWith('claude mcp add')) throw new Error('claude code snippet');
  await shot('10-mcp-desktop');
});

await step('settings, audit and approvals pages render', async () => {
  await go('settings'); await waitText('Idle disconnect'); await shot('11-settings-desktop');
  await go('audit'); await waitText('auth.login'); await shot('12-audit-desktop');
  await go('approvals'); await page.waitForFunction(() => document.querySelector('[data-role=no-pending], [data-role=approve-bar]'), { timeout: 15000 });
});

await step('1440 en: auto-approve quick switch, one-tap approve, approve all, Auto badge', async () => {
  const stamp = Date.now();
  for (const i of [1, 2, 3]) {
    const r = await mcpTool(token, 'execute_command', { server: name, command: `rm -rf /tmp/e2e-aa-${stamp}-${i}` });
    if (r.status !== 'confirmation_required') throw new Error('expected pending: ' + JSON.stringify(r));
  }
  await go('approvals');
  await page.waitForSelector('[data-role=approve-bar] [data-action="approve-all"]');
  await page.waitForSelector(`[data-role=aa-card] .aa-item[data-server="${name}"] [data-role=auto-approve]`);
  if ((await page.$$('[data-confirmation]')).length < 3) throw new Error('pending cards missing');
  // one tap approves a single item
  const firstId = await page.$eval('[data-confirmation]', (c) => c.dataset.confirmation);
  await click(`[data-confirmation="${firstId}"] [data-action="approve"]`);
  await page.waitForSelector(`[data-confirmation="${firstId}"][data-approved=true]`);
  await shot('17-approvals-desktop-en');
  // approve all (with confirmation sheet)
  await click('[data-action="approve-all"]');
  await page.waitForSelector('.modal [data-action="approve-all-confirm"]');
  await click('.modal [data-action="approve-all-confirm"]');
  await page.waitForFunction(() => !document.querySelector('.modal'));
  await page.waitForFunction(() => document.querySelector('[data-role=no-pending]'), { timeout: 10000 });
  const pend = await pageApi('/confirmations?status=pending');
  if (pend.length) throw new Error('still pending after approve all: ' + pend.length);
  // quick switch -> safe; destructive MCP command now runs directly
  await click(`.aa-item[data-server="${name}"] [data-value="safe"]`);
  await page.waitForFunction(async (n) => { const r = await fetch('/api/servers'); const j = await r.json(); return j.find((s) => s.name === n).auto_approve === 'safe'; }, { timeout: 10000 }, name);
  if (!(await page.$eval(`.aa-item[data-server="${name}"] [data-role=aa-hint]`, (e) => e.className)).includes('safe')) throw new Error('hint did not switch');
  const auto = await mcpTool(token, 'execute_command', { server: name, command: `mkdir -p /tmp/e2e-aa-${stamp}-x && rm -rf /tmp/e2e-aa-${stamp}-x` });
  if (auto.status !== 'completed' || auto.auto_approved !== true || auto.auto_approve_level !== 'safe') throw new Error('not auto-approved: ' + JSON.stringify(auto));
  // "all" requires the typed confirmation
  await click(`.aa-item[data-server="${name}"] [data-value="all"]`);
  await page.waitForSelector('.modal [data-role=aa-confirm-input]');
  if (!(await page.$eval('.modal [data-action="aa-confirm"]', (b) => b.disabled))) throw new Error('enable button must start disabled');
  await page.type('.modal [data-role=aa-confirm-input]', 'nope');
  if (!(await page.$eval('.modal [data-action="aa-confirm"]', (b) => b.disabled))) throw new Error('wrong word must not enable');
  await page.keyboard.press('Escape');
  await page.waitForFunction(() => !document.querySelector('.modal'));
  if ((await serverByName(name)).auto_approve !== 'safe') throw new Error('cancel must keep safe');
  if (await page.$eval(`.aa-item[data-server="${name}"] [data-value="safe"]`, (b) => b.getAttribute('aria-pressed')) !== 'true') throw new Error('control did not revert');
  await click(`.aa-item[data-server="${name}"] [data-value="all"]`);
  await page.waitForSelector('.modal [data-role=aa-confirm-input]');
  await page.type('.modal [data-role=aa-confirm-input]', 'CONFIRM');
  await click('.modal [data-action="aa-confirm"]');
  await page.waitForFunction(async (n) => { const r = await fetch('/api/servers'); const j = await r.json(); return j.find((s) => s.name === n).auto_approve === 'all'; }, { timeout: 10000 }, name);
  await click(`.aa-item[data-server="${name}"] [data-value="off"]`);
  await page.waitForFunction(async (n) => { const r = await fetch('/api/servers'); const j = await r.json(); return j.find((s) => s.name === n).auto_approve === 'off'; }, { timeout: 10000 }, name);
  await assertNoOverflow('desktop-en approvals');
  // Auto badge in Audit and Overview activity
  await go('audit'); await page.waitForSelector('[data-role=auto-badge]');
  if (!(await page.$eval('[data-role=auto-badge]', (e) => e.textContent)).includes('Auto')) throw new Error('audit badge text');
  await go('overview'); await page.waitForSelector('.timeline [data-role=auto-badge]');
  // server card quick switch + pill
  await go('servers');
  await click(`.card[data-server="${name}"] [data-role=aa-quick] [data-value="safe"]`);
  await page.waitForSelector(`.card[data-server="${name}"] .pill.aa-safe`, { timeout: 10000 });
  await click(`.card[data-server="${name}"] [data-role=aa-quick] [data-value="off"]`);
  await page.waitForFunction((n) => !document.querySelector(`.card[data-server="${n}"] .pill.aa-safe`), { timeout: 10000 }, name);
  // Settings: global default control exists
  await go('settings'); await page.waitForSelector('[data-role=aa-default] [data-value="off"][aria-pressed=true]');
});

await step('sidebar collapses and expands', async () => {
  await click('[data-action="collapse"]');
  await page.waitForSelector('.shell.collapsed');
  await click('[data-action="collapse"]');
  await page.waitForFunction(() => !document.querySelector('.shell.collapsed'));
});

const VIEWS = ['overview', 'servers', 'terminal', 'files', 'mcp', 'approvals', 'settings', 'audit'];
await step('desktop 1440 en: every view without horizontal overflow', async () => {
  for (const v of VIEWS) { await go(v); await sleep(500); await assertNoOverflow('desktop-en ' + v); }
  await go('overview'); await waitText('Recent activity'); await shot('02-overview-desktop-en');
});

await step('Persian RTL toggle (desktop 1440 fa) + bidi isolation + overflow', async () => {
  await setLang('fa');
  await waitText('نمای کلی');
  for (const v of VIEWS) { await go(v); await sleep(500); await assertNoOverflow('desktop-fa ' + v); }
  await go('servers');
  const d = await page.$eval(`.card[data-server="${name}"] .t2 .ltr`, (e) => ({ dir: getComputedStyle(e).direction, ub: getComputedStyle(e).unicodeBidi, t: e.textContent }));
  if (d.dir !== 'ltr' || d.ub !== 'isolate' || !d.t.startsWith('sshtest@127.0.0.1')) throw new Error('host not isolated LTR: ' + JSON.stringify(d));
  await go('overview'); await shot('13-overview-desktop-fa');
  await go('terminal'); await pickServer(name);
  await page.type('main input[data-role=cmd]', 'echo "سلام from $(hostname)"; ls -la / | head -n 6');
  await page.keyboard.press('Enter'); await waitText('[completed');
  const td = await page.$eval('.term', (e) => getComputedStyle(e).direction);
  if (td !== 'ltr') throw new Error('terminal must be LTR in fa');
  await shot('15-terminal-desktop-fa');
  await go('mcp'); await shot('16-mcp-desktop-fa');
});

await step('phone 390x844 fa: bottom nav, sheets, no overflow on any view', async () => {
  await page.setViewport(PHONE);
  await page.reload({ waitUntil: 'networkidle0' });
  await page.waitForSelector('.tabbar');
  if (await page.$eval('nav.side', (e) => getComputedStyle(e).display) !== 'none') throw new Error('sidebar visible on phone');
  const tabs = await page.$$eval('.tabbar .tab', (x) => x.map((e) => { const r = e.getBoundingClientRect(); return { v: e.dataset.view, h: r.height, w: r.width }; }));
  if (tabs.map((x) => x.v).join() !== 'overview,servers,terminal,files,mcp') throw new Error('tabs: ' + JSON.stringify(tabs));
  if (tabs.some((x) => x.h < 44 || x.w < 44)) throw new Error('touch targets too small: ' + JSON.stringify(tabs));
  for (const v of VIEWS) { await go(v); await sleep(600); await assertNoOverflow('phone-fa ' + v); }
  await go('overview'); await waitText('فعالیت‌های اخیر'); await shot('20-overview-mobile-fa');
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight)); await shot('21-overview-mobile-fa-bottom'); await page.evaluate(() => window.scrollTo(0, 0));
  await go('servers'); await shot('22-servers-mobile-fa');
  await click('[data-action="add-server"]'); await page.waitForSelector('.modal'); await sleep(600);
  const pos = await page.$eval('.modal', (m) => { const r = m.getBoundingClientRect(); return { bottom: Math.round(r.bottom), h: innerHeight }; });
  if (Math.abs(pos.bottom - pos.h) > 2) throw new Error('modal is not a bottom sheet on phone: ' + JSON.stringify(pos));
  await sleep(400); await assertNoOverflow('phone-fa server form'); await shot('23-server-form-sheet-mobile-fa');
  await click('.modal [data-action="cancel"]');
  await go('terminal'); await pickServer(name);
  await page.type('main input[data-role=cmd]', 'echo hello; echo oops >&2; df -h / | tail -n 1');
  await page.keyboard.press('Enter'); await waitText('[completed');
  await page.$eval('main input[data-role=cmd]', (i) => i.blur()); await sleep(200);
  const th = await page.$eval('.term', (e) => e.getBoundingClientRect().height);
  if (th < 300) throw new Error('terminal should fill the phone screen, height=' + th);
  await assertNoOverflow('phone-fa terminal output'); await shot('24-terminal-mobile-fa');
  await go('files'); await pickServer(name);
  await page.waitForFunction(() => document.querySelector('[data-role=crumb]')?.innerText.replace(/\s/g, '').includes('/home/sshtest'), { timeout: 15000 });
  await page.waitForSelector('.frow .kebab');
  await assertNoOverflow('phone-fa files'); await shot('25-files-mobile-fa');
  await page.evaluate(() => document.querySelector('.frow .kebab').click());
  await page.waitForSelector('.modal .sheet-item[data-action="rename"]'); await shot('26-file-actions-sheet-mobile-fa');
  await page.keyboard.press('Escape'); await page.waitForFunction(() => !document.querySelector('.modal'));
  await go('mcp'); await shot('27-mcp-mobile-fa');
  await page.evaluate(() => document.querySelector('[data-role=claude-steps]').scrollIntoView()); await shot('28-mcp-claude-steps-mobile-fa');
  await click('[data-action="more"]'); await page.waitForSelector('.modal .sheet-item'); await shot('29-more-sheet-mobile-fa');
  await click('.sheet-item[data-action="settings"]'); await page.waitForSelector('main.v-settings .view');
});

await step('390x844 fa: auto-approve control in the server sheet + approve all', async () => {
  await setLang('fa');
  await go('servers');
  await inCard(name, 'edit');
  await page.waitForSelector('.modal [data-role=aa-field] [data-role=auto-approve]');
  await sleep(500);
  await page.evaluate(() => document.querySelector('.modal [data-role=aa-field] [data-value="all"]').click());
  await page.waitForFunction(() => !document.querySelector('.modal [data-role=aa-all-warning]').classList.contains('hidden'));
  const btns = await page.$$eval('.modal [data-role=aa-field] [data-role=auto-approve] button', (x) => x.map((b) => { const r = b.getBoundingClientRect(); return { t: b.textContent, h: r.height, w: r.width }; }));
  if (btns.map((b) => b.t).join('|') !== 'خاموش|ایمن|همه') throw new Error('fa labels: ' + JSON.stringify(btns));
  if (btns.some((b) => b.h < 44)) throw new Error('auto-approve targets too small: ' + JSON.stringify(btns));
  await page.evaluate(() => document.querySelector('.modal [data-role=aa-field]').scrollIntoView({ block: 'start' }));
  await assertNoOverflow('phone-fa server sheet auto-approve');
  await shot('31-server-sheet-auto-approve-mobile-fa');
  // saving "all" without the typed word is refused client-side
  await click('.modal [data-action="save"]');
  await sleep(300);
  if ((await serverByName(name)).auto_approve !== 'off') throw new Error('saved all without confirmation');
  await page.evaluate(() => document.querySelector('.modal [data-role=aa-field] [data-value="safe"]').click());
  await page.waitForFunction(() => document.querySelector('.modal [data-role=aa-all-warning]').classList.contains('hidden'));
  await click('.modal [data-action="save"]');
  await page.waitForFunction(() => !document.querySelector('.modal'), { timeout: 10000 });
  await page.waitForSelector(`.card[data-server="${name}"] .pill.aa-safe`, { timeout: 10000 });
  if ((await serverByName(name)).auto_approve !== 'safe') throw new Error('sheet did not save safe');
  // a catastrophic op still waits for approval at "safe"; approve all on the phone
  const stamp = Date.now();
  const p1 = await mcpTool(token, 'execute_command', { server: name, command: `echo x >> /tmp/e2e-${stamp}/authorized_keys` });
  if (p1.status !== 'confirmation_required') throw new Error('catastrophic should wait: ' + JSON.stringify(p1));
  const srv = await serverByName(name);
  await page.evaluate(async (id) => { const me = await (await fetch('/api/auth/me')).json(); await fetch('/api/servers/' + id + '/auto-approve', { method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': me.csrf }, body: JSON.stringify({ level: 'off' }) }); }, srv.id);
  const p2 = await mcpTool(token, 'execute_command', { server: name, command: `rm -rf /tmp/e2e-${stamp}-b` });
  if (p2.status !== 'confirmation_required') throw new Error('off should wait: ' + JSON.stringify(p2));
  await go('approvals');
  await page.waitForSelector('[data-role=approve-bar] [data-action="approve-all"]');
  const tap = await page.$eval('[data-role=approve-bar] [data-action="approve-all"]', (b) => b.getBoundingClientRect().height);
  if (tap < 44) throw new Error('approve-all target too small: ' + tap);
  const one = await page.$eval('[data-confirmation] [data-action="approve"]', (b) => b.getBoundingClientRect().height);
  if (one < 44) throw new Error('approve target too small: ' + one);
  if (!(await page.$eval('[data-role=approve-bar]', (e) => e.innerText)).includes('تأیید همه')) throw new Error('fa approve-all label');
  await assertNoOverflow('phone-fa approvals with pending');
  await shot('32-approvals-mobile-fa');
  await click('[data-action="approve-all"]');
  await page.waitForSelector('.modal [data-action="approve-all-confirm"]');
  await sleep(300); await shot('33-approve-all-sheet-mobile-fa');
  await click('.modal [data-action="approve-all-confirm"]');
  await page.waitForFunction(() => document.querySelector('[data-role=no-pending]'), { timeout: 10000 });
  if ((await pageApi('/confirmations?status=pending')).length) throw new Error('pending left');
  await go('audit'); await page.waitForSelector('[data-role=auto-badge]');
  if (!(await page.$eval('[data-role=auto-badge]', (e) => e.textContent)).includes('خودکار')) throw new Error('fa badge');
  await assertNoOverflow('phone-fa audit');
});

await step('settings explains that a secret-based admin password is changed outside the dashboard', async () => {
  await page.setViewport(DESKTOP);
  await go('settings');
  await page.waitForSelector('[data-role="pw-secret"]');
  if (await page.$('[data-action="change-password"]')) throw new Error('change-password form shown although the password comes from the secret');
  await go('overview');
  await page.setViewport(PHONE);
});

await step('phone 390x844 en: no overflow + bottom nav', async () => {
  await setLang('en');
  for (const v of VIEWS) { await go(v); await sleep(600); await assertNoOverflow('phone-en ' + v); }
  await go('overview'); await waitText('Recent activity'); await shot('30-overview-mobile-en');
});

await step('English is the default even for a fa browser; Persian via toggle (fresh profile)', async () => {
  const ctx = await browser.createBrowserContext();
  const p2 = await ctx.newPage();
  await p2.setExtraHTTPHeaders({ 'accept-language': 'fa-IR,fa;q=0.9' });
  await p2.evaluateOnNewDocument(() => { Object.defineProperty(navigator, 'languages', { get: () => ['fa-IR', 'fa'] }); Object.defineProperty(navigator, 'language', { get: () => 'fa-IR' }); });
  await p2.setViewport(PHONE);
  await p2.goto(BASE + '/', { waitUntil: 'networkidle0' });
  await p2.waitForSelector('input[type=password]');
  const l = await p2.evaluate(() => [document.documentElement.lang, document.documentElement.dir]);
  if (l.join() !== 'en,ltr') throw new Error('expected en/ltr default, got ' + l);
  await p2.evaluate(() => localStorage.setItem('lang', 'fa'));
  await p2.reload({ waitUntil: 'networkidle0' });
  await p2.waitForSelector('input[type=password]');
  const l2 = await p2.evaluate(() => [document.documentElement.lang, document.documentElement.dir]);
  if (l2.join() !== 'fa,rtl') throw new Error('expected fa/rtl after choosing Persian, got ' + l2);
  await sleep(300); await p2.screenshot({ path: `${OUT}/19-login-mobile-fa.png` });
  await ctx.close();
});

await step('logout', async () => {
  await page.setViewport(DESKTOP);
  await page.reload({ waitUntil: 'networkidle0' });
  await page.waitForSelector('nav.side');
  await click('nav.side [data-action="logout"]');
  await page.waitForSelector('input[type=password]');
});

await step('no console errors / CSP violations', async () => {
  const real = consoleErrors.filter((e) => !/Failed to load resource: the server responded with a status of (401|409|502)/.test(e));
  if (real.length) throw new Error(real.join(' | '));
});

await browser.close();
fs.writeFileSync(`${OUT}/results.json`, JSON.stringify(results, null, 2));
const failed = results.filter((r) => r[0] === 'FAIL').length;
console.log(`\nE2E: ${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
