import puppeteer from 'puppeteer-core';
// Live smoke check of the deployed login page (desktop en + phone fa). Honors HTTPS_PROXY (credentials read
// from the environment, never printed). Usage: node scripts/live-check.mjs https://<your-worker>.workers.dev/
const URL_ = process.argv[2] ?? process.env.BASE;
if (!URL_) { console.error('usage: node scripts/live-check.mjs https://<your-worker>.workers.dev/'); process.exit(2); }
const px = process.env.HTTPS_PROXY ? new URL(process.env.HTTPS_PROXY) : null;
const args = ['--no-sandbox']; if (px) args.push(`--proxy-server=${px.hostname}:${px.port}`);
const b = await puppeteer.launch({ executablePath: process.env.CHROME ?? '/usr/bin/chromium', args, headless: true, acceptInsecureCerts: !!px });
const out = [];
for (const [lang, vp] of [['en', { width: 1440, height: 900 }], ['fa', { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true }]]) {
  const p = await b.newPage(); const errs = [];
  if (px && px.username) await p.authenticate({ username: decodeURIComponent(px.username), password: decodeURIComponent(px.password) });
  p.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); }); p.on('pageerror', (e) => errs.push(e.message));
  if (lang === 'fa') await p.evaluateOnNewDocument(() => { try { localStorage.setItem('lang', 'fa'); } catch {} });
  await p.setViewport(vp);
  await p.goto(URL_, { waitUntil: 'networkidle0' });
  await p.waitForSelector('input[type=password]', { timeout: 15000 });
  const info = await p.evaluate(async () => { await document.fonts.ready; return { lang: document.documentElement.lang, dir: document.documentElement.dir, h1: document.querySelector('h1')?.textContent, submit: !!document.querySelector('button[type=submit]'), overflow: document.documentElement.scrollWidth > innerWidth, vazir: [...document.fonts].some((f) => f.family.includes('Vazirmatn') && f.status === 'loaded') }; });
  await p.screenshot({ path: `test/e2e/screenshots/live-login-${lang}.png` });
  out.push(`live login (${lang}, ${vp.width}px): ${JSON.stringify(info)} consoleErrors=${errs.length}${errs.length ? ' ' + errs.join(' | ') : ''}`);
}
console.log(out.join('\n')); await b.close();
