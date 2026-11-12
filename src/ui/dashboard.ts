// Single-page dashboard served by the Worker. No external assets: the stylesheet and script are
// inlined under the per-request CSP nonce, icons are inline SVG and the only other asset is the
// same-origin Vazirmatn font (/assets/vazirmatn.woff2, allowed by font-src 'self').
// All dynamic text is inserted with textContent (no innerHTML with untrusted data). Credentials are
// never sent to the browser: the edit form shows "set / unchanged" placeholders only.
// Design: mobile-first (bottom tab bar + bottom sheets on phones, collapsible sidebar on tablet/desktop),
// dark layered theme, Persian RTL first-class with LTR islands for commands/paths/IPs/tokens.

import { CSS } from './styles';
import { JS } from './client';

export function renderDashboard(nonce: string): string {
  return `<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#060a13">
<meta name="robots" content="noindex, nofollow">
<title>SSH MCP</title>
<link rel="preload" href="/assets/vazirmatn.woff2" as="font" type="font/woff2" crossorigin>
<style nonce="${nonce}">${CSS}</style>
</head>
<body>
<div id="app"></div>
<script nonce="${nonce}">${JS}</script>
</body>
</html>`;
}
