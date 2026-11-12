// Dashboard stylesheet. Served inline under the per-request CSP nonce (style-src 'nonce-…').
// Mobile-first; logical properties everywhere so RTL (Persian) and LTR share one sheet.
// No inline style attributes are used anywhere (they would be blocked by the CSP).

export const CSS = String.raw`
@font-face{font-family:"Vazirmatn";src:url(/assets/vazirmatn.woff2) format("woff2");font-weight:100 900;font-style:normal;font-display:swap;
 unicode-range:U+0600-06FF,U+200C-200F,U+2010-2011,U+204F,U+2E41,U+FB50-FDFF,U+FE70-FEFC}
:root{
 --bg:#060a13;--bg2:#0a1020;--s1:#0e1526;--s2:#131c31;--s3:#1a2540;--s4:#22304f;
 --line:rgba(148,165,210,.13);--line2:rgba(148,165,210,.22);
 --text:#e9eef9;--text2:#c3cce0;--muted:#97a3bf;--faint:#6f7c99;
 --accent:#7c9bff;--accent-strong:#4867f0;--accent-soft:rgba(124,155,255,.14);--accent2:#a78bfa;
 --ok:#3ddc97;--ok-soft:rgba(61,220,151,.13);--warn:#fbbf24;--warn-soft:rgba(251,191,36,.12);
 --bad:#fb7185;--bad-soft:rgba(251,113,133,.13);--info:#60a5fa;
 --font:"Vazirmatn",system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans",Tahoma,sans-serif;
 --mono:ui-monospace,"JetBrains Mono","SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
 --r-sm:8px;--r:12px;--r-lg:16px;--r-xl:22px;
 --sp1:4px;--sp2:8px;--sp3:12px;--sp4:16px;--sp5:20px;--sp6:24px;--sp8:32px;
 --top-h:60px;--tab-h:64px;--side-w:248px;--side-w-c:76px;
 --safe-b:env(safe-area-inset-bottom,0px);--safe-t:env(safe-area-inset-top,0px);
 --safe-l:env(safe-area-inset-left,0px);--safe-r:env(safe-area-inset-right,0px);
 --shadow:0 10px 30px -12px rgba(0,0,0,.6),0 2px 6px rgba(0,0,0,.25);
 --ease:cubic-bezier(.2,.8,.2,1);
}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%;background:var(--bg);color-scheme:dark}
html,body{margin:0;min-height:100%;overflow-x:clip}
body{background:radial-gradient(1200px 600px at 100% -10%,rgba(72,103,240,.16),transparent 60%),radial-gradient(900px 500px at -10% 110%,rgba(167,139,250,.10),transparent 60%),var(--bg);
 background-attachment:fixed;color:var(--text);font:15px/1.6 var(--font);-webkit-font-smoothing:antialiased;-webkit-tap-highlight-color:transparent;min-height:100dvh}
html.modal-open,html.modal-open body{overflow:hidden}
button,input,select,textarea{font:inherit;color:inherit;letter-spacing:inherit}
a{color:var(--accent)}
svg{flex:none}
h1,h2,h3{margin:0;line-height:1.3;font-weight:700}
h2{font-size:16px}h3{font-size:14px}
p{margin:0}
:focus{outline:none}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:var(--r-sm)}
::selection{background:rgba(124,155,255,.35)}
.ltr{direction:ltr;unicode-bidi:isolate}
.bidi{unicode-bidi:isolate}
.mono,.code,.term,.crumbs,code{font-family:var(--mono)}
.mono{font-size:12.5px;overflow-wrap:anywhere}
code{display:inline-block;max-width:100%;vertical-align:baseline;line-height:1.5;font-size:.9em;background:var(--s3);border:1px solid var(--line);padding:0 6px;border-radius:6px;direction:ltr;unicode-bidi:isolate;overflow-wrap:anywhere}
.muted{color:var(--muted)}.faint{color:var(--faint)}.error{color:var(--bad)}.okc{color:var(--ok)}
.hidden{display:none!important}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.grow{flex:1 1 auto;min-width:0}
.trunc{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}

/* ---------- shell ---------- */
.shell{min-height:100dvh;display:block}
.side{display:none}
.topbar{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:var(--sp2);
 min-height:calc(var(--top-h) + var(--safe-t));padding:var(--safe-t) calc(var(--sp4) + var(--safe-r)) 0 calc(var(--sp4) + var(--safe-l));
 background:rgba(6,10,19,.72);backdrop-filter:saturate(160%) blur(14px);-webkit-backdrop-filter:saturate(160%) blur(14px);border-bottom:1px solid var(--line)}
.topbar h1{font-size:18px;flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.topbar .logo{display:inline-flex}
.top-actions{display:flex;align-items:center;gap:6px}
.logo{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;color:#fff;
 background:linear-gradient(135deg,#5b7cfa,#a78bfa);box-shadow:0 6px 18px -6px rgba(91,124,250,.7)}
.iconbtn{position:relative;display:inline-grid;place-items:center;width:44px;height:44px;border-radius:12px;border:1px solid transparent;background:transparent;color:var(--text2);cursor:pointer;transition:background .15s,color .15s}
.iconbtn:hover{background:var(--s2);color:var(--text)}
.iconbtn .badge{position:absolute;top:4px;inset-inline-end:4px}
main{display:block;padding:var(--sp4) calc(var(--sp4) + var(--safe-r)) calc(var(--tab-h) + var(--safe-b) + var(--sp6)) calc(var(--sp4) + var(--safe-l));
 max-width:1480px;margin-inline:auto;min-width:0;animation:fadeUp .28s var(--ease)}
.page-sub{color:var(--muted);font-size:13.5px;margin:-2px 0 var(--sp4)}

/* bottom tab bar (phones) */
.tabbar{position:fixed;inset-inline:0;bottom:0;z-index:40;display:grid;grid-template-columns:repeat(5,1fr);
 padding:6px calc(6px + var(--safe-r)) calc(6px + var(--safe-b)) calc(6px + var(--safe-l));
 background:rgba(10,15,28,.86);backdrop-filter:saturate(160%) blur(16px);-webkit-backdrop-filter:saturate(160%) blur(16px);border-top:1px solid var(--line)}
.tab{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;min-height:52px;border:0;background:none;color:var(--muted);
 font-size:11.5px;font-weight:600;border-radius:14px;cursor:pointer;padding:4px 2px;transition:color .15s}
.tab svg{width:22px;height:22px;transition:transform .2s var(--ease)}
.tab .tab-ic{display:grid;place-items:center;width:56px;height:30px;border-radius:99px;transition:background .2s var(--ease)}
.tab.active{color:var(--text)}
.tab.active .tab-ic{background:var(--accent-soft);color:var(--accent)}
.tab span.lbl{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
body.typing .tabbar{display:none}
body.typing main{padding-bottom:var(--sp4)}

@media (min-width:768px){
 .shell{display:grid;grid-template-columns:var(--side-w) minmax(0,1fr)}
 .shell.collapsed{grid-template-columns:var(--side-w-c) minmax(0,1fr)}
 .shell>.content{min-width:0}
 .side{display:flex;flex-direction:column;gap:2px;position:sticky;top:0;height:100dvh;padding:var(--sp4) var(--sp3);
  background:linear-gradient(180deg,rgba(14,21,38,.95),rgba(10,16,32,.95));border-inline-end:1px solid var(--line);overflow-y:auto;overflow-x:hidden}
 .tabbar{display:none}
 .topbar .logo,.topbar .m-only{display:none}
 main{padding:var(--sp6) var(--sp6) var(--sp8)}
 .topbar{padding-inline:var(--sp6)}
}
@media (min-width:1200px){main{padding:var(--sp8) var(--sp8) 48px}.topbar{padding-inline:var(--sp8)}}
@media (max-width:767.98px){.d-only{display:none!important}}

.brand{display:flex;align-items:center;gap:10px;padding:4px 8px 18px;min-height:52px}
.brand .name{font-weight:800;font-size:16px;letter-spacing:.2px}
.brand .tag{font-size:11.5px;color:var(--muted);font-weight:500}
.nav{position:relative;display:flex;align-items:center;gap:12px;width:100%;min-height:44px;padding:10px 12px;border-radius:12px;border:0;background:none;
 color:var(--muted);text-align:start;cursor:pointer;font-weight:600;font-size:14px;transition:background .15s,color .15s}
.nav:hover{background:var(--s2);color:var(--text)}
.nav.active{color:var(--text);background:linear-gradient(90deg,rgba(124,155,255,.20),rgba(167,139,250,.06))}
html[dir=rtl] .nav.active{background:linear-gradient(270deg,rgba(124,155,255,.20),rgba(167,139,250,.06))}
.nav.active::before{content:"";position:absolute;inset-inline-start:-12px;top:10px;bottom:10px;width:3px;border-radius:3px;background:var(--accent)}
.nav .badge{margin-inline-start:auto}
.nav-sep{height:1px;background:var(--line);margin:10px 8px}
.spacer{flex:1}
.collapsed .nav{justify-content:center;padding:10px}
.collapsed .nav>span:not(.badge),.collapsed .brand .txt{display:none}
.collapsed .nav .badge{position:absolute;top:4px;inset-inline-end:6px}
.collapsed .brand{justify-content:center;padding-inline:0}
.badge{display:inline-grid;place-items:center;min-width:20px;height:20px;padding:0 6px;border-radius:99px;background:var(--bad);color:#1a0509;font-size:11px;font-weight:800;line-height:1}

/* ---------- surfaces ---------- */
.card{background:linear-gradient(180deg,rgba(255,255,255,.025),rgba(255,255,255,0)) ,var(--s1);border:1px solid var(--line);border-radius:var(--r-lg);padding:var(--sp4);min-width:0;box-shadow:0 1px 0 rgba(255,255,255,.03) inset}
@media (min-width:768px){.card{padding:var(--sp5)}}
.card-h{display:flex;align-items:center;gap:var(--sp2);margin-bottom:var(--sp3);flex-wrap:wrap}
.card-h h2{display:flex;align-items:center;gap:8px;min-width:0;max-width:100%;flex-wrap:wrap;overflow-wrap:anywhere}
.card-h .grow{flex:1}
.stack{display:flex;flex-direction:column;gap:var(--sp4)}
.grid{display:grid;gap:var(--sp3)}
@media (min-width:768px){.grid{gap:var(--sp4)}}
.cols-2{grid-template-columns:minmax(0,1fr)}
@media (min-width:1024px){.cols-2{grid-template-columns:minmax(0,1.15fr) minmax(0,1fr)}}
.srv-grid{grid-template-columns:minmax(0,1fr)}
@media (min-width:1100px){.srv-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
.row{display:flex;gap:var(--sp2);align-items:center;flex-wrap:wrap;min-width:0}
.row>input,.row>select{flex:1 1 160px;width:auto;min-width:0}
.between{justify-content:space-between}
.mt{margin-top:var(--sp3)}.mb{margin-bottom:var(--sp3)}

/* stats */
.stats{grid-template-columns:repeat(2,minmax(0,1fr))}
@media (min-width:640px){.stats{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (min-width:1280px){.stats{grid-template-columns:repeat(6,minmax(0,1fr))}}
.stat{display:flex;flex-direction:column;gap:10px;cursor:pointer;transition:transform .18s var(--ease),border-color .18s;text-align:start;font:inherit;color:inherit}
.stat:hover{transform:translateY(-2px);border-color:var(--line2)}
.stat .ic{width:36px;height:36px;border-radius:11px;display:grid;place-items:center;background:var(--accent-soft);color:var(--accent)}
.stat.t-ok .ic{background:var(--ok-soft);color:var(--ok)}.stat.t-bad .ic{background:var(--bad-soft);color:var(--bad)}
.stat.t-warn .ic{background:var(--warn-soft);color:var(--warn)}.stat.t-violet .ic{background:rgba(167,139,250,.14);color:var(--accent2)}
.stat .v{font-size:28px;font-weight:800;line-height:1.1;font-variant-numeric:tabular-nums}
.stat .k{color:var(--muted);font-size:12.5px;font-weight:600}
@media (max-width:639.98px){.stat{display:grid;grid-template-columns:auto minmax(0,1fr);align-items:center;gap:8px 10px;padding:14px}.stat .v{font-size:24px;text-align:end}.stat .k{grid-column:1/-1;line-height:1.4}}

/* lists */
.list{display:flex;flex-direction:column}
.li{display:flex;align-items:center;gap:var(--sp3);padding:12px 4px;border-bottom:1px solid var(--line);min-width:0}
.li:last-child{border-bottom:0}
.li .tile{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;background:var(--s3);color:var(--text2);flex:none}
.li .tile.s-connected{background:var(--ok-soft);color:var(--ok)}.li .tile.s-error,.li .tile.s-hostkey_mismatch{background:var(--bad-soft);color:var(--bad)}.li .tile.s-hostkey_pending{background:var(--warn-soft);color:var(--warn)}
.li .main{flex:1 1 auto;min-width:0}
.li .t1{font-weight:700;display:flex;align-items:center;gap:4px 8px;min-width:0;flex-wrap:wrap}
.li .t1>.bidi,.li .t1>strong{min-width:0;overflow-wrap:anywhere}
.li .t2{overflow-wrap:anywhere}
.li .t2.error{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.li .t2{color:var(--muted);font-size:12.5px}
.li .end{display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex:none;text-align:end}

/* timeline */
.timeline{position:relative;display:flex;flex-direction:column;padding-inline-start:22px}
.timeline::before{content:"";position:absolute;inset-inline-start:7px;top:8px;bottom:8px;width:2px;background:linear-gradient(var(--line2),transparent)}
.tl{position:relative;padding:6px 0 14px;min-width:0}
.tl::before{content:"";position:absolute;inset-inline-start:-20px;top:12px;width:12px;height:12px;border-radius:50%;background:var(--s4);border:2px solid var(--bg2);box-shadow:0 0 0 1px var(--line2)}
.tl.o-ok::before{background:var(--ok)}.tl.o-bad::before{background:var(--bad)}.tl.o-warn::before{background:var(--warn)}
.tl .t1{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;font-weight:600;font-size:13.5px}
.tl .t2{color:var(--muted);font-size:12px}
.tl .det{color:var(--faint);font-size:12px;margin-top:2px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}

/* pills */
.pill{display:inline-flex;align-items:center;gap:5px;padding:2px 10px 2px 8px;border-radius:99px;font-size:12px;font-weight:700;border:1px solid var(--line2);color:var(--text2);background:var(--s2);white-space:nowrap;line-height:1.6}
.pill svg{width:13px;height:13px}
.pill.s-connected,.pill.o-ok{color:var(--ok);border-color:rgba(61,220,151,.35);background:var(--ok-soft)}
.pill.s-error,.pill.s-hostkey_mismatch,.pill.o-bad{color:var(--bad);border-color:rgba(251,113,133,.35);background:var(--bad-soft)}
.pill.s-hostkey_pending,.pill.o-warn{color:var(--warn);border-color:rgba(251,191,36,.35);background:var(--warn-soft)}
.pill.s-disconnected{color:var(--muted)}
.pill.soft{font-weight:600;color:var(--muted)}
.pill.accent{color:var(--accent);border-color:rgba(124,155,255,.35);background:var(--accent-soft)}
.dot{width:8px;height:8px;border-radius:50%;background:currentColor;flex:none}
.s-connected .dot{box-shadow:0 0 0 3px rgba(61,220,151,.18);animation:pulse 2.2s infinite}

/* buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:42px;padding:8px 16px;border-radius:12px;border:1px solid var(--line2);
 background:var(--s2);color:var(--text);cursor:pointer;font-weight:600;font-size:14px;white-space:nowrap;text-decoration:none;
 transition:background .15s,border-color .15s,transform .1s,box-shadow .15s;user-select:none}
.btn:hover{background:var(--s3);border-color:rgba(124,155,255,.45)}
.btn:active{transform:scale(.98)}
.btn.primary{background:linear-gradient(180deg,#5a78f5,var(--accent-strong));border-color:transparent;color:#fff;box-shadow:0 8px 20px -10px rgba(72,103,240,.9)}
.btn.primary:hover{filter:brightness(1.08)}
.btn.danger{background:var(--bad-soft);border-color:rgba(251,113,133,.4);color:#ffb3c0}
.btn.danger:hover{background:rgba(251,113,133,.22)}
.btn.ghost{background:transparent;border-color:transparent;color:var(--text2)}
.btn.ghost:hover{background:var(--s2)}
.btn.small{min-height:36px;padding:6px 12px;font-size:13px;border-radius:10px}
.btn.big{min-height:50px;padding:12px 20px;font-size:15px;border-radius:14px}
.btn.block{width:100%}
.btn:disabled{opacity:.45;cursor:not-allowed;transform:none}
.btn svg{width:18px;height:18px}
.btn.small svg{width:16px;height:16px}
.actions{display:grid;grid-template-columns:repeat(auto-fill,minmax(112px,1fr));gap:8px}
@media (min-width:768px){.actions{display:flex;flex-wrap:wrap}}
.seg{display:inline-flex;padding:3px;border-radius:12px;background:var(--bg2);border:1px solid var(--line);gap:2px;max-width:100%}
.seg button{flex:1 1 auto;min-height:36px;padding:6px 14px;border-radius:9px;border:0;background:none;color:var(--muted);font-weight:600;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:6px;white-space:nowrap}
.seg button[aria-pressed=true]{background:var(--s3);color:var(--text);box-shadow:0 1px 2px rgba(0,0,0,.3)}

/* forms */
input,select,textarea{width:100%;min-height:44px;background:var(--bg2);border:1px solid var(--line2);border-radius:12px;padding:10px 12px;color:var(--text);
 transition:border-color .15s,box-shadow .15s;font-size:15px}
textarea{font-family:var(--mono);font-size:13px;line-height:1.55;resize:vertical}
input::placeholder,textarea::placeholder{color:var(--faint);opacity:1}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(124,155,255,.22)}
input:focus-visible,select:focus-visible,textarea:focus-visible{outline:none}
input[type=checkbox]:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
select{appearance:none;-webkit-appearance:none;padding-inline-end:36px;
 background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='none' stroke='%2397a3bf' stroke-width='2' stroke-linecap='round' viewBox='0 0 24 24'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
 background-repeat:no-repeat;background-position:right 12px center}
select:dir(rtl){background-position:left 12px center}
label{display:block;font-size:13px;font-weight:600;color:var(--text2);margin:14px 0 6px}
.hint{font-size:12.5px;color:var(--muted);margin-top:6px}
.form{display:grid;grid-template-columns:minmax(0,1fr);gap:0 var(--sp4)}
@media (min-width:640px){.form{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}}
.form .full{grid-column:1/-1}
.fsec{grid-column:1/-1;display:flex;align-items:center;gap:8px;margin:18px 0 0;padding-top:14px;border-top:1px solid var(--line);font-size:12px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:var(--accent)}
.fsec:first-child{margin-top:0;padding-top:0;border-top:0}
.check{display:flex;gap:12px;align-items:center;color:var(--text);font-size:14px;font-weight:600;margin:12px 0 0;cursor:pointer;min-height:44px}
input[type=checkbox]{appearance:none;-webkit-appearance:none;width:44px;min-width:44px;height:26px;min-height:26px;padding:0;border-radius:99px;background:var(--s4);border:1px solid var(--line2);position:relative;cursor:pointer;transition:background .2s}
input[type=checkbox]::after{content:"";position:absolute;top:2px;inset-inline-start:2px;width:20px;height:20px;border-radius:50%;background:#cfd7ea;transition:inset-inline-start .2s var(--ease),background .2s}
input[type=checkbox]:checked{background:var(--accent-strong);border-color:transparent}
input[type=checkbox]:checked::after{inset-inline-start:20px;background:#fff}
.pwwrap{position:relative;direction:ltr}
.pwwrap input{padding-inline-end:52px}
.pwwrap .iconbtn{position:absolute;inset-inline-end:2px;top:50%;transform:translateY(-50%)}

/* boxes */
.warnbox,.dangerbox,.infobox{border-radius:var(--r);padding:12px 14px;margin:12px 0;display:flex;flex-direction:column;gap:8px;min-width:0}
.warnbox{border:1px solid rgba(251,191,36,.35);background:var(--warn-soft)}
.dangerbox{border:1px solid rgba(251,113,133,.38);background:var(--bad-soft)}
.infobox{border:1px solid rgba(124,155,255,.3);background:var(--accent-soft)}
.box-h{display:flex;gap:8px;align-items:flex-start;font-weight:600}
.box-h svg{margin-top:2px}
.warnbox .box-h svg{color:var(--warn)}.dangerbox .box-h svg{color:var(--bad)}
.kv{display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:13px}
.kv .k{color:var(--muted)}

/* code */
pre{margin:0}
.code{background:#050911;border:1px solid var(--line);border-radius:var(--r);padding:14px;font-size:12.5px;line-height:1.6;overflow:auto;white-space:pre;color:#cfe0ff;max-width:100%}
.copyrow{display:flex;gap:8px;align-items:stretch;min-width:0}
.copyval{flex:1 1 auto;min-width:0;display:flex;align-items:center;padding:12px 14px;border-radius:12px;background:#050911;border:1px solid var(--line2);font-family:var(--mono);font-size:14px;overflow-wrap:anywhere;word-break:break-all;color:#dbe6ff}
.copyval.big{font-size:15px;min-height:52px}
@media (max-width:520px){.copyrow.stackable{flex-direction:column}.copyrow.stackable .btn{width:100%}}

/* tables -> cards on phones */
.tbl-wrap{overflow-x:auto;margin-inline:-4px;padding-inline:4px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{padding:10px 10px;border-bottom:1px solid var(--line);text-align:start;vertical-align:top}
th{color:var(--muted);font-weight:700;font-size:12px;white-space:nowrap}
tbody tr{transition:background .15s}
tbody tr:hover{background:rgba(255,255,255,.02)}
@media (max-width:767.98px){
 .tbl thead{display:none}
 .tbl,.tbl tbody,.tbl tr,.tbl td{display:block;width:100%}
 .tbl tr{background:var(--s2);border:1px solid var(--line);border-radius:var(--r);padding:8px 12px;margin-bottom:10px}
 .tbl td{display:flex;gap:12px;justify-content:space-between;align-items:flex-start;border:0;padding:6px 0;min-width:0;text-align:end}
 .tbl td::before{content:attr(data-label);color:var(--muted);font-size:12px;font-weight:700;flex:none;text-align:start}
 .tbl td:empty{display:none}
 .tbl td>*{min-width:0}
 .tbl-wrap{overflow:visible}
}

/* empty / skeleton */
.empty{display:flex;flex-direction:column;align-items:center;text-align:center;gap:10px;padding:28px 12px}
.empty svg.ill{width:132px;height:100px}
.empty .t{font-weight:700;font-size:15px}
.empty .s{color:var(--muted);font-size:13.5px;max-width:42ch}
.sk{border-radius:10px;background:linear-gradient(90deg,var(--s2) 0%,var(--s3) 40%,var(--s2) 80%);background-size:300% 100%;animation:shimmer 1.4s infinite linear}
.sk.h1{height:20px;width:40%}.sk.line{height:12px;width:100%;margin:10px 0}.sk.short{width:60%}
.sk.stat{height:118px;border-radius:var(--r-lg)}.sk.card{height:180px;border-radius:var(--r-lg)}
.spin{width:16px;height:16px;border-radius:50%;border:2px solid rgba(255,255,255,.25);border-top-color:currentColor;animation:rot .8s linear infinite;display:inline-block;flex:none}

/* modal / bottom sheet */
.modal-bg{position:fixed;inset:0;z-index:60;display:flex;align-items:flex-end;justify-content:center;background:rgba(2,5,12,.62);backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px);animation:fade .2s ease}
.modal{position:relative;width:100%;max-height:92dvh;overflow:auto;overscroll-behavior:contain;background:var(--s1);border:1px solid var(--line2);border-bottom:0;
 border-radius:var(--r-xl) var(--r-xl) 0 0;padding:10px var(--sp4) calc(var(--sp4) + var(--safe-b));box-shadow:var(--shadow);animation:sheetUp .32s var(--ease)}
.modal::before{content:"";display:block;width:42px;height:5px;border-radius:99px;background:var(--s4);margin:0 auto 12px}
.modal:focus,.modal:focus-visible{outline:none}
.modal-h{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.modal-h h2{flex:1;font-size:17px;min-width:0;overflow-wrap:anywhere}
.modal-f{position:sticky;bottom:calc(-1 * (var(--sp4) + var(--safe-b)));display:flex;flex-wrap:wrap;gap:8px;margin:16px calc(-1 * var(--sp4)) calc(-1 * (var(--sp4) + var(--safe-b)));
 padding:12px var(--sp4) calc(12px + var(--safe-b));background:linear-gradient(180deg,rgba(14,21,38,.85),var(--s1) 30%);border-top:1px solid var(--line)}
.modal-f .btn{flex:1 1 140px}
@media (min-width:768px){
 .modal-bg{align-items:center;padding:24px}
 .modal{width:min(720px,100%);border-radius:var(--r-xl);border-bottom:1px solid var(--line2);padding:var(--sp6);max-height:88vh;animation:pop .22s var(--ease)}
 .modal::before{display:none}
 .modal.narrow{width:min(460px,100%)}
 .modal-f{bottom:calc(-1 * var(--sp6));margin:20px calc(-1 * var(--sp6)) calc(-1 * var(--sp6));padding:14px var(--sp6);border-radius:0 0 var(--r-xl) var(--r-xl);justify-content:flex-end}
 .modal-f .btn{flex:0 0 auto}
}
.sheet-list{display:flex;flex-direction:column;gap:4px}
.sheet-item{display:flex;align-items:center;gap:14px;min-height:52px;padding:10px 12px;border-radius:12px;border:0;background:none;color:var(--text);font-weight:600;font-size:15px;cursor:pointer;text-align:start;width:100%}
.sheet-item:hover{background:var(--s2)}
.sheet-item.danger{color:var(--bad)}
.sheet-item .badge{margin-inline-start:auto}
.sheet-item svg{color:var(--muted)}.sheet-item.danger svg{color:var(--bad)}

/* toasts */
.toasts{position:fixed;z-index:80;inset-inline:12px;bottom:calc(var(--tab-h) + var(--safe-b) + 12px);display:flex;flex-direction:column;gap:8px;pointer-events:none;align-items:center}
@media (min-width:768px){.toasts{inset-inline:auto 24px;top:calc(var(--top-h) + 12px);bottom:auto;max-width:440px;align-items:stretch}html[dir=rtl] .toasts{inset-inline:24px auto}}
.toast{pointer-events:auto;display:flex;gap:10px;align-items:flex-start;width:100%;max-width:440px;background:rgba(26,37,64,.96);border:1px solid var(--line2);padding:12px 14px;border-radius:14px;box-shadow:var(--shadow);
 overflow-wrap:anywhere;font-size:14px;animation:toastIn .3s var(--ease)}
.toast svg{color:var(--ok);margin-top:2px}.toast.bad{border-color:rgba(251,113,133,.5)}.toast.bad svg{color:var(--bad)}

/* login */
.login-wrap{min-height:100dvh;display:grid;place-items:center;padding:24px calc(16px + var(--safe-r)) calc(24px + var(--safe-b)) calc(16px + var(--safe-l))}
.login{width:min(420px,100%);padding:28px 24px;border-radius:24px;background:linear-gradient(180deg,rgba(26,37,64,.75),rgba(14,21,38,.85));border:1px solid var(--line2);box-shadow:var(--shadow);backdrop-filter:blur(10px);animation:pop .35s var(--ease)}
.login .logo{width:56px;height:56px;border-radius:16px;margin-bottom:16px}
.login h1{font-size:24px}
.login .sub{color:var(--muted);margin:6px 0 10px}
.login-top{display:flex;justify-content:space-between;align-items:flex-start}
.login .steps{margin-top:14px}.login .copyval{margin-top:6px}
.cfg-list{margin:10px 0;padding-inline-start:20px;line-height:1.9}.cfg-list code{font-weight:700}

/* terminal */
.v-terminal{display:flex;flex-direction:column;height:calc(100dvh - var(--top-h) - var(--safe-t));padding-bottom:calc(var(--tab-h) + var(--safe-b) + 12px)}
body.typing .v-terminal{padding-bottom:12px}
.v-terminal>.view,.v-terminal>.stack{flex:1 1 auto;min-height:0;display:flex;flex-direction:column}
@media (min-width:768px){.v-terminal{padding-bottom:var(--sp5)}}
.termbox{display:flex;flex-direction:column;gap:10px;flex:1 1 auto;min-height:0}
.term-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.term-tools select{flex:1 1 180px;min-width:0;width:auto}
.term-tools .to{display:flex;align-items:center;gap:6px;flex:0 0 auto}
.term-tools .to input{width:84px;min-height:42px}
.term-tools .to label{margin:0;font-size:12px}
.chips{display:flex;gap:8px;overflow-x:auto;scrollbar-width:none;padding-bottom:2px;mask-image:linear-gradient(90deg,transparent,#000 12px,#000 calc(100% - 12px),transparent)}
.chips::-webkit-scrollbar{display:none}
.chip{flex:none;display:inline-flex;align-items:center;gap:6px;min-height:36px;padding:6px 12px;border-radius:99px;border:1px solid var(--line2);background:var(--s2);color:var(--text2);font-family:var(--mono);font-size:12.5px;cursor:pointer;white-space:nowrap}
.chip:hover{border-color:var(--accent);color:var(--text)}
.term{position:relative;flex:1 1 auto;min-height:200px;background:#03060c;border:1px solid var(--line);border-radius:var(--r-lg);padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;
 font-size:13px;line-height:1.55;color:#d6e2f5;box-shadow:inset 0 1px 0 rgba(255,255,255,.03),inset 0 0 40px rgba(72,103,240,.05);text-align:left}
@media (max-width:767.98px){.term{font-size:12.5px;padding:12px}}
.term .cmd{color:#9fb6ff;font-weight:700}.term .err{color:#ff9aaa}.term .meta{color:var(--muted)}.term .ok{color:var(--ok)}
.term .hintline{color:var(--faint)}
.term-status{display:flex;align-items:center;gap:10px;min-height:26px;font-size:13px;color:var(--muted);flex-wrap:wrap}
.exit-badge{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:99px;font-family:var(--mono);font-size:12px;font-weight:700;border:1px solid var(--line2)}
.exit-badge.ok{color:var(--ok);background:var(--ok-soft);border-color:rgba(61,220,151,.35)}
.exit-badge.bad{color:var(--bad);background:var(--bad-soft);border-color:rgba(251,113,133,.35)}
.exit-badge.warn{color:var(--warn);background:var(--warn-soft);border-color:rgba(251,191,36,.35)}
.cmdbar{display:flex;gap:8px;align-items:stretch}
.cmdin{flex:1 1 auto;min-width:0;display:flex;align-items:center;gap:8px;background:#03060c;border:1px solid var(--line2);border-radius:14px;padding-inline:12px;transition:border-color .15s,box-shadow .15s}
.cmdin:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px rgba(124,155,255,.22)}
.cmdin .ps{color:var(--ok);font-family:var(--mono);font-weight:700}
.cmdin input{border:0;background:none;box-shadow:none;padding:12px 0;min-height:48px;font-family:var(--mono);font-size:14px}
.cmdin input:focus{box-shadow:none}
.cmdin input:focus-visible{outline:none}
.cmdin input::placeholder{font-family:var(--font);font-size:14px}
html[dir=rtl] .cmdin input:placeholder-shown{direction:rtl}
.cmdbar .btn{min-height:50px;min-width:50px;border-radius:14px}
@media (max-width:767.98px){.cmdbar .btn .lbl{display:none}.cmdbar .btn{padding:0 14px}}

/* files */
.crumbs{display:flex;align-items:center;gap:2px;overflow-x:auto;scrollbar-width:thin;padding:6px;border-radius:12px;background:var(--bg2);border:1px solid var(--line);font-size:13px;white-space:nowrap;min-width:0}
.crumbs button{border:0;background:none;color:var(--text2);padding:6px 8px;border-radius:8px;cursor:pointer;font:inherit;flex:none;min-height:32px}
.crumbs button:hover{background:var(--s3);color:var(--text)}
.crumbs button:last-child{color:var(--text);font-weight:700}
.crumbs .sep{color:var(--faint);flex:none}
.ftools{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.ftools select{flex:1 1 200px;width:auto;min-width:0}
@media (max-width:767.98px){.ftools .btn .lbl{display:none}.ftools .btn{flex:1 1 0;min-width:44px;padding:0 12px}.ftools select{flex:1 1 100%}}
.flist{display:flex;flex-direction:column}
.frow{display:flex;align-items:center;gap:12px;padding:8px 6px;border-bottom:1px solid var(--line);min-width:0;border-radius:10px;transition:background .12s;-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
.frow:hover{background:rgba(255,255,255,.025)}
.frow .ficon{width:40px;height:40px;border-radius:11px;display:grid;place-items:center;flex:none;background:var(--s3);color:var(--text2)}
.frow.dir .ficon{background:rgba(251,191,36,.12);color:var(--warn)}
.frow .fmain{flex:1 1 auto;min-width:0}
.frow .fname{display:block;font-weight:600;cursor:pointer;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;border:0;background:none;padding:0;color:var(--text);text-align:start;width:100%}
.frow .fname:hover{color:var(--accent)}
.frow .fmeta{font-size:12px;color:var(--muted);display:flex;gap:10px;flex-wrap:wrap}
.frow .facts{display:flex;gap:6px;flex:none}
@media (max-width:899.98px){.frow .facts{display:none}}
@media (min-width:900px){.frow .kebab{display:none}}
.flist.gridmode{display:grid;grid-template-columns:repeat(auto-fill,minmax(132px,1fr));gap:10px}
.flist.gridmode .frow{flex-direction:column;text-align:center;border:1px solid var(--line);background:var(--s2);padding:14px 10px 10px;position:relative}
.flist.gridmode .frow .ficon{width:56px;height:56px;border-radius:16px}
.flist.gridmode .frow .fname{text-align:center}
.flist.gridmode .frow .fmeta{justify-content:center}
.flist.gridmode .frow .facts{display:none}
.flist.gridmode .frow .kebab{display:inline-grid;position:absolute;top:2px;inset-inline-end:2px}
.progress{height:8px;border-radius:99px;background:var(--s3);overflow:hidden}
.progress>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent-strong),var(--accent2));border-radius:99px;transition:width .2s}
.pager{display:flex;align-items:center;gap:8px;justify-content:flex-end;margin-top:10px}
.editor{display:flex;border:1px solid var(--line2);border-radius:var(--r);overflow:hidden;background:#050911;max-height:62dvh;min-height:240px}
.editor .gutter{flex:none;padding:10px 8px;text-align:right;color:var(--faint);font-family:var(--mono);font-size:13px;line-height:1.55;background:rgba(255,255,255,.02);border-inline-end:1px solid var(--line);overflow:hidden;user-select:none;white-space:pre;min-width:44px}
.editor textarea{border:0;border-radius:0;background:transparent;min-height:240px;resize:none;white-space:pre;overflow:auto;box-shadow:none;padding:10px 12px;flex:1 1 auto;height:auto;tab-size:4}
.editor textarea:focus{box-shadow:none}

/* MCP */
.steps{counter-reset:st;display:flex;flex-direction:column;gap:14px;margin:4px 0 0;padding:0;list-style:none}
.steps li{counter-increment:st;position:relative;padding-inline-start:44px;min-height:32px;line-height:1.75}
.steps li::before{content:counter(st);position:absolute;inset-inline-start:0;top:0;width:30px;height:30px;border-radius:10px;display:grid;place-items:center;font-weight:800;font-size:14px;background:var(--accent-soft);color:var(--accent)}
.steps .copyrow{margin-top:8px}
.tabs{display:flex;gap:4px;overflow-x:auto;scrollbar-width:none;border-bottom:1px solid var(--line);margin-bottom:12px}
.tabs button{flex:none;border:0;background:none;color:var(--muted);padding:10px 14px;font-weight:700;cursor:pointer;border-bottom:2px solid transparent;min-height:44px}
.tabs button[aria-selected=true]{color:var(--text);border-bottom-color:var(--accent)}
.tokenbox{display:flex;flex-direction:column;gap:10px}

/* auto-approve */
.seg.aa{display:flex;width:100%}
.seg.aa button{flex:1 1 0;min-width:0;min-height:44px}
.seg.aa.compact button{min-height:38px;padding:6px 10px;font-size:13.5px}
.seg.aa button[data-value=safe][aria-pressed=true]{background:var(--warn-soft);color:var(--warn);box-shadow:inset 0 0 0 1px rgba(251,191,36,.45)}
.seg.aa button[data-value=all][aria-pressed=true]{background:var(--bad-soft);color:var(--bad);box-shadow:inset 0 0 0 1px rgba(251,113,133,.5)}
.seg.aa button[data-value=off][aria-pressed=true]{background:var(--s3);color:var(--text)}
.aa-row{display:flex;flex-direction:column;gap:8px;margin-top:12px;padding-top:12px;border-top:1px solid var(--line)}
.aa-row .aa-h{display:flex;align-items:center;gap:6px;font-weight:700;font-size:13.5px;color:var(--text2)}
.aa-row .aa-h svg{width:16px;height:16px;color:var(--muted)}
.aa-list{display:flex;flex-direction:column;gap:12px}
.aa-item{display:grid;grid-template-columns:minmax(0,1fr);gap:8px;padding:10px 0;border-bottom:1px solid var(--line)}
.aa-item:last-child{border-bottom:0}
@media (min-width:768px){.aa-item{grid-template-columns:minmax(0,1fr) minmax(260px,340px);align-items:center}}
.aa-hint{font-size:12.5px;color:var(--muted);line-height:1.7}
.aa-hint.safe{color:var(--warn)}.aa-hint.all{color:var(--bad);font-weight:700}
.pill.auto{color:var(--accent2);border-color:rgba(167,139,250,.4);background:rgba(167,139,250,.13)}
.pill.aa-safe{color:var(--warn);border-color:rgba(251,191,36,.35);background:var(--warn-soft)}
.pill.aa-all{color:var(--bad);border-color:rgba(251,113,133,.4);background:var(--bad-soft)}
.approve-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between}
.btn.big-tap{min-height:48px;padding-inline:20px;font-size:15px}
.grp-h{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:8px}
.grp-h h3{margin:0;font-size:15px;display:flex;align-items:center;gap:6px}

/* animations */
@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes fade{from{opacity:0}to{opacity:1}}
@keyframes sheetUp{from{transform:translateY(100%)}to{transform:none}}
@keyframes pop{from{opacity:0;transform:scale(.97) translateY(6px)}to{opacity:1;transform:none}}
@keyframes toastIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes shimmer{from{background-position:100% 0}to{background-position:-100% 0}}
@keyframes rot{to{transform:rotate(360deg)}}
@keyframes pulse{0%,100%{box-shadow:0 0 0 3px rgba(61,220,151,.18)}50%{box-shadow:0 0 0 6px rgba(61,220,151,.05)}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important;scroll-behavior:auto!important}}
@media (forced-colors:active){.pill,.btn,.card{border:1px solid CanvasText}}
`;
