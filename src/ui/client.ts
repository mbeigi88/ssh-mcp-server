// Dashboard client script (runs under the per-request CSP nonce). Rules kept from v1:
//  * every dynamic value is inserted with textContent / attributes — never innerHTML with data
//    (innerHTML is only used for the constant SVG icon / illustration markup below);
//  * credentials never reach the browser; every state-changing request carries x-csrf-token;
//  * no inline event-handler attributes, no inline style attributes (CSP-safe).
// NOTE: this file is embedded in a String.raw template — never use backticks or dollar-brace in it.

export const JS = String.raw`
(() => {
'use strict';
const I18N = {
 en: {overview:'Overview',servers:'Servers',terminal:'Terminal',files:'Files',approvals:'Approvals',mcp:'MCP',settings:'Settings',audit:'Audit log',logout:'Log out',
  sub_overview:'Your fleet at a glance',sub_servers:'Manage SSH targets, host keys and policies',sub_terminal:'Run commands over SSH',sub_files:'Browse and edit files over SFTP',
  sub_approvals:'Destructive operations waiting for a human',sub_mcp:'Connect Claude, Gemini, ChatGPT, Cursor and other MCP clients',sub_settings:'Limits, timeouts and admin password',sub_audit:'Everything that happened, newest first',
  login:'Sign in',loginSub:'SSH MCP control panel',password:'Password',showPw:'Show password',hidePw:'Hide password',totalServers:'Servers',connected:'Connected',failed:'Failed',pendingKeys:'Host keys to approve',pendingConf:'Pending approvals',cmds24:'Commands · 24h',
  recent:'Recent activity',perServer:'Server status',lastConn:'Last connection',never:'never',addServer:'Add server',edit:'Edit',del:'Delete',test:'Test',connect:'Connect',disconnect:'Disconnect',
  makeDefault:'Make default',default:'Default',name:'Name',host:'Host',port:'Port',username:'Username',auth:'Auth method',pwd:'Password',key:'Private key',passphrase:'Key passphrase',
  fp:'Host key fingerprint (optional)',labels:'Labels (comma separated)',allowRoot:'Allow root login (explicit)',policy:'Execution policy',ro:'Read-only',mod:'Allow modify',
  sudoInst:'Allow sudo package installs',save:'Save',cancel:'Cancel',close:'Close',unchanged:'set — leave empty to keep unchanged',notset:'not set',status:'Status',lastError:'Last error',
  approveKey:'Approve host key',approveKeyText:'First connection: verify this fingerprint on the server before approving. Run on the server:',
  mismatch:'HOST KEY MISMATCH — connection refused. Investigate before resetting the host key in Edit.',resetKey:'Reset host key',hostKey:'Host key',tofuPending:'not pinned yet (trust on first use)',
  run:'Run',clear:'Clear',stop:'Cancel',timeout:'Timeout (s)',history:'History',server:'Server',cmdPlaceholder:'command — Enter to run, ↑/↓ history',
  running:'running…',exit:'exit',up:'Up',refresh:'Refresh',newFolder:'New folder',upload:'Upload',uploading:'Uploading',download:'Download',rename:'Rename',open:'Open',size:'Size',mode:'Mode',modified:'Modified',
  saveFile:'Save file',approve:'Approve',reject:'Reject',showToken:'Show one-time token',noPending:'Nothing pending.',noPendingSub:'Destructive commands and file deletions requested by MCP clients will show up here.',
  mcpUrl:'MCP endpoint URL',tokens:'Access tokens',newToken:'Create token',tokenName:'Token name',
  revoke:'Revoke',copy:'Copy',copied:'Copied',tokenOnce:'Copy this token now — it will not be shown again.',clientCfg:'Client configuration',
  allowPrivate:'Allow private/loopback SSH targets (SSRF override — not recommended)',idle:'Idle disconnect (s)',cmdTimeout:'Default command timeout (s)',maxOut:'Max output per stream (bytes)',
  confTtl:'Confirmation TTL (s)',sessTtl:'Session lifetime (hours)',changePwd:'Change admin password',currentPwd:'Current password',newPwd:'New password (min 12 chars)',
  destructive:'This command is classified as DESTRUCTIVE:',runAnyway:'I understand — run it',confirmDelete:'Delete permanently?',recursive:'Recursive (directories with contents)',
  noServers:'No servers yet',noServersSub:'Add your first SSH server to start running commands and browsing files.',selectServer:'Select a server',lang:'فارسی',time:'Time',actor:'Actor',action:'Action',outcome:'Outcome',detail:'Detail',more:'Load more',
  readOnlyNote:'Read-only mode blocks all non-read commands and file changes.',textTooBig:'File too large to edit inline (max 1 MiB); download it instead.',
  connHistory:'Connection history',event:'Event',created:'Created',lastUsed:'Last used',revoked:'revoked',tool:'Tool',operation:'Operation',reason:'Reason',expires:'Expires',requestedBy:'Requested by',
  st_connected:'Connected',st_disconnected:'Idle',st_error:'Failed',st_hostkey_pending:'Key pending',st_hostkey_mismatch:'Key mismatch',
  secConn:'Connection',secAuth:'Authentication',secSec:'Security & policy',menu:'Menu',moreMenu:'More',collapse:'Collapse sidebar',expand:'Expand sidebar',
  noActivity:'No activity yet',emptyDir:'This folder is empty',emptyDirSub:'Upload a file or create a folder.',noTokens:'No tokens yet — create one below.',
  termHint:'Pick a server, then type a command or tap a quick command.',quick:'Quick commands',listView:'List',gridView:'Grid',actions:'Actions',items:'items',
  folderName:'Folder name',newName:'New name',ok:'OK',saved:'Saved',lines:'lines',noHistory:'No history yet',
  claudeTitle:'Add to Claude (custom connector)',oauthTitle:'Sign in with OAuth (Gemini, ChatGPT, Claude.ai) — no token needed',cfgDesktop:'Claude Desktop',cfgCursor:'Cursor',cfgCode:'Claude Code',headerName:'Request header name',headerValue:'Header value',
  tokenHint:'Create a token above; it is filled in automatically below.',act_test:'Test',act_connect:'Connect',act_disconnect:'Disconnect',act_default:'Default',
  prefix:'Prefix',authMode:'Auth mode',signedOut:'Signed out',notConfigured:'Admin password is not configured (ADMIN_PASSWORD_HASH secret).',
  autoApprove:'Auto-approve',aa_off:'Off',aa_safe:'Safe',aa_all:'Everything',
  aaHint_off:'Every destructive operation waits for your approval here.',
  aaHint_safe:'Destructive operations (deleting files, docker rm, service restarts, package removal…) run immediately. Catastrophic ones — disk format, rm -rf of system folders, shutdown, SSH / firewall changes, DROP DATABASE, docker volume removal — still need your approval.',
  aaHint_all:'Everything runs without approval — including catastrophic commands like rm -rf / or mkfs. Only for disposable servers.',
  aaConfirmTitle:'Auto-approve everything?',aaTypeConfirm:'Type CONFIRM to enable',aaEnable:'Enable',aaConfirmWord:'CONFIRM',
  aaRoNote:'Read-only mode still blocks every change, whatever this is set to.',autoBadge:'Auto',aaUpdated:'Auto-approve updated',
  approveAll:'Approve all',approveAllQ:'Approve every pending operation?',approveAllText:'Each approved operation runs when the agent calls it again. Pending items:',approveAllServer:'Approve all for this server',
  approvedNote:'Approved — the agent can run it now.',aaQuickTitle:'Auto-approve per server',aaQuickSub:'Stop approving one by one: let a server run destructive operations on its own.',defaultAuto:'Auto-approve for new servers',
  setupTitle:'Create admin password',setupSub:'First-time setup — this page only works until an admin password exists.',setupToken:'Setup token',
  setupTokenHint:'The SETUP_TOKEN you chose when you deployed. Forgot it? Set a new one in the Cloudflare dashboard (this Worker → Settings → Variables and Secrets).',
  newAdminPw:'New admin password (at least 12 characters)',confirmPw:'Repeat the password',pwMismatch:'The passwords do not match.',pwTooShort:'Use at least 12 characters.',
  setupBtn:'Create password and sign in',setupNeedsTitle:'One more step: add a setup token',
  setupNeedsText:'This deployment has no admin password yet. To create one safely, first add a secret named SETUP_TOKEN that only you know (at least 12 characters):',
  setupStep1:'Open dash.cloudflare.com → Workers & Pages → this Worker → Settings → Variables and Secrets.',
  setupStep2:'Add → Type: Secret → Name: SETUP_TOKEN → Value: a long phrase you will remember → Deploy.',
  setupStep3:'Reload this page and enter the same token together with your new admin password.',setupCli:'Or from a terminal:',
  setupTokenShort:'A SETUP_TOKEN secret exists but it is too short or too simple. Replace it with one of at least 12 characters, then reload.',
  setupLocked:'Setup was already completed, but no admin password is stored any more. Set the ADMIN_PASSWORD_HASH secret (npm run hash-password) to get back in.',
  cfgTitle:'Configuration needed',cfgText:'The Worker cannot run safely because a secret is missing or too weak. Fix it in the Cloudflare dashboard (this Worker → Settings → Variables and Secrets), then reload.',
  cfg_missing:'is missing',cfg_too_short:'is too short — use at least 32 characters',cfg_too_weak:'is too simple — use a long random value or passphrase',cfg_invalid_format:'has an invalid format (expected v<n>:<old key>)',
  cfgHint:'Any passphrase of 32+ characters works, for example six random words. Never change ENCRYPTION_KEY after adding servers: stored SSH credentials could no longer be decrypted.',
  reload:'Reload',pwBySecret:'The admin password comes from the ADMIN_PASSWORD_HASH secret, so it cannot be changed here. Create a new hash with npm run hash-password and update the secret (wrangler secret put ADMIN_PASSWORD_HASH).'},
 fa: {overview:'نمای کلی',servers:'سرورها',terminal:'ترمینال',files:'فایل‌ها',approvals:'تأییدها',mcp:'MCP',settings:'تنظیمات',audit:'گزارش رویدادها',logout:'خروج',
  sub_overview:'وضعیت همهٔ سرورها در یک نگاه',sub_servers:'مدیریت سرورها، کلیدهای میزبان و سیاست‌ها',sub_terminal:'اجرای دستور روی سرور',sub_files:'مرور و ویرایش فایل‌ها',
  sub_approvals:'عملیات مخربی که منتظر تأیید شما هستند',sub_mcp:'اتصال Claude، Gemini، ChatGPT، Cursor و سایر کلاینت‌های MCP',sub_settings:'محدودیت‌ها، مهلت‌ها و رمز مدیر',sub_audit:'همهٔ رویدادها، جدیدترین در بالا',
  login:'ورود',loginSub:'پنل مدیریت SSH MCP',password:'رمز عبور',showPw:'نمایش رمز',hidePw:'پنهان کردن رمز',totalServers:'سرورها',connected:'متصل',failed:'ناموفق',pendingKeys:'کلید میزبان در انتظار',pendingConf:'تأیید در انتظار',cmds24:'دستورات ۲۴ ساعت اخیر',
  recent:'فعالیت‌های اخیر',perServer:'وضعیت سرورها',lastConn:'آخرین اتصال',never:'هرگز',addServer:'افزودن سرور',edit:'ویرایش',del:'حذف',test:'آزمایش',connect:'اتصال',disconnect:'قطع اتصال',
  makeDefault:'پیش‌فرض کن',default:'پیش‌فرض',name:'نام',host:'میزبان',port:'پورت',username:'نام کاربری',auth:'روش احراز هویت',pwd:'رمز عبور',key:'کلید خصوصی',passphrase:'عبارت عبور کلید',
  fp:'اثر انگشت کلید میزبان (اختیاری)',labels:'برچسب‌ها (با کاما جدا کنید)',allowRoot:'اجازهٔ ورود root (صریح)',policy:'سیاست اجرا',ro:'فقط خواندنی',mod:'اجازهٔ تغییر',
  sudoInst:'اجازهٔ نصب بسته با sudo',save:'ذخیره',cancel:'انصراف',close:'بستن',unchanged:'تنظیم شده — برای حفظ، خالی بگذارید',notset:'تنظیم نشده',status:'وضعیت',lastError:'آخرین خطا',
  approveKey:'تأیید کلید میزبان',approveKeyText:'اتصال اول: پیش از تأیید، این اثر انگشت را روی خود سرور بررسی کنید. این دستور را روی سرور اجرا کنید:',
  mismatch:'عدم تطابق کلید میزبان — اتصال رد شد. پیش از بازنشانی کلید در «ویرایش»، موضوع را بررسی کنید.',resetKey:'بازنشانی کلید میزبان',hostKey:'کلید میزبان',tofuPending:'هنوز ثبت نشده (اعتماد در اولین اتصال)',
  run:'اجرا',clear:'پاک کردن',stop:'لغو',timeout:'مهلت (ثانیه)',history:'تاریخچه',server:'سرور',cmdPlaceholder:'دستور را بنویسید…',
  running:'در حال اجرا…',exit:'کد خروج',up:'بالا',refresh:'بازخوانی',newFolder:'پوشهٔ جدید',upload:'بارگذاری',uploading:'در حال بارگذاری',download:'دانلود',rename:'تغییر نام',open:'باز کردن',size:'اندازه',mode:'مجوز',modified:'تغییر',
  saveFile:'ذخیرهٔ فایل',approve:'تأیید',reject:'رد',showToken:'نمایش توکن یک‌بارمصرف',noPending:'موردی در انتظار نیست.',noPendingSub:'دستورات مخرب و حذف فایل‌هایی که کلاینت‌های MCP درخواست کنند، اینجا نمایش داده می‌شوند.',
  mcpUrl:'نشانی MCP',tokens:'توکن‌های دسترسی',newToken:'ساخت توکن',tokenName:'نام توکن',
  revoke:'ابطال',copy:'کپی',copied:'کپی شد',tokenOnce:'این توکن را همین حالا کپی کنید — دوباره نمایش داده نمی‌شود.',clientCfg:'پیکربندی کلاینت',
  allowPrivate:'اجازهٔ اتصال به نشانی‌های خصوصی/محلی (غیرفعال کردن محافظت SSRF — توصیه نمی‌شود)',idle:'قطع در بیکاری (ثانیه)',cmdTimeout:'مهلت پیش‌فرض دستور (ثانیه)',maxOut:'حداکثر خروجی هر جریان (بایت)',
  confTtl:'اعتبار تأیید (ثانیه)',sessTtl:'طول نشست (ساعت)',changePwd:'تغییر رمز مدیر',currentPwd:'رمز فعلی',newPwd:'رمز جدید (حداقل ۱۲ نویسه)',
  destructive:'این دستور «مخرب» تشخیص داده شد:',runAnyway:'متوجه هستم — اجرا شود',confirmDelete:'برای همیشه حذف شود؟',recursive:'بازگشتی (پوشه همراه محتوا)',
  noServers:'هنوز سروری ندارید',noServersSub:'اولین سرور SSH خود را اضافه کنید تا بتوانید دستور اجرا کنید و فایل‌ها را ببینید.',selectServer:'یک سرور انتخاب کنید',lang:'English',time:'زمان',actor:'عامل',action:'عملیات',outcome:'نتیجه',detail:'جزئیات',more:'بیشتر',
  readOnlyNote:'حالت فقط‌خواندنی همهٔ دستورات غیرخواندنی و تغییرات فایل را مسدود می‌کند.',textTooBig:'فایل برای ویرایش در صفحه بزرگ است (حداکثر ۱ مگابایت)؛ آن را دانلود کنید.',
  connHistory:'تاریخچهٔ اتصال',event:'رویداد',created:'ایجاد',lastUsed:'آخرین استفاده',revoked:'باطل‌شده',tool:'ابزار',operation:'عملیات',reason:'دلیل',expires:'انقضا',requestedBy:'درخواست‌کننده',
  st_connected:'متصل',st_disconnected:'بیکار',st_error:'ناموفق',st_hostkey_pending:'کلید در انتظار',st_hostkey_mismatch:'کلید نامعتبر',
  secConn:'اتصال',secAuth:'احراز هویت',secSec:'امنیت و سیاست',menu:'منو',moreMenu:'بیشتر',collapse:'جمع کردن نوار کناری',expand:'باز کردن نوار کناری',
  noActivity:'هنوز فعالیتی ثبت نشده',emptyDir:'این پوشه خالی است',emptyDirSub:'یک فایل بارگذاری کنید یا پوشه بسازید.',noTokens:'هنوز توکنی ندارید — از بالا یکی بسازید.',
  termHint:'یک سرور انتخاب کنید، سپس دستور بنویسید یا روی یکی از دستورهای سریع بزنید.',quick:'دستورهای سریع',listView:'فهرست',gridView:'شبکه',actions:'عملیات',items:'مورد',
  folderName:'نام پوشه',newName:'نام جدید',ok:'تأیید',saved:'ذخیره شد',lines:'خط',noHistory:'هنوز تاریخچه‌ای نیست',
  claudeTitle:'افزودن به Claude (کانکتور سفارشی)',oauthTitle:'اتصال با OAuth (Gemini، ChatGPT، Claude.ai) — بدون توکن',cfgDesktop:'Claude Desktop',cfgCursor:'Cursor',cfgCode:'Claude Code',headerName:'نام هدر درخواست',headerValue:'مقدار هدر',
  tokenHint:'ابتدا از بالا یک توکن بسازید؛ به‌طور خودکار در پایین قرار می‌گیرد.',act_test:'آزمایش',act_connect:'اتصال',act_disconnect:'قطع اتصال',act_default:'پیش‌فرض',
  prefix:'پیشوند',authMode:'حالت احراز هویت',signedOut:'خارج شدید',notConfigured:'رمز مدیر تنظیم نشده است (راز ADMIN_PASSWORD_HASH).',
  autoApprove:'تأیید خودکار',aa_off:'خاموش',aa_safe:'ایمن',aa_all:'همه',
  aaHint_off:'هر عملیات مخرب اینجا منتظر تأیید شما می‌ماند.',
  aaHint_safe:'عملیات مخرب (حذف فایل، docker rm، راه‌اندازی دوبارهٔ سرویس، حذف بسته…) بی‌درنگ اجرا می‌شوند. موارد فاجعه‌بار — فرمت دیسک، rm -rf پوشه‌های سیستمی، خاموش کردن سرور، تغییر SSH یا فایروال، DROP DATABASE، حذف حجم‌های docker — همچنان تأیید شما را لازم دارند.',
  aaHint_all:'همه‌چیز بدون تأیید اجرا می‌شود — حتی دستورهای فاجعه‌بار مثل rm -rf / یا mkfs. فقط برای سرورهای آزمایشی و دورریختنی.',
  aaConfirmTitle:'تأیید خودکار برای همه‌چیز فعال شود؟',aaTypeConfirm:'برای فعال‌سازی، کلمهٔ «تأیید» را بنویسید',aaEnable:'فعال شود',aaConfirmWord:'تأیید',
  aaRoNote:'حالت فقط‌خواندنی، هر مقداری که این‌جا باشد، همچنان همهٔ تغییرات را مسدود می‌کند.',autoBadge:'خودکار',aaUpdated:'تأیید خودکار به‌روز شد',
  approveAll:'تأیید همه',approveAllQ:'همهٔ عملیات در انتظار تأیید شوند؟',approveAllText:'هر عملیات تأییدشده وقتی عامل دوباره آن را فراخوانی کند اجرا می‌شود. موارد در انتظار:',approveAllServer:'تأیید همهٔ موارد این سرور',
  approvedNote:'تأیید شد — عامل حالا می‌تواند آن را اجرا کند.',aaQuickTitle:'تأیید خودکار هر سرور',aaQuickSub:'دیگر لازم نیست تک‌تک تأیید کنید: اجازه دهید سرور عملیات مخرب را خودش اجرا کند.',defaultAuto:'تأیید خودکار برای سرورهای جدید',
  setupTitle:'ساخت رمز مدیر',setupSub:'راه‌اندازی اولیه — این صفحه فقط تا وقتی رمز مدیر ساخته نشده کار می‌کند.',setupToken:'توکن راه‌اندازی',
  setupTokenHint:'همان SETUP_TOKEN که هنگام استقرار انتخاب کردید. فراموش کرده‌اید؟ در داشبورد کلادفلر (این Worker ← Settings ← Variables and Secrets) یک مقدار تازه بگذارید.',
  newAdminPw:'رمز جدید مدیر (حداقل ۱۲ نویسه)',confirmPw:'تکرار رمز',pwMismatch:'دو رمز یکسان نیستند.',pwTooShort:'حداقل ۱۲ نویسه وارد کنید.',
  setupBtn:'ساخت رمز و ورود',setupNeedsTitle:'یک قدم دیگر: توکن راه‌اندازی را اضافه کنید',
  setupNeedsText:'این استقرار هنوز رمز مدیر ندارد. برای ساخت امن آن، ابتدا یک راز به نام SETUP_TOKEN که فقط خودتان می‌دانید (حداقل ۱۲ نویسه) اضافه کنید:',
  setupStep1:'به dash.cloudflare.com بروید ← Workers & Pages ← این Worker ← Settings ← Variables and Secrets.',
  setupStep2:'Add ← نوع: Secret ← نام: SETUP_TOKEN ← مقدار: یک عبارت بلند که به خاطر می‌سپارید ← Deploy.',
  setupStep3:'این صفحه را دوباره بارگذاری کنید و همان توکن را همراه رمز جدید مدیر وارد کنید.',setupCli:'یا از خط فرمان:',
  setupTokenShort:'راز SETUP_TOKEN وجود دارد اما خیلی کوتاه یا ساده است. آن را با مقداری حداقل ۱۲ نویسه‌ای عوض کنید و صفحه را دوباره بارگذاری کنید.',
  setupLocked:'راه‌اندازی قبلاً انجام شده اما دیگر رمز مدیری ذخیره نشده است. برای ورود دوباره، راز ADMIN_PASSWORD_HASH را تنظیم کنید (npm run hash-password).',
  cfgTitle:'نیاز به پیکربندی',cfgText:'این Worker نمی‌تواند به‌صورت امن اجرا شود، چون یک راز وجود ندارد یا خیلی ضعیف است. آن را در داشبورد کلادفلر (این Worker ← Settings ← Variables and Secrets) درست کنید و صفحه را دوباره بارگذاری کنید.',
  cfg_missing:'تنظیم نشده است',cfg_too_short:'خیلی کوتاه است — حداقل ۳۲ نویسه لازم است',cfg_too_weak:'خیلی ساده است — یک مقدار تصادفی یا عبارت عبور بلند بگذارید',cfg_invalid_format:'قالب نادرست دارد (قالب درست: v<n>:<old key>)',
  cfgHint:'هر عبارت عبور ۳۲ نویسه‌ای یا بلندتر کار می‌کند، مثلاً شش کلمهٔ تصادفی. بعد از افزودن سرور هرگز ENCRYPTION_KEY را عوض نکنید؛ وگرنه اطلاعات ورود SSH ذخیره‌شده دیگر رمزگشایی نمی‌شوند.',
  reload:'بارگذاری دوباره',pwBySecret:'رمز مدیر از راز ADMIN_PASSWORD_HASH می‌آید و این‌جا قابل تغییر نیست. با npm run hash-password یک هش تازه بسازید و راز را به‌روز کنید (wrangler secret put ADMIN_PASSWORD_HASH).'}
};
const LS = {get:(k)=>{try{return localStorage.getItem(k);}catch{return null;}},set:(k,v)=>{try{localStorage.setItem(k,v);}catch{}}};
// English is the default for everyone; Persian (RTL) is opt-in via the language toggle and remembered.
let lang = LS.get('lang') === 'fa' ? 'fa' : 'en';
const t = (k) => (I18N[lang] && I18N[lang][k]) || I18N.en[k] || k;
const LRI='\u2066', FSI='\u2068', PDI='\u2069';
const isoL = (s) => LRI+s+PDI;   // force-LTR isolate for places where elements cannot be used (option text, toasts, title)
const isoA = (s) => FSI+s+PDI;   // auto-direction isolate
function applyDir(){document.documentElement.lang=lang;document.documentElement.dir=lang==='fa'?'rtl':'ltr';}
applyDir();
const nf = (n) => {try{return Number(n).toLocaleString(lang==='fa'?'fa-IR':'en-US');}catch{return String(n);}};

const ICONS = {
 server:'<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><circle cx="7" cy="7.5" r="1"/><circle cx="7" cy="16.5" r="1"/>',
 grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
 term:'<rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M7 9l3 3-3 3M12 15h5"/>',
 folder:'<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
 file:'<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
 shield:'<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
 plug:'<path d="M9 7V3M15 7V3M7 7h10v4a5 5 0 0 1-10 0zM12 16v5"/>',
 gear:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
 list:'<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
 out:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
 globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
 link:'<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
 plus:'<path d="M12 5v14M5 12h14"/>',play:'<path d="M7 4.5v15l12-7.5z"/>',stop:'<rect x="6" y="6" width="12" height="12" rx="2"/>',
 copy:'<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>',
 check:'<path d="M20 6L9 17l-5-5"/>',x:'<path d="M18 6L6 18M6 6l12 12"/>',checkc:'<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
 alert:'<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
 xc:'<circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/>',key:'<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3L21 2M16 7l3 3M18.5 4.5l2 2"/>',
 refresh:'<path d="M21 12a9 9 0 1 1-2.6-6.4L21 8"/><path d="M21 3v5h-5"/>',upload:'<path d="M12 16V4M7 9l5-5 5 5M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>',
 download:'<path d="M12 4v12M7 11l5 5 5-5M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>',edit:'<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
 trash:'<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>',
 dots:'<circle cx="12" cy="5" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="12" cy="19" r="1.3"/>',
 arrowUp:'<path d="M12 19V5M5 12l7-7 7 7"/>',history:'<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 3"/>',
 sidebar:'<rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M9 4v16"/>',clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
 star:'<path d="M12 3l2.8 5.7 6.2.9-4.5 4.4 1.1 6.2L12 17.3 6.4 20.2l1.1-6.2L3 9.6l6.2-.9z"/>',eye:'<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
 eyeoff:'<path d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3 3.9M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
 activity:'<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',bolt:'<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',bell:'<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.9 1.9 0 0 0 3.4 0"/>',
 lock:'<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',save:'<path d="M5 3h11l5 5v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M7 3v6h8M7 21v-7h10v7"/>',
 chevL:'<path d="M15 18l-6-6 6-6"/>',chevR:'<path d="M9 18l6-6-6-6"/>',claude:'<path d="M12 3v18M3 12h18M5.6 5.6l12.8 12.8M18.4 5.6L5.6 18.4"/>',
 code:'<path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/>',home:'<path d="M3 11l9-8 9 8v9a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z"/>'
};
function icon(name, cls, size){const s=document.createElementNS('http://www.w3.org/2000/svg','svg');s.setAttribute('viewBox','0 0 24 24');s.setAttribute('width',String(size||18));s.setAttribute('height',String(size||18));s.setAttribute('fill','none');s.setAttribute('stroke','currentColor');s.setAttribute('stroke-width','1.8');s.setAttribute('stroke-linecap','round');s.setAttribute('stroke-linejoin','round');s.setAttribute('aria-hidden','true');s.innerHTML=ICONS[name]||'';if(cls)s.setAttribute('class',cls);return s;}
// constant illustrations for empty states
const ILL = {
 servers:'<rect x="22" y="18" width="88" height="26" rx="8" fill="#141c31" stroke="#2c3a5e"/><rect x="22" y="54" width="88" height="26" rx="8" fill="#141c31" stroke="#2c3a5e"/><circle cx="36" cy="31" r="4" fill="#7c9bff"/><circle cx="36" cy="67" r="4" fill="#3a4a72"/><rect x="48" y="28" width="40" height="6" rx="3" fill="#2c3a5e"/><rect x="48" y="64" width="28" height="6" rx="3" fill="#2c3a5e"/><circle cx="108" cy="80" r="14" fill="#4867f0"/><path d="M108 73v14M101 80h14" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/>',
 inbox:'<path d="M20 52l14-30h64l14 30v26a6 6 0 0 1-6 6H26a6 6 0 0 1-6-6z" fill="#141c31" stroke="#2c3a5e"/><path d="M20 52h28l6 10h24l6-10h28" fill="none" stroke="#3a4a72" stroke-width="2"/><circle cx="96" cy="26" r="12" fill="#3ddc97" opacity=".9"/><path d="M90 26l4 4 8-8" stroke="#06231a" stroke-width="2.5" fill="none" stroke-linecap="round"/>',
 folder:'<path d="M18 30a6 6 0 0 1 6-6h24l8 8h52a6 6 0 0 1 6 6v40a6 6 0 0 1-6 6H24a6 6 0 0 1-6-6z" fill="#141c31" stroke="#2c3a5e"/><path d="M18 42h96" stroke="#2c3a5e"/><circle cx="66" cy="62" r="11" fill="none" stroke="#fbbf24" stroke-width="2.5"/><path d="M74 70l8 8" stroke="#fbbf24" stroke-width="2.5" stroke-linecap="round"/>',
 activity:'<rect x="16" y="20" width="100" height="60" rx="10" fill="#141c31" stroke="#2c3a5e"/><path d="M26 58h16l8-18 12 30 10-22 6 10h28" fill="none" stroke="#7c9bff" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>',
 key:'<circle cx="46" cy="50" r="20" fill="#141c31" stroke="#2c3a5e" stroke-width="2"/><circle cx="46" cy="50" r="7" fill="#7c9bff"/><path d="M64 50h44M96 50v12M106 50v8" stroke="#3a4a72" stroke-width="5" stroke-linecap="round"/>'
};
function ill(name){const s=document.createElementNS('http://www.w3.org/2000/svg','svg');s.setAttribute('viewBox','0 0 132 100');s.setAttribute('class','ill');s.setAttribute('aria-hidden','true');s.innerHTML=ILL[name]||'';return s;}

// h('div.class', {attrs/on*}, children...) — text children always via textContent
function h(tag, props, ...kids){const [name,...cls]=tag.split('.');const el=document.createElement(name||'div');if(cls.length)el.className=cls.join(' ');
 if(props){for(const [k,v] of Object.entries(props)){if(v==null||v===false)continue;if(k.startsWith('on'))el.addEventListener(k.slice(2),v);else if(k==='value')el.value=v;else if(k==='checked')el.checked=!!v;else el.setAttribute(k,v===true?'':String(v));}}
 for(const k of kids.flat()){if(k==null||k===false)continue;el.append(k instanceof Node?k:document.createTextNode(String(k)));}return el;}
// LTR island: IPs, commands, paths, tokens, fingerprints — never let them reorder inside RTL text
const ltr = (text, tag, props) => h((tag||'span')+'.ltr', Object.assign({dir:'ltr'}, props||{}), text);
const auto = (text, tag) => h((tag||'span')+'.bidi', {dir:'auto'}, text);
function btn(cls, ic, label, props){const b=h('button.btn'+(cls?'.'+cls:''),Object.assign({type:'button'},props||{}));if(ic)b.append(icon(ic));if(label!=null)b.append(h('span.lbl',null,label));return b;}
function iconBtn(ic, label, props){return h('button.iconbtn',Object.assign({type:'button','aria-label':label,title:label},props||{}),icon(ic,null,20));}

const state = {csrf:null, view:location.hash.slice(1)||'overview', servers:[], current:LS.get('srv')||null, termHistory:(()=>{try{return JSON.parse(LS.get('termHist')||'[]');}catch{return [];}})(), cwd:{}, fview:LS.get('fview')||'list'};
const app = document.getElementById('app');

async function api(path, opts={}){
 const o={method:opts.method||'GET',headers:{},credentials:'same-origin'};
 if(opts.body!==undefined){if(opts.raw){o.body=opts.body;o.headers['content-type']='application/octet-stream';}else{o.body=JSON.stringify(opts.body);o.headers['content-type']='application/json';}}
 if(o.method!=='GET'&&state.csrf)o.headers['x-csrf-token']=state.csrf;
 const r=await fetch('/api'+path,o);
 if(opts.stream)return r;
 let j=null;try{j=await r.json();}catch{}
 if(r.status===401&&!path.startsWith('/auth')){state.csrf=null;renderLogin();throw new Error('auth');}
 if(!r.ok){const e=new Error((j&&(j.error||j.message||j.reason))||('HTTP '+r.status));e.status=r.status;e.body=j;throw e;}
 return j;
}
// chunk upload with real progress (same endpoint, same CSRF header as api())
function xhrUpload(path, body, onProgress){return new Promise((res,rej)=>{const x=new XMLHttpRequest();x.open('POST','/api'+path);x.withCredentials=true;x.setRequestHeader('content-type','application/octet-stream');if(state.csrf)x.setRequestHeader('x-csrf-token',state.csrf);
 x.upload.onprogress=(e)=>{if(e.lengthComputable)onProgress(e.loaded);};
 x.onload=()=>{let j=null;try{j=JSON.parse(x.responseText);}catch{}if(x.status===401){state.csrf=null;renderLogin();rej(new Error('auth'));return;}if(x.status<200||x.status>=300){rej(new Error((j&&(j.error||j.message||j.reason))||('HTTP '+x.status)));return;}res(j);};
 x.onerror=()=>rej(new Error('network error'));x.send(body);});}

function toast(msg, bad){let box=document.getElementById('toasts');if(!box){box=h('div.toasts',{id:'toasts',role:'status','aria-live':'polite'});document.body.append(box);}
 const d=h('div.toast'+(bad?'.bad':''),null,icon(bad?'xc':'checkc'),h('div.bidi',{dir:'auto'},msg));box.append(d);while(box.children.length>3)box.firstChild.remove();setTimeout(()=>d.remove(),bad?6000:2600);}
function fmtTime(ts){if(!ts)return t('never');try{return new Date(ts).toLocaleString(lang==='fa'?'fa-IR':undefined,{dateStyle:'medium',timeStyle:'short'});}catch{return String(ts);}}
function relTime(ts){if(!ts)return t('never');try{const rtf=new Intl.RelativeTimeFormat(lang==='fa'?'fa':'en',{numeric:'auto'});const d=(ts-Date.now())/1000;const a=Math.abs(d);
 if(a<45)return rtf.format(Math.round(d),'second');if(a<2700)return rtf.format(Math.round(d/60),'minute');if(a<79200)return rtf.format(Math.round(d/3600),'hour');if(a<2592000)return rtf.format(Math.round(d/86400),'day');return fmtTime(ts);}catch{return fmtTime(ts);}}
function fmtBytes(n){if(n==null)return'';const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return (i?n.toFixed(1):n)+' '+u[i];}
const ST_ICON={connected:'checkc',disconnected:'clock',error:'xc',hostkey_pending:'key',hostkey_mismatch:'alert'};
function pill(s){return h('span.pill.s-'+s,{'data-status':s},s==='connected'?h('span.dot'):icon(ST_ICON[s]||'clock'),t('st_'+s));}
function outcomeClass(o){o=String(o||'');if(/^(ok|completed|success|approved|executed|connected)$/.test(o))return 'o-ok';if(/denied|blocked|error|fail|rate_limited|timeout|mismatch|reject/.test(o))return 'o-bad';if(/pending|cancel|expired/.test(o))return 'o-warn';return '';}
function empty(il, title, sub, action){return h('div.empty',null,ill(il),h('div.t',null,title),sub?h('div.s',null,sub):null,action||null);}
function td(label, ...kids){return h('td',{'data-label':label},...kids);}
function table(headers, tbody){return h('div.tbl-wrap',null,h('table.tbl',null,h('thead',null,h('tr',null,...headers.map(x=>h('th',null,x)))),tbody));}
function lockScroll(){document.documentElement.classList.toggle('modal-open',!!document.querySelector('.modal-bg'));}
function modal(title, body, actions, opts){opts=opts||{};const bg=h('div.modal-bg');const prevFocus=document.activeElement;
 let closed=false;const close=()=>{if(closed)return;closed=true;Element.prototype.remove.call(bg);document.removeEventListener('keydown',onKey);lockScroll();if(opts.onClose)opts.onClose();if(prevFocus&&prevFocus.focus&&document.contains(prevFocus))try{prevFocus.focus({preventScroll:true});}catch{}};
 const onKey=(e)=>{if(e.key!=='Escape')return;const all=document.querySelectorAll('.modal-bg');if(all[all.length-1]===bg){e.preventDefault();close();}};
 const m=h('div.modal'+(opts.narrow?'.narrow':''),{role:'dialog','aria-modal':'true',tabindex:'-1','aria-label':typeof title==='string'?title:''},
  h('div.modal-h',null,h('h2',null,title),iconBtn('x',t('close'),{onclick:close})),body,(actions&&actions.length)?h('div.modal-f',null,...actions):null);
 bg.append(m);bg.addEventListener('click',e=>{if(e.target===bg)close();});document.addEventListener('keydown',onKey);document.body.append(bg);bg.remove=close;lockScroll();
 if(!opts.noFocus&&isDesktop()){const f=m.querySelector('input:not([type=checkbox]),textarea');if(f)try{f.focus({preventScroll:true});}catch{}}else{try{m.focus({preventScroll:true});}catch{}}return bg;}
function askText(title, initial, opts){return new Promise((resolve)=>{opts=opts||{};const inp=h('input',{type:'text',value:initial||'',dir:opts.ltr?'ltr':'auto',autocomplete:'off',spellcheck:'false',autocapitalize:'off','aria-label':opts.label||title});
 let done=false;const fin=(v)=>{if(done)return;done=true;resolve(v);m.remove();};
 const m=modal(title,h('div',null,opts.label?h('label',null,opts.label):null,inp),[btn('primary','check',t('ok'),{'data-action':'ok',onclick:()=>fin(inp.value)}),btn('','',t('cancel'),{onclick:()=>fin(null)})],{narrow:true,onClose:()=>{if(!done){done=true;resolve(null);}}});
 inp.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();fin(inp.value);}});try{inp.focus({preventScroll:true});if(initial){const i=initial.lastIndexOf('/')+1;inp.setSelectionRange(i,initial.length);}}catch{}});}
function sheet(title, items){const list=h('div.sheet-list');const m=modal(title,list,null,{narrow:true,noFocus:true});
 for(const it of items){if(!it)continue;list.append(h('button.sheet-item'+(it.danger?'.danger':''),{type:'button','data-action':it.action||null,onclick:()=>{m.remove();it.run();}},icon(it.icon||'chevR',null,20),h('span',null,it.label),it.badge?h('span.badge',null,it.badge):null));}return m;}
async function copy(text){try{await navigator.clipboard.writeText(text);toast(t('copied'));}catch{const ta=h('textarea');ta.value=text;document.body.append(ta);ta.select();try{document.execCommand('copy');toast(t('copied'));}catch{toast(text);}ta.remove();}}
function copyRow(value, opts){opts=opts||{};const v=ltr(value,'div',{class:'copyval'+(opts.big?' big':''),'data-copy':opts.name||null});
 const b=btn(opts.big?'primary.big':'small','copy',t('copy'),{onclick:()=>copy(opts.get?opts.get():v.textContent),'aria-label':t('copy')+' '+(opts.name||'')});return h('div.copyrow'+(opts.big?'.stackable':''),null,v,b);}
function skeleton(v){const s=h('div.stack',{'aria-busy':'true'});
 if(v==='overview'){s.append(h('div.grid.stats',null,...[1,2,3,4,5,6].map(()=>h('div.sk.stat'))),h('div.grid.cols-2',null,h('div.sk.card'),h('div.sk.card')));}
 else{s.append(h('div.card',null,h('div.sk.h1'),h('div.sk.line'),h('div.sk.line.short'),h('div.sk.line')),h('div.sk.card'));}return s;}

// ---------------------------------------------------------------- shell
async function boot(){
 const me=await api('/auth/me');
 if(me.config_errors&&me.config_errors.length){renderConfigError(me);return;}
 if(!me.authenticated&&me.setup&&me.setup!=='done'&&me.setup!=='not_applicable'){renderSetup(me);return;}
 if(!me.authenticated){renderLogin(me);return;}
 state.csrf=me.csrf;renderShell();
}
function toggleLang(after){lang=lang==='en'?'fa':'en';LS.set('lang',lang);applyDir();after();}
function renderLogin(me){
 document.querySelectorAll('.modal-bg').forEach(x=>x.remove());lockScroll();
 app.replaceChildren();document.title='SSH MCP';const err=h('div.error',{role:'alert'});
 const pw=h('input',{type:'password',autocomplete:'current-password',id:'pw',dir:'ltr'});
 const eye=iconBtn('eye',t('showPw'),{onclick:()=>{const show=pw.type==='password';pw.type=show?'text':'password';eye.replaceChildren(icon(show?'eyeoff':'eye',null,20));eye.setAttribute('aria-label',t(show?'hidePw':'showPw'));}});
 const needPw=!me||me.auth_mode!=='access';
 const submit=h('button.btn.primary.big.block',{type:'submit'},icon('lock'),h('span',null,t('login')));
 const form=h('form.login',{onsubmit:async e=>{e.preventDefault();err.textContent='';submit.disabled=true;try{const r=await api('/auth/login',{method:'POST',body:needPw?{password:pw.value}:{}});state.csrf=r.csrf;renderShell();}catch(x){err.textContent=x.message;submit.disabled=false;}}},
  h('div.login-top',null,h('div.logo',null,icon('term',null,28)),btn('small.ghost','globe',t('lang'),{'data-action':'lang',onclick:()=>toggleLang(()=>renderLogin(me))})),
  h('h1',null,'SSH MCP'),h('p.sub',null,t('loginSub')),
  needPw?h('label',{for:'pw'},t('password')):null,needPw?h('div.pwwrap',null,pw,eye):null,
  h('div.mt',null,submit),err,me&&!me.configured?h('p.error.mt',null,t('notConfigured')):null);
 app.append(h('div.login-wrap',null,form));if(needPw)pw.focus();
}
function authCard(rerender, ...kids){
 document.querySelectorAll('.modal-bg').forEach(x=>x.remove());lockScroll();app.replaceChildren();document.title='SSH MCP';
 const card=h('div.login',{'data-view':'auth-card'},h('div.login-top',null,h('div.logo',null,icon('term',null,28)),btn('small.ghost','globe',t('lang'),{'data-action':'lang',onclick:()=>toggleLang(rerender)})),...kids);
 app.append(h('div.login-wrap',null,card));return card;}
function renderConfigError(me){
 const list=h('ul.cfg-list');for(const i of me.config_errors)list.append(h('li',null,ltr(i.name,'code'),' ',t('cfg_'+i.problem)));
 authCard(()=>renderConfigError(me),h('h1',{'data-role':'config-error'},t('cfgTitle')),h('p.sub',null,t('cfgText')),list,h('p.hint',null,t('cfgHint')),
  h('div.mt',null,btn('primary.big.block','refresh',t('reload'),{onclick:()=>location.reload()})));
}
function renderSetup(me){
 if(me.setup!=='available'){
  if(me.setup==='locked'){authCard(()=>renderSetup(me),h('h1',null,t('setupTitle')),h('p.error.mt',{'data-role':'setup-locked'},t('setupLocked')));return;}
  const short=me.setup_reason&&me.setup_reason!=='setup_token_missing';
  authCard(()=>renderSetup(me),h('h1',{'data-role':'setup-needs-token'},t('setupNeedsTitle')),
   short?h('p.error',null,t('setupTokenShort')):h('p.sub',null,t('setupNeedsText')),
   h('ol.steps.mt',null,h('li',null,t('setupStep1')),h('li',null,t('setupStep2')),h('li',null,t('setupStep3'))),
   h('p.hint.mt',null,t('setupCli')),ltr('npx wrangler secret put SETUP_TOKEN','div',{class:'copyval'}),
   h('div.mt',null,btn('primary.big.block','refresh',t('reload'),{onclick:()=>location.reload()})));
  return;}
 const err=h('div.error',{role:'alert'});
 const tok=h('input',{type:'password',autocomplete:'off',id:'setup-token',dir:'ltr',autocapitalize:'off',spellcheck:'false'});
 const pw=h('input',{type:'password',autocomplete:'new-password',id:'setup-pw',dir:'ltr'});
 const pw2=h('input',{type:'password',autocomplete:'new-password',id:'setup-pw2',dir:'ltr'});
 const eye=iconBtn('eye',t('showPw'),{onclick:()=>{const show=pw.type==='password';for(const x of [tok,pw,pw2])x.type=show?'text':'password';eye.replaceChildren(icon(show?'eyeoff':'eye',null,20));eye.setAttribute('aria-label',t(show?'hidePw':'showPw'));}});
 const submit=h('button.btn.primary.big.block',{type:'submit','data-action':'setup'},icon('lock'),h('span',null,t('setupBtn')));
 let csrf=null;
 const form=h('form',{onsubmit:async e=>{e.preventDefault();err.textContent='';
   if(pw.value.length<12){err.textContent=t('pwTooShort');return;}if(pw.value!==pw2.value){err.textContent=t('pwMismatch');return;}
   submit.disabled=true;
   try{if(!csrf){const st=await api('/setup');csrf=st.csrf;}
    const r=await fetch('/api/setup',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json','x-csrf-token':csrf||''},body:JSON.stringify({setup_token:tok.value,password:pw.value})});
    let j=null;try{j=await r.json();}catch{}
    if(!r.ok){if(r.status===403&&j&&j.state){boot();return;}throw new Error((j&&j.error)||('HTTP '+r.status));}
    state.csrf=j.csrf;renderShell();}catch(x){err.textContent=x.message;submit.disabled=false;}}},
  h('label',{for:'setup-token'},t('setupToken')),tok,h('p.hint',null,t('setupTokenHint')),
  h('label',{for:'setup-pw'},t('newAdminPw')),h('div.pwwrap',null,pw,eye),
  h('label',{for:'setup-pw2'},t('confirmPw')),pw2,
  h('div.mt',null,submit),err);
 authCard(()=>renderSetup(me),h('h1',{'data-role':'setup'},t('setupTitle')),h('p.sub',null,t('setupSub')),form);
 api('/setup').then(st=>{csrf=st.csrf;if(st.state!=='available')boot();}).catch(()=>{});
 try{tok.focus();}catch{}
}
const VIEWS=[['overview','grid'],['servers','server'],['terminal','term'],['files','folder'],['approvals','shield'],['mcp','plug'],['settings','gear'],['audit','list']];
const TABS=['overview','servers','terminal','files','mcp'];
let mainEl, titleEl, shellEl, navEls={}, tabEls={}, badgeTargets=[], pendingCount=0;
const isDesktop=()=>matchMedia('(min-width:768px)').matches;
async function logout(){await api('/auth/logout',{method:'POST'}).catch(()=>{});state.csrf=null;renderLogin();}
function moreSheet(){sheet(t('moreMenu'),[
 {label:t('approvals'),icon:'shield',action:'approvals',badge:pendingCount?nf(pendingCount):null,run:()=>go('approvals')},
 {label:t('settings'),icon:'gear',action:'settings',run:()=>go('settings')},
 {label:t('audit'),icon:'list',action:'audit',run:()=>go('audit')},
 {label:t('lang'),icon:'globe',action:'lang',run:()=>toggleLang(renderShell)},
 {label:t('logout'),icon:'out',action:'logout',danger:true,run:logout}]);}
function renderShell(){
 document.querySelectorAll('.modal-bg').forEach(x=>x.remove());lockScroll();
 app.replaceChildren();navEls={};tabEls={};badgeTargets=[];
 const sideStored=LS.get('side');const collapsed=sideStored?sideStored==='closed':(innerWidth>=768&&innerWidth<1200);
 const side=h('nav.side',{'aria-label':t('menu')});
 const collBtn=iconBtn('sidebar',t(collapsed?'expand':'collapse'),{'data-action':'collapse',onclick:()=>{const c=!shellEl.classList.contains('collapsed');shellEl.classList.toggle('collapsed',c);LS.set('side',c?'closed':'open');collBtn.setAttribute('aria-label',t(c?'expand':'collapse'));collBtn.title=t(c?'expand':'collapse');}});
 side.append(h('div.brand',null,h('div.logo',null,icon('term',null,20)),h('div.txt',null,h('div.name',null,'SSH MCP'),h('div.tag',null,location.host))));
 for(const [v,ic] of VIEWS){const b=h('button.nav',{type:'button','data-view':v,title:t(v),onclick:()=>go(v)},icon(ic,null,20),h('span',null,t(v)));navEls[v]=b;side.append(b);if(v==='mcp')side.append(h('div.nav-sep'));}
 if(navEls.approvals)badgeTargets.push(navEls.approvals);
 side.append(h('div.spacer'),h('button.nav',{type:'button','data-action':'lang',title:t('lang'),onclick:()=>toggleLang(renderShell)},icon('globe',null,20),h('span',null,t('lang'))),
  h('button.nav',{type:'button','data-action':'logout',title:t('logout'),onclick:logout},icon('out',null,20),h('span',null,t('logout'))));
 titleEl=h('h1');
 const bell=iconBtn('bell',t('approvals'),{class:'iconbtn m-only','data-action':'bell',onclick:()=>go('approvals')});badgeTargets.push(bell);
 const more=iconBtn('dots',t('moreMenu'),{class:'iconbtn m-only','data-action':'more',onclick:moreSheet});
 const top=h('header.topbar',null,h('div.logo',null,icon('term',null,18)),h('span.d-only',null,collBtn),titleEl,
  h('div.top-actions',null,btn('small.ghost.d-only','globe',t('lang'),{'data-action':'lang-top',onclick:()=>toggleLang(renderShell)}),bell,more));
 mainEl=h('main');
 const tabbar=h('nav.tabbar',{'aria-label':t('menu')});
 for(const v of TABS){const ic=VIEWS.find(x=>x[0]===v)[1];const b=h('button.tab',{type:'button','data-view':v,onclick:()=>go(v)},h('span.tab-ic',null,icon(ic,null,22)),h('span.lbl',null,t(v)));tabEls[v]=b;tabbar.append(b);}
 shellEl=h('div.shell'+(collapsed?'.collapsed':''),null,side,h('div.content',null,top,mainEl));
 app.append(shellEl,tabbar);go(state.view);refreshBadge();
}
async function refreshBadge(){try{const p=await api('/confirmations?status=pending');pendingCount=p.length;for(const b of badgeTargets){b.querySelector('.badge')?.remove();if(p.length)b.append(h('span.badge',{'aria-label':String(p.length)},nf(p.length)));}}catch{}}
function rerender(v){if(state.view===v)go(v);}
function go(v){if(!VIEWS.find(x=>x[0]===v))v='overview';state.view=v;if(location.hash.slice(1)!==v)location.hash=v;
 for(const [k,el] of Object.entries(navEls)){el.classList.toggle('active',k===v);if(k===v)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');}
 for(const [k,el] of Object.entries(tabEls)){el.classList.toggle('active',k===v);if(k===v)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');}
 titleEl.textContent=t(v);document.title=t(v)+' · SSH MCP';
 const fresh=h('main.v-'+v,{id:'main'});mainEl.replaceWith(fresh);mainEl=fresh;window.scrollTo(0,0);
 if(v!=='terminal')mainEl.append(h('p.page-sub',null,t('sub_'+v)));
 const root=mainEl;const body=h('div.stack.view');const sk=skeleton(v);root.append(sk);
 ({overview:viewOverview,servers:viewServers,terminal:viewTerminal,files:viewFiles,approvals:viewApprovals,mcp:viewMcp,settings:viewSettings,audit:viewAudit})[v](body)
  .then(()=>{sk.replaceWith(body);if(body.__after)body.__after();})
  .catch(e=>{if(e.message!=='auth'){sk.replaceWith(h('div.card',null,h('div.dangerbox',null,h('div.box-h',null,icon('alert'),h('span.bidi',{dir:'auto'},e.message))),btn('','refresh',t('refresh'),{onclick:()=>go(v)})));}});}
async function loadServers(){state.servers=await api('/servers');if(!state.servers.find(s=>s.id===state.current)){const d=state.servers.find(s=>s.is_default)||state.servers[0];state.current=d?d.id:null;}return state.servers;}
const strongDir=(txt)=>{const m=/[A-Za-z\u00C0-\u024F\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFF]/.exec(txt||'');return m&&/[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFF]/.test(m[0])?'rtl':(m?'ltr':(lang==='fa'?'rtl':'ltr'));};
function serverPicker(onchange){const fix=()=>{const o=sel.options[sel.selectedIndex];sel.dir=strongDir(o?o.text:'');};
 const sel=h('select',{'aria-label':t('server'),'data-role':'server-picker',onchange:e=>{state.current=e.target.value;LS.set('srv',state.current);fix();onchange();}});setTimeout(fix,0);
 for(const s of state.servers)sel.append(h('option',{value:s.id,selected:s.id===state.current,title:s.username+'@'+s.host+':'+s.port},s.name+(s.is_default?' ★':'')));return sel;}
function noServersState(){return h('div.card',null,empty('servers',t('noServers'),t('noServersSub'),btn('primary','plus',t('addServer'),{onclick:()=>{go('servers');setTimeout(()=>serverForm(),50);}})));}

// ---------------------------------------------------------------- overview
async function viewOverview(root){
 const o=await api('/overview');const T=o.totals;
 const stat=(k,v,ic,tone,to)=>h('button.card.stat'+(tone?'.t-'+tone:''),{type:'button','data-stat':k,onclick:()=>go(to)},h('div.ic',null,icon(ic,null,20)),h('div.v',null,nf(v)),h('div.k',null,t(k)));
 root.append(h('div.grid.stats',null,stat('totalServers',T.servers,'server','','servers'),stat('connected',T.connected,'checkc','ok','servers'),stat('failed',T.failed,'xc',T.failed?'bad':'','servers'),
  stat('pendingKeys',T.pending_hostkeys,'key',T.pending_hostkeys?'warn':'','servers'),stat('pendingConf',T.pending_confirmations,'shield',T.pending_confirmations?'warn':'','approvals'),stat('cmds24',T.commands_24h,'bolt','violet','terminal')));
 const srvCard=h('div.card',null,h('div.card-h',null,h('h2',null,icon('server'),t('perServer')),h('span.grow'),btn('small.ghost','chevR',null,{'aria-label':t('servers'),onclick:()=>go('servers')})));
 if(!o.servers.length)srvCard.append(empty('servers',t('noServers'),t('noServersSub'),btn('primary','plus',t('addServer'),{onclick:()=>{go('servers');setTimeout(()=>serverForm(),50);}})));
 else{const l=h('div.list');for(const s of o.servers)l.append(h('div.li',{'data-server':s.name},h('div.tile.s-'+s.status,null,icon('server',null,20)),
   h('div.main',null,h('div.t1',null,auto(s.name,'span'),s.is_default?h('span.pill.accent',null,icon('star'),t('default')):null),h('div.t2',null,ltr(s.username+'@'+s.host+':'+s.port)),
    s.last_error?ltr(s.last_error,'div',{class:'t2 error mono'}):null),
   h('div.end',null,pill(s.status),h('span.t2',{title:fmtTime(s.last_connected_at)},relTime(s.last_connected_at)))));srvCard.append(l);}
 const actCard=h('div.card',null,h('div.card-h',null,h('h2',null,icon('activity'),t('recent')),h('span.grow'),btn('small.ghost','chevR',null,{'aria-label':t('audit'),onclick:()=>go('audit')})));
 if(!o.recent_activity.length)actCard.append(empty('activity',t('noActivity')));
 else{const tl=h('div.timeline');for(const a of o.recent_activity.slice(0,15))tl.append(h('div.tl.'+(outcomeClass(a.outcome)||'o-none'),null,
   h('div.t1',null,ltr(a.action,'span'),h('span.pill.soft.'+(outcomeClass(a.outcome)||'x'),null,ltr(a.outcome||'—')),a.auto_approved?autoBadge(a.auto_level):null),
   h('div.t2',null,ltr(a.actor||''),' · ',h('span',{title:fmtTime(a.ts)},relTime(a.ts))),a.detail?ltr(String(a.detail).slice(0,160),'div',{class:'det mono'}):null));actCard.append(tl);}
 root.append(h('div.grid.cols-2',null,srvCard,actCard));
}

// ---------------------------------------------------------------- servers
async function viewServers(root){
 await loadServers();
 root.append(h('div.row.between',null,h('span.muted',null,t('servers')+': '+nf(state.servers.length)),btn('primary','plus',t('addServer'),{'data-action':'add-server',onclick:()=>serverForm()})));
 if(!state.servers.length){root.append(h('div.card',null,empty('servers',t('noServers'),t('noServersSub'))));return;}
 const grid=h('div.grid.srv-grid');root.append(grid);
 for(const s of state.servers){
  const card=h('div.card.srv',{'data-server':s.name});
  card.append(h('div.li',null,h('div.tile.s-'+s.status,null,icon('server',null,20)),h('div.main',null,h('div.t1',null,auto(s.name,'strong'),s.is_default?h('span.pill.accent',null,icon('star'),t('default')):null),
   h('div.t2',null,ltr(s.username+'@'+s.host+':'+s.port))),h('div.end',null,pill(s.status))));
  const chips=h('div.row.mt');chips.append(h('span.pill.soft',null,icon(s.auth_method==='key'?'key':'lock'),s.auth_method==='key'?t('key'):t('pwd')),h('span.pill.soft',null,icon('shield'),s.policy_mode==='read_only'?t('ro'):t('mod')));
  const ap=aaPill(s.auto_approve);if(ap)chips.append(ap);
  if(s.allow_sudo_install)chips.append(h('span.pill.soft',null,ltr('sudo install')));if(s.allow_root)chips.append(h('span.pill.o-warn',null,ltr('root')));
  for(const l of s.labels)chips.append(h('span.pill.soft',null,auto(l)));card.append(chips);
  card.append(h('div.kv.mt',null,h('span.k',null,t('hostKey')+':'),s.host_key_fingerprint?ltr((s.host_key_algo||'')+' '+s.host_key_fingerprint,'span',{class:'mono'}):h('span.muted',null,t('tofuPending'))));
  card.append(h('div.aa-row',{'data-role':'aa-quick'},h('div.aa-h',null,icon('bolt'),h('span',null,t('autoApprove'))),aaControl(s.auto_approve,(v,prev)=>quickAuto(s,v,prev).then(okk=>{if(okk)rerender('servers');return okk;}),{compact:true}).el));
  if(s.status==='hostkey_pending'&&s.pending_fingerprint){card.append(h('div.warnbox',{'data-role':'hostkey-pending'},h('div.box-h',null,icon('key'),h('span',null,t('approveKeyText'))),ltr('ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub','code'),
   ltr((s.pending_fingerprint_algo||'')+' '+s.pending_fingerprint,'div',{class:'mono'}),
   h('div',null,btn('primary.small','check',t('approveKey'),{'data-action':'approve-key',onclick:async()=>{try{await api('/servers/'+s.id+'/approve-hostkey',{method:'POST',body:{fingerprint:s.pending_fingerprint}});toast('✓ '+t('approveKey'));rerender('servers');}catch(e){toast(e.message,true);}}}))));}
  if(s.status==='hostkey_mismatch')card.append(h('div.dangerbox',null,h('div.box-h',null,icon('alert'),h('span',null,t('mismatch')))));
  if(s.last_error&&s.status!=='hostkey_pending')card.append(h('div.dangerbox',null,h('div.box-h',null,icon('xc'),ltr(s.last_error,'span',{class:'mono'}))));
  const hist=h('div');
  const histBtn=btn('small.ghost','history',t('connHistory'),{'data-action':'history',onclick:async()=>{if(hist.childNodes.length){hist.replaceChildren();return;}try{const rows=await api('/servers/'+s.id+'/history');const tb=h('tbody');
   for(const r of rows)tb.append(h('tr',null,td(t('time'),fmtTime(r.ts)),td(t('event'),h('span.pill.soft.'+(outcomeClass(r.event)||'x'),null,ltr(r.event))),td(t('detail'),r.detail?ltr(r.detail,'span',{class:'mono'}):''),td('ms',r.duration_ms!=null?ltr(nf(r.duration_ms)+' ms'):'')));
   hist.replaceChildren(h('div.mt',null,rows.length?table([t('time'),t('event'),t('detail'),''],tb):h('p.muted',null,t('noActivity'))));}catch(e){toast(e.message,true);}}});
  card.append(h('div.actions.mt',null,
   btn('primary.small','bolt',t('connect'),{'data-action':'connect',onclick:()=>act(s,'connect')}),btn('small','activity',t('test'),{'data-action':'test',onclick:()=>act(s,'test')}),
   btn('small','x',t('disconnect'),{'data-action':'disconnect',onclick:()=>act(s,'disconnect')}),btn('small','edit',t('edit'),{'data-action':'edit',onclick:()=>serverForm(s)}),
   s.is_default?null:btn('small','star',t('makeDefault'),{'data-action':'default',onclick:()=>act(s,'default')}),
   btn('small.danger','trash',t('del'),{'data-action':'delete',onclick:()=>{const m=modal(t('del')+' — '+isoA(s.name)+'?',h('p',null,ltr(s.username+'@'+s.host)),[btn('danger','trash',t('del'),{onclick:async()=>{try{await api('/servers/'+s.id,{method:'DELETE'});m.remove();rerender('servers');}catch(e){toast(e.message,true);}}}),btn('','',t('cancel'),{onclick:()=>m.remove()})],{narrow:true});}})),
   h('div.mt',null,histBtn),hist);
  grid.append(card);
 }
}
async function act(s, what){try{const r=await api('/servers/'+s.id+'/'+what,{method:'POST'});toast(t('act_'+what)+': '+(r.ok===false?r.message:'ok')+(r.latency_ms?' ('+nf(r.latency_ms)+' ms)':''),r.ok===false);}catch(e){if(e.body&&e.body.code==='HOSTKEY_UNKNOWN')toast(t('approveKey')+' — '+isoA(s.name));else toast(e.message,true);}rerender('servers');}
function seg(options, value, label){const wrap=h('div.seg',{role:'group','aria-label':label});const ctl={get value(){return value;},addEventListener:(ev,fn)=>wrap.addEventListener('segchange',fn)};
 for(const [v,lbl,ic] of options){const b=h('button',{type:'button','aria-pressed':String(v===value),'data-value':v,onclick:()=>{value=v;for(const x of wrap.children)x.setAttribute('aria-pressed',String(x.dataset.value===v));wrap.dispatchEvent(new Event('segchange'));}},ic?icon(ic):null,lbl);wrap.append(b);}
 ctl.el=wrap;return ctl;}
// ---------------------------------------------------------------- auto-approve controls
const AA=['off','safe','all'];
const AA_ICON={off:'lock',safe:'shield',all:'bolt'};
function isAllWord(v){v=String(v||'').trim().replace(/\u064A/g,'\u06CC').replace(/\u0643/g,'\u06A9');return /^confirm$/i.test(v)||v==='\u062A\u0623\u06CC\u06CC\u062F'||v==='\u062A\u0627\u06CC\u06CC\u062F';}
function aaPill(level){return level&&level!=='off'?h('span.pill.aa-'+level,{'data-role':'aa-pill'},icon(AA_ICON[level]),t('autoApprove')+': '+t('aa_'+level)):null;}
function autoBadge(level){return h('span.pill.auto',{'data-role':'auto-badge',title:t('autoApprove')+(level?' · '+t('aa_'+level):'')},icon('bolt'),t('autoBadge')+(level?' · '+t('aa_'+level):''));}
// 3-state segmented control; onPick(v) may return false/Promise<false> to refuse the change
function aaControl(value, onPick, opts){opts=opts||{};const wrap=h('div.seg.aa'+(opts.compact?'.compact':''),{role:'radiogroup','aria-label':t('autoApprove'),'data-role':'auto-approve'});
 const ctl={get value(){return value;},el:wrap,set(v){value=v;for(const x of wrap.children){x.setAttribute('aria-pressed',String(x.dataset.value===v));x.setAttribute('aria-checked',String(x.dataset.value===v));}}};
 for(const v of AA){wrap.append(h('button',{type:'button',role:'radio','data-value':v,'aria-pressed':String(v===value),'aria-checked':String(v===value),onclick:async()=>{if(v===value)return;const prev=value;ctl.set(v);let okk=true;try{okk=(await onPick(v,prev))!==false;}catch{okk=false;}if(!okk)ctl.set(prev);}},icon(AA_ICON[v]),h('span',null,t('aa_'+v))));}
 return ctl;}
// typed confirmation before "all"; resolves with the typed word or null
function askAllConfirm(subject){return new Promise((resolve)=>{const inp=h('input',{type:'text',autocomplete:'off',spellcheck:'false',autocapitalize:'off',dir:'auto','aria-label':t('aaTypeConfirm'),'data-role':'aa-confirm-input',placeholder:t('aaConfirmWord')});
 let done=false;const fin=(v)=>{if(done)return;done=true;resolve(v);m.remove();};
 const go=btn('danger','bolt',t('aaEnable'),{'data-action':'aa-confirm',disabled:true,onclick:()=>{if(isAllWord(inp.value))fin(inp.value.trim());}});
 inp.addEventListener('input',()=>{go.disabled=!isAllWord(inp.value);});inp.addEventListener('keydown',e=>{if(e.key==='Enter'&&isAllWord(inp.value)){e.preventDefault();fin(inp.value.trim());}});
 const m=modal(t('aaConfirmTitle'),h('div',null,h('div.dangerbox',null,h('div.box-h',null,icon('alert'),h('span',null,t('aaHint_all'))),subject?auto(subject,'div'):null),h('label',null,t('aaTypeConfirm')),inp),[go,btn('','',t('cancel'),{onclick:()=>fin(null)})],{narrow:true,onClose:()=>{if(!done){done=true;resolve(null);}}});
 try{inp.focus({preventScroll:true});}catch{}});}
// quick switch: POST /servers/:id/auto-approve
async function quickAuto(s, v, prev){let confirm_text;if(v==='all'&&prev!=='all'){confirm_text=await askAllConfirm(s.name);if(!confirm_text)return false;}
 try{const r=await api('/servers/'+s.id+'/auto-approve',{method:'POST',body:confirm_text?{level:v,confirm_text}:{level:v}});s.auto_approve=r.auto_approve;toast(t('aaUpdated')+': '+isoA(s.name)+' · '+t('aa_'+v));return true;}catch(e){toast(e.message,true);return false;}}
function aaHint(level){return h('p.aa-hint.'+level,{'data-role':'aa-hint'},t('aaHint_'+level));}
function serverForm(s){
 const f={};const editing=!!s;
 const inp=(k,type,attrs)=>(f[k]=h('input',Object.assign({type:type||'text',value:s?(s[k]??''):''},attrs||{})));
 f.auth_method=seg([['password',t('pwd'),'lock'],['key',t('key'),'key']],s?s.auth_method:'password',t('auth'));
 f.password=h('input',{type:'password',autocomplete:'new-password',dir:'ltr',placeholder:editing&&s.password==='set'?t('unchanged'):''});
 f.private_key=h('textarea',{rows:5,dir:'ltr',spellcheck:'false',placeholder:editing&&s.private_key==='set'?t('unchanged'):'-----BEGIN OPENSSH PRIVATE KEY-----'});
 f.passphrase=h('input',{type:'password',autocomplete:'new-password',dir:'ltr',placeholder:editing&&s.passphrase==='set'?t('unchanged'):''});
 f.policy_mode=seg([['modify',t('mod'),'edit'],['read_only',t('ro'),'eye']],s?s.policy_mode:'modify',t('policy'));
 const origAA=s?s.auto_approve:'off';let aaTouched=false;
 const aaHintEl=h('div');const aaConfirm=h('input',{type:'text',autocomplete:'off',spellcheck:'false',autocapitalize:'off',dir:'auto','data-role':'aa-confirm-input',placeholder:t('aaConfirmWord'),'aria-label':t('aaTypeConfirm')});
 const aaConfirmRow=h('div.dangerbox.hidden',{'data-role':'aa-all-warning'},h('div.box-h',null,icon('alert'),h('strong',null,t('aaConfirmTitle'))),h('label',null,t('aaTypeConfirm')),aaConfirm);
 const syncAA=()=>{const v=f.auto_approve.value;aaHintEl.replaceChildren(aaHint(v));aaConfirmRow.classList.toggle('hidden',!(v==='all'&&origAA!=='all'));};
 f.auto_approve=aaControl(origAA,()=>{aaTouched=true;setTimeout(syncAA,0);return true;});syncAA();
 if(!s)api('/settings').then(x=>{if(!aaTouched&&x&&x.default_auto_approve){f.auto_approve.set(x.default_auto_approve);syncAA();}}).catch(()=>{});
 f.labels=h('input',{value:s?s.labels.join(', '):'',dir:'auto'});
 f.host_key_fingerprint=h('input',{value:s&&s.host_key_fingerprint||'',placeholder:'SHA256:…',dir:'ltr',spellcheck:'false',autocapitalize:'off'});
 const cb=(k,lbl)=>{f[k]=h('input',{type:'checkbox',checked:s?s[k]:false,role:'switch'});return h('label.check.full',null,f[k],h('span',null,t(lbl)));};
 const pwRow=h('div.full',null,h('label',null,t('pwd')),f.password);const keyRow=h('div.full',null,h('label',null,t('key')),f.private_key,h('label',null,t('passphrase')),f.passphrase);
 const sync=()=>{pwRow.classList.toggle('hidden',f.auth_method.value!=='password');keyRow.classList.toggle('hidden',f.auth_method.value!=='key');};f.auth_method.addEventListener('segchange',sync);sync();
 const err=h('div.error.full',{role:'alert'});
 const lt={dir:'ltr',spellcheck:'false',autocapitalize:'off',autocomplete:'off'};
 const body=h('div.form',null,h('div.fsec',null,icon('server'),t('secConn')),
  h('div',null,h('label',null,t('name')),inp('name','text',{dir:'auto',autocomplete:'off'})),h('div',null,h('label',null,t('host')),inp('host','text',Object.assign({inputmode:'url',placeholder:'203.0.113.10'},lt))),
  h('div',null,h('label',null,t('port')),inp('port','number',Object.assign({min:1,max:65535,value:s?s.port:22,inputmode:'numeric'},lt))),h('div',null,h('label',null,t('username')),inp('username','text',lt)),
  h('div.fsec',null,icon('lock'),t('secAuth')),h('div.full',null,h('label',null,t('auth')),f.auth_method.el),pwRow,keyRow,
  h('div.fsec',null,icon('shield'),t('secSec')),h('div.full',null,h('label',null,t('policy')),f.policy_mode.el,h('p.hint',null,t('readOnlyNote'))),
  h('div.full',{'data-role':'aa-field'},h('label',null,icon('bolt'),' ',t('autoApprove')),f.auto_approve.el,aaHintEl,aaConfirmRow,h('p.hint',null,t('aaRoNote'))),
  h('div.full',null,h('label',null,t('fp')),f.host_key_fingerprint),h('div.full',null,h('label',null,t('labels')),f.labels),cb('allow_root','allowRoot'),cb('allow_sudo_install','sudoInst'),cb('is_default','makeDefault'),err);
 const m=modal(editing?t('edit')+' — '+isoA(s.name):t('addServer'),body,[btn('primary','save',t('save'),{'data-action':'save',onclick:async()=>{
  const p={name:f.name.value,host:f.host.value.trim(),port:Number(f.port.value),username:f.username.value.trim(),auth_method:f.auth_method.value,policy_mode:f.policy_mode.value,
   labels:f.labels.value.split(',').map(x=>x.trim()).filter(Boolean),allow_root:f.allow_root.checked,allow_sudo_install:f.allow_sudo_install.checked,is_default:f.is_default.checked};
  const aav=f.auto_approve.value;if(editing?aav!==origAA:aaTouched){p.auto_approve=aav;if(aav==='all'&&origAA!=='all'){if(!isAllWord(aaConfirm.value)){err.textContent=t('aaTypeConfirm');try{aaConfirm.focus();}catch{}return;}p.auto_approve_confirm=aaConfirm.value.trim();}}
  if(f.password.value)p.password=f.password.value;if(f.private_key.value)p.private_key=f.private_key.value;if(f.passphrase.value)p.passphrase=f.passphrase.value;
  const fp=f.host_key_fingerprint.value.trim();if(fp&&(!s||fp!==s.host_key_fingerprint))p.host_key_fingerprint=fp;
  try{await api(editing?'/servers/'+s.id:'/servers',{method:editing?'PATCH':'POST',body:p});
   f.password.value='';f.private_key.value='';f.passphrase.value='';m.remove();toast('✓ '+t('saved'));rerender('servers');}catch(e){err.textContent=e.message;}}}),
  editing?btn('','key',t('resetKey'),{'data-action':'reset-key',onclick:async()=>{try{await api('/servers/'+s.id,{method:'PATCH',body:{reset_host_key:true}});m.remove();rerender('servers');}catch(e){err.textContent=e.message;}}}):null,
  btn('','',t('cancel'),{'data-action':'cancel',onclick:()=>m.remove()})].filter(Boolean));
}

// ---------------------------------------------------------------- terminal
let termBusy=null;
const QUICK=['uptime','df -h','free -m','uname -a','whoami','ps aux --sort=-%cpu | head -n 15','systemctl --failed','docker ps','ip -brief addr','ls -la'];
async function viewTerminal(root){
 await loadServers();if(!state.servers.length){root.append(noServersState());return;}
 const out=h('div.term',{dir:'ltr',role:'log','aria-live':'polite',tabindex:'0','aria-label':t('terminal')},h('span.hintline',{dir:'auto'},t('termHint')+'\n'));
 const cmd=h('input.mono',{placeholder:t('cmdPlaceholder'),autocomplete:'off',autocorrect:'off',autocapitalize:'off',spellcheck:'false',dir:'ltr',enterkeyhint:'send','aria-label':t('terminal'),'data-role':'cmd'});
 const to=h('input',{type:'number',min:1,max:600,value:LS.get('termTimeout')||60,inputmode:'numeric',dir:'ltr',id:'term-to'});
 const stat=h('span.term-status-text');const exitB=h('span.exit-badge.hidden',{'data-role':'exit'});const spin=h('span.spin.hidden');
 const runBtn=btn('primary','play',t('run'),{'data-action':'run','aria-label':t('run')});const stopBtn=btn('danger','stop',t('stop'),{disabled:true,'data-action':'stop','aria-label':t('stop')});
 let hi=-1;
 const line=(text,cls)=>{out.querySelector('.hintline')?.remove();const s=h('span'+(cls?'.'+cls:''),null,text);out.append(s);if(out.childNodes.length>4000)out.firstChild.remove();out.scrollTop=out.scrollHeight;};
 const setExit=(ev)=>{exitB.classList.remove('hidden','ok','bad','warn');const okk=ev.status==='completed'&&ev.exitCode===0;exitB.classList.add(okk?'ok':(ev.status==='completed'||ev.status==='failed'?'bad':'warn'));
  exitB.replaceChildren(icon(okk?'check':(ev.status==='completed'?'x':'alert')),document.createTextNode(ev.status==='completed'?(t('exit')+' '+(ev.exitCode??'-')):ev.status+(ev.exitCode!=null?' · '+ev.exitCode:'')));exitB.title=nf(ev.durationMs)+' ms';};
 async function run(confirmed){
  const c=cmd.value.trim();if(!c||termBusy)return;LS.set('termTimeout',to.value);
  cmd.value='';if(!confirmed){state.termHistory=[c,...state.termHistory.filter(x=>x!==c)].slice(0,100);LS.set('termHist',JSON.stringify(state.termHistory));hi=-1;}
  line((out.childNodes.length?'\n':'')+'$ '+c+'\n','cmd');stat.textContent=t('running');spin.classList.remove('hidden');exitB.classList.add('hidden');runBtn.disabled=true;stopBtn.disabled=false;
  const srv=state.current;let execId=null;
  try{
   const r=await api('/servers/'+srv+'/exec',{method:'POST',body:{command:c,timeout_seconds:Number(to.value)||60,confirmed:!!confirmed},stream:true});
   if(r.status===409){const j=await r.json();line('[confirmation required] '+j.reason+'\n','err');
    const m=modal(t('destructive'),h('div.dangerbox',null,h('div.box-h',null,icon('alert'),h('span',null,t('destructive'))),ltr(c,'div',{class:'mono'}),h('div.bidi',{dir:'auto'},j.reason)),[btn('danger','play',t('runAnyway'),{'data-action':'run-anyway',onclick:()=>{m.remove();cmd.value=c;run(true);}}),btn('','',t('cancel'),{'data-action':'cancel',onclick:()=>m.remove()})],{narrow:true,noFocus:true});return;}
   if(!r.ok){const j=await r.json().catch(()=>({}));line('['+(j.status||r.status)+'] '+(j.reason||j.error||'error')+'\n','err');return;}
   execId=r.headers.get('x-exec-id');termBusy={srv,execId};
   const reader=r.body.getReader();const dec=new TextDecoder();let buf='';
   for(;;){const {value,done}=await reader.read();if(done)break;buf+=dec.decode(value,{stream:true});let i;
    while((i=buf.indexOf('\n'))>=0){const ln=buf.slice(0,i);buf=buf.slice(i+1);if(!ln)continue;let ev;try{ev=JSON.parse(ln);}catch{continue;}
     if(ev.type==='stdout')line(ev.data);else if(ev.type==='stderr')line(ev.data,'err');else if(ev.type==='truncated')line('\n[output truncated at '+ev.limit+' bytes]\n','meta');
     else if(ev.type==='error')line('[error] '+ev.error+'\n','err');else if(ev.type==='exit'){line('['+ev.status+' · exit '+(ev.exitCode??'-')+(ev.signal?' · '+ev.signal:'')+' · '+ev.durationMs+'ms]\n','meta');setExit(ev);}}}
  }catch(e){if(e.message!=='auth')line('[error] '+e.message+'\n','err');}
  finally{termBusy=null;stat.textContent='';spin.classList.add('hidden');runBtn.disabled=false;stopBtn.disabled=true;if(isDesktop())cmd.focus();}
 }
 runBtn.onclick=()=>run(false);
 stopBtn.onclick=async()=>{if(!termBusy)return;try{await api('/servers/'+termBusy.srv+'/exec/'+termBusy.execId+'/cancel',{method:'POST'});}catch(e){toast(e.message,true);}};
 cmd.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();run(false);}else if(e.key==='ArrowUp'){hi=Math.min(hi+1,state.termHistory.length-1);if(hi>=0)cmd.value=state.termHistory[hi];e.preventDefault();}else if(e.key==='ArrowDown'){hi=Math.max(hi-1,-1);cmd.value=hi>=0?state.termHistory[hi]:'';e.preventDefault();}});
 const histBtn=btn('small','history',t('history'),{'data-action':'history',onclick:()=>{const items=state.termHistory.slice(0,40);if(!items.length){toast(t('noHistory'));return;}
  const list=h('div.sheet-list');const m=modal(t('history'),list,null,{narrow:true,noFocus:true});for(const c of items)list.append(h('button.sheet-item',{type:'button',onclick:()=>{m.remove();cmd.value=c;cmd.focus();}},icon('term',null,18),ltr(c,'span',{class:'mono trunc'})));}});
 const chips=h('div.chips',{role:'toolbar','aria-label':t('quick')});for(const q of QUICK)chips.append(h('button.chip',{type:'button',dir:'ltr',onclick:()=>{cmd.value=q;cmd.focus();}},q));
 root.append(h('div.termbox',null,
  h('div.term-tools',null,serverPicker(()=>line('\n— '+state.servers.find(s=>s.id===state.current).name+' —\n','meta')),h('div.to',null,h('label',{for:'term-to'},t('timeout')),to),histBtn,btn('small.ghost','trash',t('clear'),{'data-action':'clear',onclick:()=>{out.replaceChildren();exitB.classList.add('hidden');}})),
  chips,out,h('div.term-status',null,spin,stat,exitB),
  h('div.cmdbar',null,h('label.cmdin',null,h('span.ps',{'aria-hidden':'true'},'$'),cmd),runBtn,stopBtn)));
 root.classList.add('termroot');root.__after=()=>{if(isDesktop())cmd.focus();};
}

// ---------------------------------------------------------------- files
async function viewFiles(root){
 await loadServers();if(!state.servers.length){root.append(noServersState());return;}
 const crumbs=h('nav.crumbs',{dir:'ltr','aria-label':'path','data-role':'crumb'});const list=h('div.flist'+(state.fview==='grid'?'.gridmode':''),{role:'list'});const info=h('span.muted');const editor=h('div');let page=0;const PAGE=200;
 const prog=h('div.card.hidden',null,h('div.row.between',null,h('span.bidi',{dir:'auto'}),h('span.muted')),h('div.progress.mt',null,h('i')));
 const cwd=()=>state.cwd[state.current]||'.';const join=(a,b)=>(a.endsWith('/')?a:a+'/')+b;
 function renderCrumbs(p){crumbs.replaceChildren();if(!p.startsWith('/')){crumbs.append(h('button',{type:'button'},p));return;}
  const parts=p.split('/').filter(Boolean);crumbs.append(h('button',{type:'button','aria-label':'/',onclick:()=>load('/')},'/'));let acc='';
  parts.forEach((seg,i)=>{acc+='/'+seg;const target=acc;if(i>0)crumbs.append(h('span.sep',{'aria-hidden':'true'},'/'));crumbs.append(h('button',{type:'button',onclick:()=>load(target)},seg));});
  requestAnimationFrame(()=>{crumbs.scrollLeft=crumbs.scrollWidth;});}
 function fileMenu(full,e){sheet(e.name,[e.type==='directory'?{label:t('open'),icon:'folder',run:()=>load(full)}:{label:t('open'),icon:'edit',action:'open',run:()=>openFile(full,e)},
  e.type==='file'?{label:t('download'),icon:'download',action:'download',run:()=>{location.href='/api/servers/'+state.current+'/files/download?path='+encodeURIComponent(full);}}:null,
  {label:t('rename'),icon:'edit',action:'rename',run:()=>renameFile(full)},{label:t('del'),icon:'trash',action:'delete',danger:true,run:()=>delFile(full,e.type==='directory')}]);}
 async function renameFile(full){const n=await askText(t('rename'),full,{ltr:true,label:t('newName')});if(n&&n!==full)api('/servers/'+state.current+'/files/rename',{method:'POST',body:{from:full,to:n}}).then(()=>load(cwd()),x=>toast(x.message,true));}
 async function load(path,offset){try{const r=await api('/servers/'+state.current+'/files?path='+encodeURIComponent(path)+'&offset='+(offset||0)+'&limit='+PAGE);state.cwd[state.current]=r.path;page=(offset||0)/PAGE;renderCrumbs(r.path);list.replaceChildren();
  if(!r.entries.length)list.append(empty('folder',t('emptyDir'),t('emptyDirSub')));
  for(const e of r.entries){const full=join(r.path,e.name);const isDir=e.type==='directory';
   const openIt=()=>isDir?load(full):openFile(full,e);
   const row=h('div.frow'+(isDir?'.dir':''),{role:'listitem','data-name':e.name},
    h('div.ficon',null,icon(isDir?'folder':'file',null,20)),
    h('div.fmain',null,h('button.fname.clickable',{type:'button',dir:'auto',title:e.name,onclick:openIt},e.name),
     h('div.fmeta',null,isDir?null:ltr(fmtBytes(e.size)),ltr(e.mode,'span',{class:'mono'}),h('span',null,fmtTime(e.mtime*1000)))),
    h('div.facts',null,e.type==='file'?h('a.btn.small',{href:'/api/servers/'+state.current+'/files/download?path='+encodeURIComponent(full),'data-action':'download'},icon('download'),h('span',null,t('download'))):null,
     btn('small','edit',t('rename'),{'data-action':'rename',onclick:()=>renameFile(full)}),btn('small.danger','trash',t('del'),{'data-action':'delete',onclick:()=>delFile(full,isDir)})),
    iconBtn('dots',t('actions'),{class:'iconbtn kebab','data-action':'kebab',onclick:()=>fileMenu(full,e)}));
   let timer=null;row.addEventListener('touchstart',()=>{timer=setTimeout(()=>{timer=null;if(navigator.vibrate)try{navigator.vibrate(15);}catch{}fileMenu(full,e);},550);},{passive:true});
   const cancelLP=()=>{if(timer){clearTimeout(timer);timer=null;}};row.addEventListener('touchend',cancelLP);row.addEventListener('touchmove',cancelLP,{passive:true});
   row.addEventListener('contextmenu',ev=>{ev.preventDefault();cancelLP();fileMenu(full,e);});
   list.append(row);}
  info.textContent=nf(r.total?r.offset+1:0)+'–'+nf(Math.min(r.offset+r.limit,r.total))+' / '+nf(r.total);prev.disabled=r.offset===0;next.disabled=r.offset+r.limit>=r.total;
 }catch(e){toast(e.message,true);}}
 function delFile(path,isDir){const rec=h('input',{type:'checkbox',role:'switch'});const m=modal(t('confirmDelete'),h('div',null,ltr(path,'div',{class:'copyval'}),isDir?h('label.check',null,rec,h('span',null,t('recursive'))):null),[btn('danger','trash',t('del'),{'data-action':'confirm-delete',onclick:async()=>{try{await api('/servers/'+state.current+'/files/delete',{method:'POST',body:{path,recursive:rec.checked,confirmed:true}});m.remove();load(cwd());}catch(e){toast(e.message,true);}}}),btn('','',t('cancel'),{onclick:()=>m.remove()})],{narrow:true,noFocus:true});}
 async function openFile(path,e){editor.replaceChildren();
  const meta=h('div.fmeta.muted',null,ltr(fmtBytes(e.size)),' · ',ltr(e.mode),' · ',ltr('uid '+e.uid+' gid '+e.gid),' · ',fmtTime(e.mtime*1000));
  const head=h('div.card-h',null,h('h2.grow.trunc',null,icon('file'),ltr(path,'span',{class:'mono trunc'})),iconBtn('x',t('close'),{onclick:()=>editor.replaceChildren()}));
  if(e.size>1024*1024){editor.append(h('div.card',null,head,meta,h('div.warnbox',null,t('textTooBig'))));editor.scrollIntoView({behavior:'smooth',block:'start'});return;}
  try{const r=await api('/servers/'+state.current+'/files/read?path='+encodeURIComponent(path)+'&length=1048576');const bytes=Uint8Array.from(atob(r.dataBase64),c=>c.charCodeAt(0));
   const text=new TextDecoder().decode(bytes);const ta=h('textarea',{rows:18,spellcheck:'false',dir:'ltr',wrap:'off','aria-label':path,autocapitalize:'off',autocorrect:'off'});ta.value=text;
   const gutter=h('div.gutter',{'aria-hidden':'true'});let lastN=0;const lc=h('span.muted');
   const syncG=()=>{const n=ta.value.split('\n').length;if(n!==lastN){lastN=n;let s='';for(let i=1;i<=n;i++)s+=i+'\n';gutter.textContent=s;lc.textContent=nf(n)+' '+t('lines');}gutter.scrollTop=ta.scrollTop;};
   ta.addEventListener('input',syncG);ta.addEventListener('scroll',()=>{gutter.scrollTop=ta.scrollTop;});syncG();
   const save=async()=>{try{const x=await api('/servers/'+state.current+'/files/write',{method:'POST',body:{path,content:ta.value}});toast('✓ '+fmtBytes(x.bytes));load(cwd());}catch(er){toast(er.message,true);}};
   ta.addEventListener('keydown',ev=>{if((ev.ctrlKey||ev.metaKey)&&ev.key==='s'){ev.preventDefault();save();}else if(ev.key==='Tab'&&!ev.shiftKey){ev.preventDefault();const a=ta.selectionStart,b=ta.selectionEnd;ta.setRangeText('\t',a,b,'end');syncG();}});
   editor.append(h('div.card',{'data-role':'editor'},head,meta,h('div.editor.mt',{dir:'ltr'},gutter,ta),h('div.row.between.mt',null,lc,h('div.row',null,btn('','',t('cancel'),{onclick:()=>editor.replaceChildren()}),btn('primary','save',t('saveFile'),{'data-action':'save-file',onclick:save})))));
   editor.scrollIntoView({behavior:'smooth',block:'start'});
  }catch(er){toast(er.message,true);}}
 const upInput=h('input.hidden',{type:'file',onchange:async()=>{const file=upInput.files[0];if(!file)return;const dest=join(cwd(),file.name);const CH=4*1024*1024;
  const [nameEl,pctEl]=prog.firstChild.children;const bar=prog.querySelector('i');prog.classList.remove('hidden');nameEl.textContent=t('uploading')+': '+file.name;
  const setP=(done)=>{const p=Math.min(100,Math.round(done/Math.max(file.size,1)*100));bar.style.width=p+'%';pctEl.textContent=nf(p)+'%';info.textContent=t('upload')+' '+p+'%';};setP(0);
  try{for(let off=0;off<file.size||off===0;off+=CH){const chunk=await file.slice(off,off+CH).arrayBuffer();const base=off;
    await xhrUpload('/servers/'+state.current+'/files/upload?path='+encodeURIComponent(dest)+'&offset='+off,chunk,(l)=>setP(base+l));setP(Math.min(file.size,off+CH));if(file.size===0)break;}
   setP(file.size||1);toast('✓ '+file.name);load(cwd());}catch(e){if(e.message!=='auth')toast(e.message,true);}upInput.value='';setTimeout(()=>prog.classList.add('hidden'),900);}});
 const prev=iconBtn(lang==='fa'?'chevR':'chevL','previous',{onclick:()=>load(cwd(),(page-1)*PAGE)});const next=iconBtn(lang==='fa'?'chevL':'chevR','next',{onclick:()=>load(cwd(),(page+1)*PAGE)});
 const vt=seg([['list',t('listView'),'list'],['grid',t('gridView'),'grid']],state.fview,'view');vt.addEventListener('segchange',()=>{state.fview=vt.value;LS.set('fview',vt.value);list.classList.toggle('gridmode',vt.value==='grid');});
 root.append(h('div.card',null,h('div.ftools',null,serverPicker(()=>{editor.replaceChildren();load(cwd());}),
   btn('','arrowUp',t('up'),{'data-action':'up','aria-label':t('up'),onclick:()=>load(cwd()+'/..')}),btn('','refresh',t('refresh'),{'data-action':'refresh','aria-label':t('refresh'),onclick:()=>load(cwd())}),
   btn('','plus',t('newFolder'),{'data-action':'mkdir','aria-label':t('newFolder'),onclick:async()=>{const n=await askText(t('newFolder'),'',{ltr:true,label:t('folderName')});if(n)api('/servers/'+state.current+'/files/mkdir',{method:'POST',body:{path:join(cwd(),n)}}).then(()=>load(cwd()),x=>toast(x.message,true));}}),
   btn('primary','upload',t('upload'),{'data-action':'upload','aria-label':t('upload'),onclick:()=>upInput.click()}),upInput),
  h('div.row.mt',null,h('div.grow',null,crumbs),vt.el),prog,h('div.mt',null,list),h('div.pager',null,info,prev,next)),editor);
 load(cwd());
}

// ---------------------------------------------------------------- approvals
async function viewApprovals(root){
 const [rows]=await Promise.all([api('/confirmations?status=pending'),loadServers()]);refreshBadge();
 // quick auto-approve switches
 if(state.servers.length){const list=h('div.aa-list');
  for(const s of state.servers){const hintEl=h('div',null,aaHint(s.auto_approve));
   const ctl=aaControl(s.auto_approve,(v,prev)=>quickAuto(s,v,prev).then(okk=>{if(okk)hintEl.replaceChildren(aaHint(v));return okk;}),{compact:true});
   list.append(h('div.aa-item',{'data-server':s.name},h('div',null,h('div.t1',null,auto(s.name,'strong'),' ',ltr(s.username+'@'+s.host,'span',{class:'muted'})),hintEl),ctl.el));}
  root.append(h('div.card',{'data-role':'aa-card'},h('div.card-h',null,h('h2',null,icon('bolt'),t('aaQuickTitle'))),h('p.hint',null,t('aaQuickSub')),list,h('p.hint',null,t('aaRoNote'))));}
 if(!rows.length){root.append(h('div.card',{'data-role':'no-pending'},empty('inbox',t('noPending'),t('noPendingSub'))));return;}
 const approveAll=async(serverId,subset)=>{const items=h('div.stack');for(const r of subset.slice(0,8)){let op={};try{op=JSON.parse(r.operation);}catch{}items.append(ltr(op.type==='exec'?op.command:(op.type==='delete'?'delete '+(op.recursive?'-r ':'')+op.path:r.tool),'div',{class:'mono trunc'}));}
  if(subset.length>8)items.append(h('div.muted',null,'+'+nf(subset.length-8)));
  const m=modal(t('approveAllQ'),h('div',null,h('p',null,t('approveAllText')+' '+nf(subset.length)),h('div.dangerbox',null,items)),[btn('danger','check',t('approveAll')+' ('+nf(subset.length)+')',{'data-action':'approve-all-confirm',onclick:async()=>{try{const x=await api('/confirmations/approve-all',{method:'POST',body:serverId?{server_id:serverId}:{}});m.remove();toast('✓ '+t('approveAll')+': '+nf(x.approved));rerender('approvals');refreshBadge();}catch(e){toast(e.message,true);}}}),btn('','',t('cancel'),{onclick:()=>m.remove()})],{narrow:true,noFocus:true});};
 root.append(h('div.card.approve-bar',{'data-role':'approve-bar'},h('span',null,h('strong',null,nf(rows.length)),' ',t('pendingConf')),btn('danger.big-tap','check',t('approveAll'),{'data-action':'approve-all',onclick:()=>approveAll(null,rows)})));
 const groups=new Map();for(const r of rows){if(!groups.has(r.server_id))groups.set(r.server_id,[]);groups.get(r.server_id).push(r);}
 for(const [sid,list] of groups){
  const sname=list[0].server_name||sid;
  root.append(h('div.grp-h',{'data-group':sname},h('h3',null,icon('server'),auto(sname)),h('span.pill.o-warn',null,nf(list.length)),h('span.grow'),list.length>1?btn('small','check',t('approveAllServer'),{'data-action':'approve-all-server',onclick:()=>approveAll(sid,list)}):null));
  for(const r of list){let op={};try{op=JSON.parse(r.operation);}catch{}
   const tokenBox=h('div');
   const card=h('div.card',{'data-confirmation':r.id},h('div.card-h',null,h('h2',null,icon('shield'),ltr(r.tool)),h('span.grow'),h('span.pill.o-warn',null,icon('clock'),relTime(r.expires_at))),
    h('div.dangerbox',null,ltr(op.type==='exec'?op.command:(op.type==='delete'?'delete '+(op.recursive?'-r ':'')+op.path:r.operation),'div',{class:'mono'}),h('div.kv',null,h('span.k',null,t('reason')+':'),auto(r.reason))),
    h('div.kv.muted',null,h('span.k',null,t('requestedBy')+':'),ltr(r.requested_by),' · ',ltr('id '+r.id,'span',{class:'mono'})),
    h('div.actions.mt',null,btn('danger.big-tap','check',t('approve'),{'data-action':'approve',onclick:async(ev)=>{const b=ev.currentTarget;b.disabled=true;try{await api('/confirmations/'+r.id+'/approve',{method:'POST'});
       card.replaceChildren(h('div.row',null,icon('checkc'),h('strong',null,t('approvedNote')),ltr(op.type==='exec'?op.command:(op.path||''),'span',{class:'mono muted trunc'})));card.setAttribute('data-approved','true');refreshBadge();setTimeout(()=>{card.remove();},2500);}catch(e){b.disabled=false;toast(e.message,true);}}}),
     btn('','x',t('reject'),{'data-action':'reject',onclick:async()=>{try{await api('/confirmations/'+r.id+'/reject',{method:'POST'});card.remove();refreshBadge();}catch(e){toast(e.message,true);}}}),
     btn('','key',t('showToken'),{'data-action':'token',onclick:async()=>{try{const x=await api('/confirmations/'+r.id+'/token',{method:'POST'});tokenBox.replaceChildren(h('div.warnbox',null,copyRow(x.token,{name:'confirm-token'})));}catch(e){toast(e.message,true);}}})),tokenBox);
   root.append(card);}
 }
}

// ---------------------------------------------------------------- MCP
const STEPS = {
 en:[['In Claude (web or desktop) open ',['Settings → Connectors'],' and press ',['Add custom connector'],'.'],
  ['Name it, for example ',['my-ssh'],'.'],
  ['Paste this into ',['Remote MCP server URL'],':','URL'],
  ['Open ',['Advanced settings'],' and set Authentication to ',['No sign-in'],'.'],
  ['Request header name:','HNAME'],
  ['Header value — the word Bearer, a space, then your token:','HVAL'],
  ['Press ',['Add'],', then enable the connector\u2019s tools from the chat\u2019s tools menu.']],
 fa:[['در Claude (نسخهٔ وب یا دسکتاپ) به ',['Settings → Connectors'],' بروید و روی ',['Add custom connector'],' بزنید.'],
  ['یک نام بنویسید؛ مثلاً ',['my-ssh'],'.'],
  ['این نشانی را در کادر ',['Remote MCP server URL'],' بگذارید:','URL'],
  ['بخش ',['Advanced settings'],' را باز کنید و Authentication را روی ',['No sign-in'],' (بدون ورود) بگذارید.'],
  ['در کادر ',['Request header name'],' این مقدار را بنویسید:','HNAME'],
  ['مقدار هدر — کلمهٔ Bearer، یک فاصله و سپس توکن شما:','HVAL'],
  ['روی ',['Add'],' بزنید و سپس ابزارهای این کانکتور را از منوی ابزارهای گفتگو فعال کنید.']]
};
const OAUTH_STEPS={
 en:[['In your AI app add a new MCP server / connector (in Gemini: ',['Settings → Extensions / MCP servers → Add'],').'],
  ['Paste only this address, with no header or token:','URL'],
  ['If the app asks for an auth type, choose ',['OAuth'],'. Client ID / secret can be left empty — the app registers itself automatically.'],
  ['An ',['Authorize MCP access'],' page opens: enter your dashboard admin password and press ',['Approve'],'.'],
  ['Done. The app shows up in the tokens list above as ',['OAuth · <app name>'],'; press revoke there to cut its access at any time.']],
 fa:[['در اپ هوش مصنوعی یک سرور MCP / کانکتور جدید اضافه کنید (در Gemini: ',['Settings → Extensions / MCP servers → Add'],').'],
  ['فقط همین نشانی را بگذارید، بدون هدر و توکن:','URL'],
  ['اگر نوع احراز هویت پرسید، ',['OAuth'],' را انتخاب کنید. Client ID و Secret را خالی بگذارید؛ اپ خودش ثبت‌نام می‌کند.'],
  ['صفحهٔ ',['Authorize MCP access'],' باز می‌شود: رمز مدیر پنل را وارد کنید و ',['Approve'],' را بزنید.'],
  ['تمام. اپ در فهرست توکن‌های بالا با نام ',['OAuth · <نام اپ>'],' دیده می‌شود و هر وقت خواستید با دکمهٔ لغو دسترسی‌اش را قطع کنید.']]
};
async function viewMcp(root){
 const url=location.origin+'/mcp';let curTok='';
 root.append(h('div.card',{'data-role':'mcp-url'},h('div.card-h',null,h('h2',null,icon('link'),t('mcpUrl'))),copyRow(url,{big:true,name:'url'})));
 const tb=h('tbody');const tokEmpty=h('p.muted.hidden',null,t('noTokens'));const newBox=h('div');const name=h('input',{placeholder:'claude-desktop',dir:'auto','aria-label':t('tokenName'),'data-role':'token-name'});
 const hval=()=>'Bearer '+(curTok||'sshmcp_…');
 const hvalRow=copyRow(hval(),{name:'header-value',get:()=>hval()});const hvalText=hvalRow.querySelector('.copyval');
 const pres={};const mkCfg=()=>{const tk=curTok||'<your token>';
  pres.desktop.textContent=JSON.stringify({mcpServers:{'my-ssh':{command:'npx',args:['-y','mcp-remote',url,'--header','Authorization:Bearer $'+'{MCP_TOKEN}'],env:{MCP_TOKEN:tk}}}},null,2);
  pres.cursor.textContent=JSON.stringify({mcpServers:{'my-ssh':{url,headers:{Authorization:'Bearer '+tk}}}},null,2);
  pres.code.textContent='claude mcp add --transport http my-ssh '+url+' --header "Authorization: Bearer '+tk+'"';hvalText.textContent=hval();};
 for(const k of ['desktop','cursor','code'])pres[k]=h('pre.code',{dir:'ltr','data-cfg':k,tabindex:'0'});
 async function load(){const rows=await api('/mcp/tokens');tb.replaceChildren();tokEmpty.classList.toggle('hidden',rows.length>0);for(const r of rows)tb.append(h('tr',null,td(t('name'),auto(r.name)),td(t('prefix'),ltr(r.prefix+'…','span',{class:'mono'})),td(t('created'),fmtTime(r.created_at)),td(t('lastUsed'),fmtTime(r.last_used_at)),
  td('',r.revoked_at?h('span.pill.o-bad',null,t('revoked')):btn('small.danger','x',t('revoke'),{'data-action':'revoke',onclick:async()=>{try{await api('/mcp/tokens/'+r.id,{method:'DELETE'});load();}catch(e){toast(e.message,true);}}}))));}
 const create=async()=>{try{const r=await api('/mcp/tokens',{method:'POST',body:{name:name.value||'token'}});name.value='';curTok=r.token;
   newBox.replaceChildren(h('div.warnbox.tokenbox',{'data-role':'new-token'},h('div.box-h',null,icon('alert'),h('span',null,t('tokenOnce'))),copyRow(r.token,{big:true,name:'token'})));mkCfg();load();}catch(e){toast(e.message,true);}};
 name.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();create();}});
 root.append(h('div.card',null,h('div.card-h',null,h('h2',null,icon('key'),t('tokens'))),h('div.row',null,name,btn('primary','plus',t('newToken'),{'data-action':'create-token',onclick:create})),newBox,
  h('div.mt',null,table([t('name'),t('prefix'),t('created'),t('lastUsed'),''],tb)),tokEmpty));
 // OAuth (no token): Gemini, ChatGPT, Claude.ai
 const ool=h('ol.steps');for(const st of OAUTH_STEPS[lang]||OAUTH_STEPS.en){const li=h('li');for(const part of st){
   if(part==='URL')li.append(copyRow(url,{name:'oauth-url'}));else if(Array.isArray(part))li.append(ltr(part[0],'code'));else li.append(part);}ool.append(li);}
 root.append(h('div.card',{'data-role':'oauth-steps'},h('div.card-h',null,h('h2',null,icon('lock'),t('oauthTitle'))),ool));
 // Claude custom connector, step by step
 const ol=h('ol.steps');for(const st of STEPS[lang]||STEPS.en){const li=h('li');for(const part of st){
   if(part==='URL')li.append(copyRow(url,{name:'step-url'}));else if(part==='HNAME')li.append(copyRow('Authorization',{name:'header-name'}));else if(part==='HVAL')li.append(hvalRow,h('p.hint',null,t('tokenHint')));
   else if(Array.isArray(part))li.append(ltr(part[0],'code'));else li.append(part);}ol.append(li);}
 root.append(h('div.card',{'data-role':'claude-steps'},h('div.card-h',null,h('h2',null,icon('claude'),t('claudeTitle'))),ol));
 const tabsEl=h('div.tabs',{role:'tablist'});const panes=h('div');const tabDefs=[['desktop',t('cfgDesktop')],['cursor',t('cfgCursor')],['code',t('cfgCode')]];
 const sel=(k)=>{for(const b of tabsEl.children)b.setAttribute('aria-selected',String(b.dataset.k===k));for(const [kk] of tabDefs)pres[kk].parentNode.classList.toggle('hidden',kk!==k);};
 for(const [k,lbl] of tabDefs){tabsEl.append(h('button',{type:'button',role:'tab','data-k':k,'aria-selected':'false',onclick:()=>sel(k)},lbl));panes.append(h('div.stack',null,pres[k],h('div',null,btn('small','copy',t('copy'),{onclick:()=>copy(pres[k].textContent)}))));}
 root.append(h('div.card',null,h('div.card-h',null,h('h2',null,icon('code'),t('clientCfg'))),tabsEl,panes));mkCfg();sel('desktop');
 await load();
}

// ---------------------------------------------------------------- settings
async function viewSettings(root){
 const s=await api('/settings');const f={};
 const num=(k,lbl)=>h('div',null,h('label',{for:'set-'+k},t(lbl)),f[k]=h('input',{type:'number',value:s[k],id:'set-'+k,dir:'ltr',inputmode:'numeric'}));
 f.allow_private_targets=h('input',{type:'checkbox',checked:s.allow_private_targets,role:'switch'});
 const err=h('div.error',{role:'alert'});
 const aaDefHint=h('div',null,aaHint(s.default_auto_approve||'off'));
 const aaDef=aaControl(s.default_auto_approve||'off',async(v,prev)=>{let confirm_text;if(v==='all'&&prev!=='all'){confirm_text=await askAllConfirm(t('defaultAuto'));if(!confirm_text)return false;}
  try{await api('/settings',{method:'PATCH',body:confirm_text?{default_auto_approve:v,default_auto_approve_confirm:confirm_text}:{default_auto_approve:v}});aaDefHint.replaceChildren(aaHint(v));toast(t('aaUpdated'));return true;}catch(e){toast(e.message,true);return false;}});
 root.append(h('div.card',null,h('div.card-h',null,h('h2',null,icon('gear'),t('settings'))),h('div.form',null,num('idle_timeout_seconds','idle'),num('default_command_timeout_seconds','cmdTimeout'),num('max_output_bytes','maxOut'),num('confirmation_ttl_seconds','confTtl'),num('session_ttl_hours','sessTtl'),
  h('div.full',{'data-role':'aa-default'},h('label',null,icon('bolt'),' ',t('defaultAuto')),aaDef.el,aaDefHint,h('p.hint',null,t('aaRoNote'))),
  h('label.check.full',null,f.allow_private_targets,h('span',null,t('allowPrivate'))),h('p.hint.full',null,t('authMode')+': ',ltr(s.auth_mode),s.dev_allow_private_targets?ltr(' · DEV_ALLOW_PRIVATE_TARGETS=true'):null),h('div.full',null,err)),
  h('div.mt',null,btn('primary','save',t('save'),{'data-action':'save-settings',onclick:async()=>{const p={allow_private_targets:f.allow_private_targets.checked};for(const k of ['idle_timeout_seconds','default_command_timeout_seconds','max_output_bytes','confirmation_ttl_seconds','session_ttl_hours'])p[k]=Number(f[k].value);
   try{await api('/settings',{method:'PATCH',body:p});toast('✓ '+t('saved'));err.textContent='';}catch(e){err.textContent=e.message;}}}))));
 if(s.admin_password_source==='secret'){root.append(h('div.card',{'data-role':'pw-secret'},h('div.card-h',null,h('h2',null,icon('lock'),t('changePwd'))),h('p.hint',null,t('pwBySecret'))));return;}
 const cur=h('input',{type:'password',autocomplete:'current-password',dir:'ltr',id:'pw-cur'}),nw=h('input',{type:'password',autocomplete:'new-password',dir:'ltr',id:'pw-new'}),perr=h('div.error',{role:'alert'});
 root.append(h('div.card',null,h('div.card-h',null,h('h2',null,icon('lock'),t('changePwd'))),h('div.form',null,h('div',null,h('label',{for:'pw-cur'},t('currentPwd')),cur),h('div',null,h('label',{for:'pw-new'},t('newPwd')),nw)),perr,
  h('div.mt',null,btn('','save',t('save'),{'data-action':'change-password',onclick:async()=>{try{await api('/auth/change-password',{method:'POST',body:{current_password:cur.value,new_password:nw.value}});cur.value='';nw.value='';toast('✓ '+t('saved'));perr.textContent='';}catch(e){perr.textContent=e.message;}}}))));
}

// ---------------------------------------------------------------- audit
async function viewAudit(root){
 const tb=h('tbody');let before=0;const more=btn('','refresh',t('more'),{'data-action':'more',onclick:()=>load()});
 async function load(){const rows=await api('/audit?limit=100'+(before?'&before='+before:''));for(const a of rows){tb.append(h('tr',null,td(t('time'),fmtTime(a.ts)),td(t('actor'),ltr(a.actor||'')),td(t('action'),ltr(a.action,'span',{class:'mono'}),a.auto_approved?[' ',autoBadge(a.auto_level)]:null),
  td(t('outcome'),h('span.pill.soft.'+(outcomeClass(a.outcome)||'x'),null,ltr(a.outcome||'—'))),td(t('detail'),a.detail?ltr(String(a.detail).slice(0,300),'span',{class:'mono'}):''),td('IP',a.ip?ltr(a.ip,'span',{class:'mono'}):'')));before=a.id;}if(rows.length<100)more.disabled=true;}
 root.append(h('div.card',null,table([t('time'),t('actor'),t('action'),t('outcome'),t('detail'),'IP'],tb),h('div.mt',null,more)));
 await load();
}

// hide the bottom tab bar while the on-screen keyboard is likely open (phones)
document.addEventListener('focusin',e=>{const el=e.target;if(!isDesktop()&&el&&el.matches&&el.matches('input:not([type=checkbox]):not([type=file]),textarea'))document.body.classList.add('typing');});
document.addEventListener('focusout',()=>{setTimeout(()=>{const a=document.activeElement;if(!(a&&a.matches&&a.matches('input,textarea')))document.body.classList.remove('typing');},50);});
window.addEventListener('hashchange',()=>{const v=location.hash.slice(1);if(mainEl&&v&&v!==state.view)go(v);});
boot().catch(e=>{app.textContent=e.message;});
})();
`;
