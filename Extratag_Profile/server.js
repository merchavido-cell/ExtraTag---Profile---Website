'use strict';
if (process.platform === 'win32') module.paths.push('D:\\node_modules');

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');

function loadEnvFile(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return; }
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !line.trim().startsWith('#') && !(m[1] in process.env)) process.env[m[1]] = m[2];
  }
}
loadEnvFile(path.join(__dirname, '.env'));
loadEnvFile(path.join(__dirname, 'Secret', 'Passecret.env'));
loadEnvFile(path.join(__dirname, 'Secret', 'mailSecret.env'));
// Render "Secret Files" are mounted under /etc/secrets/
loadEnvFile('/etc/secrets/.env');
loadEnvFile('/etc/secrets/Passecret.env');
loadEnvFile('/etc/secrets/mailSecret.env');

const DEV = process.env.EXTRATAG_DEV === '1';
const PORT = +process.env.PORT || 5000;
const ON_RENDER = !!process.env.RENDER;
const HOST = process.env.HOST || (ON_RENDER ? '0.0.0.0' : '127.0.0.1');
const PROXIES = process.env.TRUSTED_PROXIES !== undefined ? +process.env.TRUSTED_PROXIES || 0 : (ON_RENDER ? 1 : 0);
const MAIL_DOMAIN = process.env.MAIL_DOMAIN || 'extra-tag.com';
const COOKIE = DEV ? 'sid' : '__Host-sid';
const SESSION_ABSOLUTE = 7 * 86400, IDLE_USER = 30 * 60, IDLE_ANON = 2 * 3600;
const VERIFY_TTL = 24 * 3600, MAX_FAILED = 5, LOCK_SECONDS = 15 * 60;

// ===== IN-MEMORY STORAGE (NO DATABASE) =====
const pendingUsers = new Map();
const users = new Map();
const sessions = new Map();
const rateLimits = new Map();

const now = () => Math.floor(Date.now() / 1000);
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

function limited(key, limit, window) {
  const t = now();
  const timestamps = rateLimits.get(key) || [];
  const recent = timestamps.filter(ts => ts > t - window);
  recent.push(t);
  rateLimits.set(key, recent);
  return recent.length > limit;
}

setInterval(() => {
  const t = now();
  for (const [email, u] of pendingUsers.entries()) {
    if (u.expires < t) pendingUsers.delete(email);
  }
  for (const [h, s] of sessions.entries()) {
    if (t - s.created >= SESSION_ABSOLUTE || t - s.lastSeen >= (s.userId ? IDLE_USER : IDLE_ANON)) {
      sessions.delete(h);
    }
  }
}, 3600 * 1000).unref();

// ===== PASSWORD HASHING =====
const scrypt = promisify(crypto.scrypt);
const SP = { N: 65536, r: 8, p: 1 };
const MAXMEM = 256 * 1024 * 1024;
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 32, { ...SP, maxmem: MAXMEM });
  return `scrypt$${SP.N}$${SP.r}$${SP.p}$${salt.toString('base64')}$${h.toString('base64')}`;
}
async function verifyPw(stored, pw) {
  const [t, N, r, p, s, h] = String(stored).split('$');
  if (t !== 'scrypt' || !h) return false;
  const want = Buffer.from(h, 'base64');
  const got = await scrypt(pw, Buffer.from(s, 'base64'), want.length, { N: +N, r: +r, p: +p, maxmem: MAXMEM });
  return crypto.timingSafeEqual(got, want);
}
const normPw = (p) => p.normalize('NFKC');
let DUMMY_HASH;

// ===== VALIDATION =====
const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,29}$/;
const NAME_RE = /^\p{L}(?:[\p{L} '.\-]){0,39}$/u;
const EMAIL_RE = /^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$/;
const RESERVED = new Set(['admin', 'root', 'postmaster', 'abuse', 'support', 'info', 'security', 'noreply', 'no-reply', 'webmaster', 'hostmaster', 'mail', 'extratag', 'staff', 'help', 'billing', 'calc']);
const LANGS = new Set(['en', 'he', 'ar', 'ru', 'es', 'fr', 'de']);
const SHAPES = new Set(['circle', 'square', 'pentagon', 'hexagon', 'heptagon', 'octagon']);
const COLOR_RE = /^#[0-9a-fA-F]{6}$/;

const str = (d, k, n = 256) => (typeof d[k] === 'string' ? d[k].trim().slice(0, n) : '');
const publicUser = (u) => ({ id: u.id, firstName: u.firstName, lastName: u.lastName, email: u.email, username: u.username, exmail: u.exmail, language: u.language || 'en', avatarColor: u.avatarColor || '#38bdf8', avatarShape: u.avatarShape || 'circle' });

// ===== GITHUB SYNC =====
const GITHUB_API_URL = 'https://api.github.com/repos/merchavido-cell/ExtraTag---Data/contents/global_history.json';
const GITHUB_HEADERS = { Accept: 'application/vnd.github.v3+json', 'User-Agent': 'ExtraTag-Signup' };
if (process.env.GITHUB_TOKEN) {
  GITHUB_HEADERS.Authorization = `token ${String(process.env.GITHUB_TOKEN).trim()}`;
  console.log('GitHub sync: enabled');
} else {
  console.log('GitHub sync: disabled (GITHUB_TOKEN not set)');
}

function cleanForGithub(data) {
  if (Array.isArray(data)) {
    return data.map((item) => {
      if (!item || typeof item !== 'object') return item;
      const copy = { ...item };
      delete copy.is_logged_in;
      delete copy.is_selected;
      return copy;
    });
  }
  return data;
}

async function githubLoadGlobalHistory() {
  const meta = await fetch(GITHUB_API_URL, { headers: GITHUB_HEADERS, signal: AbortSignal.timeout(60000) });
  if (!meta.ok) throw new Error(`GitHub meta ${meta.status}`);
  const info = await meta.json();
  const sha = info.sha;
  const raw = await fetch(info.download_url, { signal: AbortSignal.timeout(60000) });
  if (!raw.ok) throw new Error(`GitHub raw ${raw.status}`);
  const text = (await raw.text()).trim();
  let data = [];
  if (text && text !== '[]') {
    try { data = JSON.parse(text); } catch { data = []; }
  }
  return { data: Array.isArray(data) ? data : [], sha };
}

async function githubSaveGlobalHistory(data, sha) {
  let currentSha = sha;
  if (!currentSha) {
    const meta = await fetch(GITHUB_API_URL, { headers: GITHUB_HEADERS, signal: AbortSignal.timeout(60000) });
    if (!meta.ok) throw new Error(`GitHub meta ${meta.status}`);
    currentSha = (await meta.json()).sha;
  }
  const encoded = Buffer.from(JSON.stringify(cleanForGithub(data), null, 4), 'utf8').toString('base64');
  const payload = { message: 'Sync profile from signup site', content: encoded, sha: currentSha };
  let res = await fetch(GITHUB_API_URL, {
    method: 'PUT',
    headers: { ...GITHUB_HEADERS, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(60000)
  });
  if (res.status === 409) {
    const meta = await fetch(GITHUB_API_URL, { headers: GITHUB_HEADERS, signal: AbortSignal.timeout(60000) });
    payload.sha = (await meta.json()).sha;
    res = await fetch(GITHUB_API_URL, {
      method: 'PUT',
      headers: { ...GITHUB_HEADERS, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(60000)
    });
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`GitHub PUT ${res.status} ${body.slice(0, 200)}`);
  }
  return true;
}

async function pushProfileToGithub(profile) {
  if (!process.env.GITHUB_TOKEN) return false;
  try {
    console.log('🔄 Pushing profile to GitHub...');
    const { data, sha } = await githubLoadGlobalHistory();
    console.log('📥 Loaded history, sha:', sha.slice(0, 8) + '...');
    const clean = { ...profile };
    delete clean.is_logged_in;
    delete clean.is_selected;
    const idx = data.findIndex((p) => p && String(p.id) === String(clean.id));
    if (idx >= 0) {
      const existing = data[idx];
      const mergedFiles = mergeByName(existing.files, clean.files);
      const mergedEvents = mergeById(existing.events, clean.events);
      data[idx] = { ...existing, ...clean, files: mergedFiles, events: mergedEvents };
    } else {
      data.push(clean);
    }
    await githubSaveGlobalHistory(data, sha);
    console.log(`✔ pushed profile ${clean.id} (${clean.email}) to global_history.json`);
    return true;
  } catch (e) {
    console.error('❌ GitHub push failed:', e.message);
    return false;
  }
}

function mergeByName(a, b) {
  const out = {};
  for (const f of Array.isArray(a) ? a : []) if (f && f.file_name) out[f.file_name] = f;
  for (const f of Array.isArray(b) ? b : []) if (f && f.file_name) out[f.file_name] = f;
  return Object.values(out);
}
function mergeById(a, b) {
  const out = {};
  for (const e of Array.isArray(a) ? a : []) if (e && e.id) out[String(e.id)] = e;
  for (const e of Array.isArray(b) ? b : []) if (e && e.id) out[String(e.id)] = e;
  return Object.values(out);
}

// ===== MAIL =====
const OUTBOX = [];
async function sendMail(to, subject, text) {
  if (!process.env.SMTP_HOST) {
    if (DEV) { OUTBOX.push({ to, subject, text }); console.log(`\n[DEV MAIL] to ${to}\n${text}\n`); }
    else console.error('SMTP_HOST not configured; verification email was not sent.');
    return;
  }
  try {
    const nm = require('nodemailer');
    const port = +process.env.SMTP_PORT || 587;
    await nm.createTransport({ host: process.env.SMTP_HOST, port, secure: port === 465, auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' } : undefined })
      .sendMail({ from: process.env.SMTP_FROM || `no-reply@${MAIL_DOMAIN}`, to, subject, text });
  } catch (e) { console.error('Mail error:', e.code === 'MODULE_NOT_FOUND' ? 'run "npm install nodemailer"' : e.message); }
}

// ===== HTTP HELPERS =====
function sendJson(ctx, code, obj) {
  const h = secHeaders({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  if (ctx.cookies.length) h['Set-Cookie'] = ctx.cookies;
  ctx.res.writeHead(code, h);
  ctx.res.end(JSON.stringify(obj));
}
const err = (ctx, msg, code = 400) => sendJson(ctx, code, { ok: false, error: msg });
function secHeaders(h) {
  return { ...h, 'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'", 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()', 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin', ...(DEV ? {} : { 'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload' }) };
}
function clientIp(req) {
  let ip = req.socket.remoteAddress || '0';
  if (PROXIES > 0) {
    const xs = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (xs.length - PROXIES >= 0) ip = xs[xs.length - PROXIES];
  }
  return ip;
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > 16384) { reject(new Error('big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { const d = JSON.parse(Buffer.concat(chunks).toString('utf8')); resolve(d && typeof d === 'object' && !Array.isArray(d) ? d : {}); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

// ===== SESSIONS =====
function setCookie(ctx, raw) { ctx.cookies.push(`${COOKIE}=${raw}; Path=/; HttpOnly; SameSite=Strict${DEV ? '' : '; Secure'}`); }
function newSession(ctx, userId) {
  const raw = rand(32), csrf = crypto.randomBytes(32).toString('hex'), t = now();
  sessions.set(sha(raw), { userId, csrf, created: t, lastSeen: t });
  setCookie(ctx, raw);
  ctx.sess = { hash: sha(raw), csrf, userId };
  ctx.user = userId ? (Array.from(users.values()).find(u => u.id === userId) || null) : null;
  return csrf;
}
function dropSession(ctx) {
  if (ctx.sess) sessions.delete(ctx.sess.hash);
  ctx.sess = null; ctx.user = null;
}
function loadSession(ctx) {
  ctx.sess = null; ctx.user = null;
  const m = String(ctx.req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).find(([k]) => k === COOKIE);
  if (!m || !m[1]) return;
  const h = sha(m[1]), s = sessions.get(h), t = now();
  if (!s) return;
  if (t - s.created >= SESSION_ABSOLUTE || t - s.lastSeen >= (s.userId ? IDLE_USER : IDLE_ANON)) { sessions.delete(h); return; }
  if (t - s.lastSeen > 60) s.lastSeen = t;
  ctx.sess = { hash: h, csrf: s.csrf, userId: s.userId };
  if (s.userId) {
    ctx.user = Array.from(users.values()).find(u => u.id === s.userId) || null;
  }
}
function csrfGuard(ctx) {
  const { req } = ctx;
  const origin = req.headers.origin;
  if (origin) { try { if (new URL(origin).host !== req.headers.host) return err(ctx, 'Bad origin.', 403), true; } catch { return err(ctx, 'Bad origin.', 403), true; } }
  const sent = String(req.headers['x-csrf-token'] || ''), want = ctx.sess ? ctx.sess.csrf : '';
  if (!want || !safeEq(sent, want)) return err(ctx, 'Invalid CSRF token. Reload the page.', 403), true;
  if (!String(req.headers['content-type'] || '').startsWith('application/json')) return err(ctx, 'JSON required.', 415), true;
  return false;
}

// ===== PAGES =====
const TEMPLATE = fs.readFileSync(path.join(__dirname, 'templates', 'index.html'), 'utf8');
const STATIC = path.join(__dirname, 'static');
const MIME = { '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png' };

function page(ctx) {
  const csrf = ctx.sess ? ctx.sess.csrf : newSession(ctx, null);
  const h = secHeaders({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  if (ctx.cookies.length) h['Set-Cookie'] = ctx.cookies;
  ctx.res.writeHead(200, h);
  ctx.res.end(TEMPLATE.replace('{{ csrf }}', csrf));
}
function serveStatic(ctx) {
  let rel;
  try { rel = decodeURIComponent(ctx.url.pathname.slice('/static/'.length)); } catch { return err(ctx, 'Not found.', 404); }
  const file = path.resolve(STATIC, rel);
  if (rel.includes('\0') || !file.startsWith(STATIC + path.sep) || !MIME[path.extname(file)]) return err(ctx, 'Not found.', 404);
  fs.readFile(file, (e, buf) => {
    if (e) return err(ctx, 'Not found.', 404);
    ctx.res.writeHead(200, secHeaders({ 'Content-Type': MIME[path.extname(file)], 'Cache-Control': 'public, max-age=300' }));
    ctx.res.end(buf);
  });
}

// ===== API =====
const API = {};

API['/api/signup'] = async (ctx, d) => {
  if (limited('signup:' + ctx.ip, 10, 3600)) return err(ctx, 'Too many attempts. Try again later.', 429);
  const first = str(d, 'firstName', 40), last = str(d, 'lastName', 40);
  const email = str(d, 'email', 320).toLowerCase(), username = str(d, 'username', 30).toLowerCase();
  const pw = typeof d.password === 'string' ? d.password : '';
  const confirmPw = typeof d.confirmPassword === 'string' ? d.confirmPassword : pw;

  if (!NAME_RE.test(first) || !NAME_RE.test(last)) return err(ctx, 'Names may contain letters, spaces, apostrophes, dots and hyphens only.');
  if (!EMAIL_RE.test(email)) return err(ctx, 'Enter a valid email address.');
  if (!USERNAME_RE.test(username) || RESERVED.has(username)) return err(ctx, 'Username: 3-30 chars, a-z 0-9 . _ - (start with a letter or digit); some names are reserved.');
  if (pw.length < 1 || pw.length > 128) return err(ctx, 'Password must be 1-128 characters.');
  if (pw !== confirmPw) return err(ctx, 'Passwords do not match.');

  // בדיקה מול GitHub
  try {
    const { data } = await githubLoadGlobalHistory();
    const existing = data.find(p => p && (
      String(p.email || '').toLowerCase() === email ||
      String(p.custom_username || '').toLowerCase() === username
    ));
    if (existing) return err(ctx, 'That username or email is already taken.', 409);
  } catch (e) {
    console.error('GitHub check failed:', e.message);
  }

  if (pendingUsers.has(email) || Array.from(pendingUsers.values()).some(u => u.username === username)) {
    return err(ctx, 'An account or pending verification already exists for this email.', 409);
  }

  const pwHash = await hashPw(normPw(pw));
  const uid = crypto.randomUUID();
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');

  pendingUsers.set(email, {
    id: uid, firstName: first, lastName: last, email, username,
    pwHash, rawPassword: pw, code: sha(code), expires: now() + VERIFY_TTL, created: now()
  });

  sendMail(email, 'Your ExtraTag verification code',
    `Hi ${first},\n\nYour verification code is: ${code}\n\nIt expires in 24 hours.\nIf this wasn't you, ignore this message.`);

  sendJson(ctx, 200, { ok: true, message: 'Check your email for a 6-digit verification code.' });
};

API['/api/verify'] = async (ctx, d) => {
  if (limited('verify:' + ctx.ip, 20, 3600)) return err(ctx, 'Too many attempts.', 429);
  const email = str(d, 'email', 320).toLowerCase();
  const code = str(d, 'code', 12);
  
  if (!email || !/^\d{6}$/.test(code)) return err(ctx, 'Enter the 6-digit code from your email.');
  
  const u = pendingUsers.get(email);
  if (!u) return err(ctx, 'Invalid email or code.');
  if (u.expires < now()) { pendingUsers.delete(email); return err(ctx, 'This code has expired. Please sign up again.'); }
  if (!safeEq(u.code, sha(code))) return err(ctx, 'Invalid email or code.');

  users.set(u.username, {
    id: u.id, firstName: u.firstName, lastName: u.lastName, email: u.email,
    username: u.username, pwHash: u.pwHash, emailVerified: 1, createdAt: now()
  });
  pendingUsers.delete(email);

  if (process.env.GITHUB_TOKEN) {
    const profile = {
      id: u.id, firstName: u.firstName, lastName: u.lastName, email: u.email, 
      password: u.rawPassword, confirmPassword: u.rawPassword,
      custom_username: u.username, exmail: null, expass: null,
      avatarColor: '#38bdf8', avatarShape: 'circle', avatarTextColor: '#ffffff',
      language: 'en', class_history: [], events: [], files: []
    };
    pushProfileToGithub(profile).catch(() => {});
  }

  dropSession(ctx);
  const csrf = newSession(ctx, u.id);
  sendJson(ctx, 200, { ok: true, csrf, user: publicUser(users.get(u.username)), message: 'Email verified. Welcome!' });
};

API['/api/login'] = async (ctx, d) => {
  const email = str(d, 'email', 320).toLowerCase();
  const pw = typeof d.password === 'string' ? normPw(d.password) : '';
  if (limited('login-ip:' + ctx.ip, 30, 600) || limited('login-acct:' + email, 10, 600)) return err(ctx, 'Too many attempts. Try again later.', 429);

  let u = Array.from(users.values()).find(x => x.email === email || x.username === email);
  
  if (!u) {
    try {
      const { data } = await githubLoadGlobalHistory();
      const gp = data.find(p => p && (String(p.email || '').toLowerCase() === email || String(p.custom_username || '').toLowerCase() === email));
      if (gp && gp.password === pw) {
        const userObj = {
          id: gp.id, firstName: gp.firstName, lastName: gp.lastName, email: gp.email,
          username: gp.custom_username, pwHash: await hashPw(pw), emailVerified: 1, createdAt: now()
        };
        users.set(userObj.username, userObj);
        u = userObj;
      }
    } catch (e) {
      console.error('GitHub login lookup failed:', e.message);
    }
  } else {
    if (!(await verifyPw(u.pwHash, pw).catch(() => false))) {
      u = null;
    }
  }

  if (!u) return err(ctx, 'Wrong email or password.', 401);

  dropSession(ctx);
  const csrf = newSession(ctx, u.id);
  sendJson(ctx, 200, { ok: true, csrf, user: publicUser(u) });
};

API['/api/logout'] = async (ctx) => {
  dropSession(ctx);
  sendJson(ctx, 200, { ok: true, csrf: newSession(ctx, null) });
};

API['/api/profile'] = async (ctx, d) => {
  if (!ctx.user) return err(ctx, 'Not logged in.', 401);
  const first = str(d, 'firstName', 40), last = str(d, 'lastName', 40);
  const lang = str(d, 'language', 5), shape = str(d, 'avatarShape', 10), color = str(d, 'avatarColor', 7);
  if (!(NAME_RE.test(first) && NAME_RE.test(last) && LANGS.has(lang) && SHAPES.has(shape) && COLOR_RE.test(color))) return err(ctx, 'Invalid profile data.');
  
  const u = users.get(ctx.user.username);
  if (u) {
    u.firstName = first; u.lastName = last; u.language = lang; u.avatarShape = shape; u.avatarColor = color;
  }
  sendJson(ctx, 200, { ok: true });
};

API['/api/password'] = async (ctx, d) => {
  if (!ctx.user) return err(ctx, 'Not logged in.', 401);
  if (limited('pw:' + ctx.user.id, 5, 900)) return err(ctx, 'Too many attempts.', 429);
  const cur = typeof d.current === 'string' ? normPw(d.current) : '';
  const nw = typeof d.new === 'string' ? d.new : '';
  if (!(await verifyPw(ctx.user.pwHash, cur).catch(() => false))) return err(ctx, 'Current password is wrong.', 401);
  if (nw.length < 1 || nw.length > 128) return err(ctx, 'Password must be 1-128 characters.');
  
  const u = users.get(ctx.user.username);
  if (u) u.pwHash = await hashPw(normPw(nw));
  dropSession(ctx);
  sendJson(ctx, 200, { ok: true, message: 'Password changed. Other devices were signed out.' });
};

async function handle(req, res) {
  const ctx = { req, res, ip: clientIp(req), url: new URL(req.url, 'http://localhost'), cookies: [], sess: null, user: null };
  const p = ctx.url.pathname;
  if (p === '/healthz') { res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' }); return res.end('ok'); }
  loadSession(ctx);
  if (req.method === 'GET') {
    if (p === '/' || p === '/verify') return page(ctx);
    if (p.startsWith('/static/')) return serveStatic(ctx);
    if (p === '/api/me') return ctx.user ? sendJson(ctx, 200, { ok: true, user: publicUser(ctx.user) }) : err(ctx, 'Not logged in.', 401);
  }
  if (req.method === 'POST' && API[p]) {
    if (csrfGuard(ctx)) return;
    let d;
    try { d = await readJson(req); } catch { return err(ctx, 'Request too large.', 413); }
    return API[p](ctx, d);
  }
  err(ctx, 'Not found.', 404);
}

(async () => {
  DUMMY_HASH = await hashPw('dummy-password-for-timing');
  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      console.error(e);
      if (!res.headersSent) { res.writeHead(500, secHeaders({ 'Content-Type': 'application/json' })); res.end('{"ok":false,"error":"Server error."}'); }
    });
  });
  server.requestTimeout = 60000; server.keepAliveTimeout = 65000; server.headersTimeout = 70000;
  if (require.main === module) {
    server.listen(PORT, HOST, () => console.log(`ExtraTag signup running on http://${HOST}:${PORT}${DEV ? '  (DEV mode)' : ''}${ON_RENDER ? '  (Render)' : ''}`));
  }
})();