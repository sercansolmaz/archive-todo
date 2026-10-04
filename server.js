'use strict';
/* Gerçeklik Defteri — zero-dependency Node server
   Auth: APP_PASSWORD env, HMAC-signed cookie. State: $DATA_DIR/state.json */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '3001', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const APP_PASSWORD = process.env.APP_PASSWORD || '';
const COOKIE_NAME = 'gdk_auth';
const COOKIE_DAYS = 30;
const MAX_BODY = 2 * 1024 * 1024;

if (!APP_PASSWORD) { console.error('FATAL: APP_PASSWORD env eksik'); process.exit(1); }

const PASS_HASH = crypto.createHash('sha256').update(APP_PASSWORD).digest('hex');
const SECRET = crypto.createHash('sha256').update('gdk::' + PASS_HASH).digest('hex');

function sign(v) { return crypto.createHmac('sha256', SECRET).update(String(v)).digest('hex'); }
function safeEqual(a, b) {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}
function makeCookieHeader() {
  const exp = Date.now() + COOKIE_DAYS * 864e5;
  const p = String(exp);
  return `${COOKIE_NAME}=${p}.${sign(p)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${COOKIE_DAYS * 86400}`;
}
function clearCookieHeader() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}
function isAuthed(req) {
  const raw = req.headers.cookie || '';
  const m = raw.match(new RegExp('(?:^|;\\s*)' + COOKIE_NAME + '=([^;]+)'));
  if (!m) return false;
  const parts = m[1].split('.');
  if (parts.length !== 2) return false;
  const [exp, sig] = parts;
  if (!/^\d+$/.test(exp) || Date.now() > parseInt(exp, 10)) return false;
  return safeEqual(sig, sign(exp));
}

/* ---------- state ---------- */
let state = { v: 1, rev: 0, updatedAt: null, items: [], guide: [] };
function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
      if (parsed && Array.isArray(parsed.items)) {
        state = { v: 1, rev: parsed.rev || 0, updatedAt: parsed.updatedAt || null, items: parsed.items, guide: Array.isArray(parsed.guide) ? parsed.guide : [] };
      }
    }
  } catch (e) { console.error('state load hatasi:', e.message); }
}
function saveState() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = STATE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(state, null, 1), 'utf8');
  fs.renameSync(tmp, STATE_FILE);
}
loadState();

/* ---------- helpers ---------- */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch (e) { reject(new Error('bad json')); }
    });
    req.on('error', reject);
  });
}
function json(res, code, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  }, extraHeaders || {}));
  res.end(body);
}
function cleanItem(it) {
  const s = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');
  return {
    no: parseInt(it.no, 10) || 0,
    category: s(it.category, 120),
    title: s(it.title, 300),
    detail: s(it.detail, 3000),
    found: s(it.found, 40),
    burcuKnows: s(it.burcuKnows, 40),
    status: s(it.status, 40),
    secondCheck: s(it.secondCheck, 40),
    openFile: s(it.openFile, 40),
    notes: s(it.notes, 5000),
    checkDate: s(it.checkDate, 30),
  };
}

const INDEX_FILE = path.join(__dirname, 'public', 'index.html');
function serveIndex(res) {
  try {
    const html = fs.readFileSync(INDEX_FILE);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(html);
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'text/plain' }); res.end('index.html yok');
  }
}

/* ---------- server ---------- */
const server = http.createServer(async (req, res) => {
  const url = (req.url || '/').split('?')[0];
  try {
    if (req.method === 'GET' && (url === '/' || url === '/index.html')) return serveIndex(res);
    if (req.method === 'GET' && url === '/api/health') return json(res, 200, { ok: true, ts: Date.now() });
    if (req.method === 'GET' && url === '/favicon.ico') { res.writeHead(204); return res.end(); }

    if (req.method === 'POST' && url === '/api/login') {
      const body = await readBody(req);
      const given = crypto.createHash('sha256').update(String(body.password || '')).digest('hex');
      if (safeEqual(given, PASS_HASH)) return json(res, 200, { ok: true }, { 'Set-Cookie': makeCookieHeader() });
      return json(res, 401, { ok: false, error: 'Şifre hatalı' });
    }
    if (req.method === 'POST' && url === '/api/logout') {
      return json(res, 200, { ok: true }, { 'Set-Cookie': clearCookieHeader() });
    }

    if (url === '/api/state') {
      if (!isAuthed(req)) return json(res, 401, { error: 'unauthorized' });
      if (req.method === 'GET') return json(res, 200, state);
      if (req.method === 'PUT') {
        const body = await readBody(req);
        if (!Array.isArray(body.items)) return json(res, 400, { error: 'items array gerekli' });
        if (body.items.length > 500) return json(res, 400, { error: 'çok fazla madde' });
        state.items = body.items.map(cleanItem);
        if (Array.isArray(body.guide) && body.guide.length) state.guide = body.guide;
        state.rev = Date.now();
        state.updatedAt = new Date().toISOString();
        saveState();
        return json(res, 200, { ok: true, rev: state.rev, updatedAt: state.updatedAt });
      }
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found');
  } catch (e) {
    json(res, 500, { error: e.message });
  }
});
server.listen(PORT, () => console.log(`gerceklik-defteri listening on :${PORT}, data: ${DATA_DIR}`));
