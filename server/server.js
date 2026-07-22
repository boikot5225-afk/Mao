require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');

const APP_PASSWORD = process.env.APP_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!APP_PASSWORD || !SESSION_SECRET) {
  console.error('APP_PASSWORD and SESSION_SECRET must be set (see .env.example)');
  process.exit(1);
}

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'orders.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    chat TEXT,
    description TEXT,
    price REAL DEFAULT 0,
    paid INTEGER DEFAULT 0,
    deadline TEXT,
    photos TEXT DEFAULT '[]',
    source TEXT DEFAULT 'manual',
    reviewed INTEGER DEFAULT 1,
    createdAt INTEGER
  )
`);
// Defensive migration for databases created before source/reviewed existed.
for (const stmt of [
  "ALTER TABLE orders ADD COLUMN source TEXT DEFAULT 'manual'",
  "ALTER TABLE orders ADD COLUMN reviewed INTEGER DEFAULT 1"
]) {
  try { db.exec(stmt); } catch (e) { /* column already exists */ }
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '25mb' }));
app.use(cookieParser());

const SESSION_MAX_AGE = 30 * 24 * 60 * 60 * 1000; // 30 days

function signSession(expiresAt) {
  const payload = String(expiresAt);
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return payload + '.' + sig;
}

function verifySession(token) {
  if (!token) return false;
  const idx = token.lastIndexOf('.');
  if (idx === -1) return false;
  const payload = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return false;
  return Date.now() < parseInt(payload, 10);
}

function requireAuth(req, res, next) {
  if (verifySession(req.cookies.session)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'unauthorized' });
  return res.redirect('/login.html');
}

async function notifyTelegram(order) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;
  const lines = [
    '🔔 Новая заявка на заказ',
    '',
    'Имя: ' + order.name,
    'Контакt: ' + (order.chat || '—'),
    'Состав: ' + (order.desc || '—')
  ];
  try {
    await fetch('https://api.telegram.org/bot' + token + '/sendMessage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: lines.join('\n') })
    });
  } catch (e) {
    console.error('Telegram notify failed:', e.message);
  }
}

// Very small in-memory rate limiter for the public order form (per IP).
const publicSubmitLog = new Map();
function publicRateLimit(req, res, next) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const windowMs = 30 * 60 * 1000;
  const limit = 5;
  const timestamps = (publicSubmitLog.get(ip) || []).filter((t) => now - t < windowMs);
  if (timestamps.length >= limit) {
    return res.status(429).json({ error: 'too many submissions, try again later' });
  }
  timestamps.push(now);
  publicSubmitLog.set(ip, timestamps);
  next();
}

app.post('/api/login', (req, res) => {
  const password = String((req.body && req.body.password) || '');
  const a = Buffer.from(password);
  const b = Buffer.from(APP_PASSWORD);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!ok) return res.status(401).json({ error: 'wrong password' });
  const expiresAt = Date.now() + SESSION_MAX_AGE;
  res.cookie('session', signSession(expiresAt), {
    httpOnly: true,
    sameSite: 'lax',
    secure: req.secure,
    maxAge: SESSION_MAX_AGE
  });
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/new-order.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'new-order.html'));
});

function rowToOrder(row) {
  return {
    id: row.id,
    name: row.name,
    chat: row.chat,
    desc: row.description,
    price: row.price,
    paid: !!row.paid,
    deadline: row.deadline,
    photos: JSON.parse(row.photos || '[]').map((f) => '/api/photo/' + f),
    source: row.source || 'manual',
    reviewed: !!row.reviewed,
    createdAt: row.createdAt
  };
}

// Accepts either fresh data: URLs (new uploads) or existing /api/photo/<file> URLs
// (photos kept unchanged from a previous save) and returns stored filenames.
function normalizeIncomingPhotos(photos) {
  return (photos || [])
    .map((p) => {
      if (typeof p !== 'string') return null;
      if (p.startsWith('data:image/')) {
        const match = p.match(/^data:image\/(\w+);base64,(.+)$/);
        if (!match) return null;
        const ext = match[1] === 'jpeg' ? 'jpg' : match[1].replace(/[^a-z0-9]/gi, '');
        const filename = crypto.randomUUID() + '.' + ext;
        fs.writeFileSync(path.join(UPLOADS_DIR, filename), Buffer.from(match[2], 'base64'));
        return filename;
      }
      if (p.startsWith('/api/photo/')) {
        return p.slice('/api/photo/'.length);
      }
      return null;
    })
    .filter(Boolean);
}

app.post('/api/public-orders', publicRateLimit, async (req, res) => {
  const b = req.body || {};
  if (b.company) {
    // Honeypot field — bots tend to fill it, real visitors never see it.
    return res.json({ ok: true });
  }
  if (!b.name || !String(b.name).trim()) return res.status(400).json({ error: 'name required' });
  const id = crypto.randomUUID();
  const photos = normalizeIncomingPhotos(b.photos);
  db.prepare(`
    INSERT INTO orders (id, name, chat, description, price, paid, deadline, photos, source, reviewed, createdAt)
    VALUES (?, ?, ?, ?, 0, 0, '', ?, 'customer', 0, ?)
  `).run(id, String(b.name).trim(), b.chat || '', b.desc || '', JSON.stringify(photos), Date.now());
  const order = rowToOrder(db.prepare('SELECT * FROM orders WHERE id = ?').get(id));
  notifyTelegram(order);
  res.json({ ok: true });
});

app.use(requireAuth);

app.get('/api/orders', (req, res) => {
  const rows = db.prepare('SELECT * FROM orders ORDER BY createdAt DESC').all();
  res.json(rows.map(rowToOrder));
});

app.post('/api/orders', (req, res) => {
  const b = req.body || {};
  if (!b.name || !String(b.name).trim()) return res.status(400).json({ error: 'name required' });
  const id = crypto.randomUUID();
  const photos = normalizeIncomingPhotos(b.photos);
  db.prepare(`
    INSERT INTO orders (id, name, chat, description, price, paid, deadline, photos, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, String(b.name).trim(), b.chat || '', b.desc || '',
    Number(b.price) || 0, b.paid ? 1 : 0, b.deadline || '',
    JSON.stringify(photos), Date.now()
  );
  res.json(rowToOrder(db.prepare('SELECT * FROM orders WHERE id = ?').get(id)));
});

app.put('/api/orders/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'not found' });
  const b = req.body || {};
  if (!b.name || !String(b.name).trim()) return res.status(400).json({ error: 'name required' });

  const oldPhotos = JSON.parse(existing.photos || '[]');
  const newPhotos = normalizeIncomingPhotos(b.photos);
  oldPhotos
    .filter((f) => !newPhotos.includes(f))
    .forEach((f) => fs.unlink(path.join(UPLOADS_DIR, f), () => {}));

  db.prepare(`
    UPDATE orders SET name=?, chat=?, description=?, price=?, paid=?, deadline=?, photos=?, reviewed=1
    WHERE id = ?
  `).run(
    String(b.name).trim(), b.chat || '', b.desc || '',
    Number(b.price) || 0, b.paid ? 1 : 0, b.deadline || '',
    JSON.stringify(newPhotos), req.params.id
  );
  res.json(rowToOrder(db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id)));
});

app.delete('/api/orders/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'not found' });
  JSON.parse(existing.photos || '[]').forEach((f) => fs.unlink(path.join(UPLOADS_DIR, f), () => {}));
  db.prepare('DELETE FROM orders WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/photo/:filename', (req, res) => {
  const filename = req.params.filename;
  if (!/^[\w-]+\.[a-zA-Z0-9]+$/.test(filename)) return res.status(400).end();
  const filePath = path.join(UPLOADS_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.sendFile(filePath);
});

app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Jewelry orders server listening on port ' + PORT));
