import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { open } from 'sqlite';
import sqlite3 from 'sqlite3';

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// Middlewares
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(express.static('.'));

// DB setup
let db;
async function getDb() {
  if (!db) {
    db = await open({ filename: './data.db', driver: sqlite3.Database });
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        phone TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        metadata TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
      );
      CREATE INDEX IF NOT EXISTS idx_activities_user_created ON activities(user_id, created_at DESC);
    `);
  }
  return db;
}

function setAuthCookie(res, token) {
  res.cookie('auth', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // set true if behind HTTPS
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });
}

function clearAuthCookie(res) {
  res.clearCookie('auth', { path: '/' });
}

async function authMiddleware(req, res, next) {
  const token = req.cookies?.auth || req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Helpers
function normalizeIdentifier(identifier) {
  if (!identifier) return null;
  const trimmed = String(identifier).trim();
  if (/^\+?\d{8,15}$/.test(trimmed)) return { type: 'phone', value: trimmed.replace(/^\+/, '') };
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return { type: 'email', value: trimmed.toLowerCase() };
  return null;
}

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { identifier, password } = req.body;
    const normalized = normalizeIdentifier(identifier);
    if (!normalized || !password || password.length < 6) {
      return res.status(400).json({ error: 'Invalid identifier or password' });
    }
    const dbx = await getDb();
    const passwordHash = await bcrypt.hash(password, 10);
    const fields = normalized.type === 'email' ? { email: normalized.value } : { phone: normalized.value };
    try {
      const result = await dbx.run(
        `INSERT INTO users(${Object.keys(fields).join(', ')}, password_hash) VALUES (${Object.keys(fields).map(()=>'?' ).join(', ')}, ?)`,
        [...Object.values(fields), passwordHash]
      );
      const userId = result.lastID;
      const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
      setAuthCookie(res, token);
      res.json({ ok: true, userId });
    } catch (e) {
      if (String(e).includes('UNIQUE')) {
        return res.status(409).json({ error: 'User already exists' });
      }
      throw e;
    }
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;
    const normalized = normalizeIdentifier(identifier);
    if (!normalized || !password) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const dbx = await getDb();
    const where = normalized.type === 'email' ? 'email = ?' : 'phone = ?';
    const user = await dbx.get(`SELECT * FROM users WHERE ${where}`, [normalized.value]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    setAuthCookie(res, token);
    await dbx.run('INSERT INTO activities(user_id, action, metadata) VALUES (?, ?, ?)', [user.id, 'login', null]);
    res.json({ ok: true, userId: user.id });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', authMiddleware, async (req, res) => {
  try {
    const dbx = await getDb();
    await dbx.run('INSERT INTO activities(user_id, action, metadata) VALUES (?, ?, ?)', [req.user.userId, 'logout', null]);
  } catch {}
  clearAuthCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const user = await dbx.get('SELECT id, email, phone, created_at FROM users WHERE id = ?', [req.user.userId]);
  res.json({ user });
});

app.post('/api/activities', authMiddleware, async (req, res) => {
  try {
    const { action, metadata } = req.body || {};
    if (!action) return res.status(400).json({ error: 'Action required' });
    const dbx = await getDb();
    await dbx.run('INSERT INTO activities(user_id, action, metadata) VALUES (?, ?, ?)', [req.user.userId, String(action), metadata ? JSON.stringify(metadata) : null]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/activities', authMiddleware, async (req, res) => {
  const dbx = await getDb();
  const rows = await dbx.all('SELECT id, action, metadata, created_at FROM activities WHERE user_id = ? ORDER BY created_at DESC LIMIT 100', [req.user.userId]);
  const parsed = rows.map(r => ({ ...r, metadata: r.metadata ? JSON.parse(r.metadata) : null }));
  res.json({ activities: parsed });
});

app.listen(PORT, () => {
  console.log(`Auth server listening on http://localhost:${PORT}`);
});
