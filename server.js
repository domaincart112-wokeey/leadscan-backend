/**
 * LeadScan — Exhibition Lead Management Backend
 * Node.js / Express server
 *
 * npm install express better-sqlite3 bcryptjs jsonwebtoken nodemailer
 *             express-rate-limit cors dotenv
 */

require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

// ── DATABASE ──────────────────────────────────────────────────
const db = new Database(process.env.DB_PATH || './leadscan.db');

// Run migrations
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    company     TEXT,
    notify_email TEXT,
    email_enabled INTEGER DEFAULT 1,
    created_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS leads (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    name        TEXT NOT NULL,
    company     TEXT,
    phone       TEXT NOT NULL,
    email       TEXT,
    interest    TEXT,
    notes       TEXT,
    status      TEXT DEFAULT 'new',
    source      TEXT DEFAULT 'form',
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_leads_user ON leads(user_id);
  CREATE INDEX IF NOT EXISTS idx_leads_created ON leads(created_at);
`);

// ── MIDDLEWARE ────────────────────────────────────────────────
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, '../frontend')));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { ok: false, message: 'Too many attempts. Please try again in 15 minutes.' }
});
const leadsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { ok: false, message: 'Too many requests.' }
});

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ ok: false, message: 'Authentication required.' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch(e) {
    return res.status(401).json({ ok: false, message: 'Invalid or expired token.' });
  }
}

// ── INPUT SANITIZATION ────────────────────────────────────────
function sanitize(str, maxLen = 255) {
  if (!str || typeof str !== 'string') return null;
  return str.trim().slice(0, maxLen);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhone(phone) {
  return /^[0-9+\s\-()]{6,20}$/.test(phone);
}

function generateId() {
  return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
}

// ── EMAIL TRANSPORT ───────────────────────────────────────────
let transporter;
if (process.env.SMTP_HOST) {
 transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',https://github.com/domaincart112-wokeey/leadscan-backend/blob/main/server.js
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
} else if (process.env.GMAIL_USER) {
  // Gmail with App Password
 transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASS
    }
  });
}

async function sendLeadEmail(user, lead) {
  if (!transporter || !user.email_enabled || !user.notify_email) return;

  const html = `
    <div style="font-family: 'DM Sans', Arial, sans-serif; max-width: 560px; margin: 0 auto; border: 1px solid #ddd9d2; border-radius: 12px; overflow: hidden;">
      <div style="background: #0d0d0d; padding: 20px 24px;">
        <span style="color: #fff; font-size: 18px; font-weight: 800; letter-spacing: -0.03em;">
          Lead<span style="color: #e8500a;">.</span>Scan
        </span>
      </div>
      <div style="padding: 24px; background: #fff;">
        <p style="font-size: 16px; font-weight: 600; margin-bottom: 4px; color: #0d0d0d;">
          🎉 New Lead Captured — ${lead.name}
        </p>
        <p style="font-size: 13px; color: #7a7570; margin-bottom: 20px;">
          From ${user.company || 'your booth'} · ${new Date(lead.created_at).toLocaleString('en-IN')}
        </p>
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          ${row('Name', lead.name)}
          ${row('Company', lead.company || '—')}
          ${row('Phone', `<a href="tel:${lead.phone}" style="color:#e8500a">${lead.phone}</a>`)}
          ${row('Email', lead.email ? `<a href="mailto:${lead.email}" style="color:#e8500a">${lead.email}</a>` : '—')}
          ${row('Interest', lead.interest || '—')}
          ${row('Notes', lead.notes || '—')}
        </table>
        <div style="margin-top:24px;padding-top:16px;border-top:1px solid #ddd9d2;font-size:12px;color:#7a7570;">
          To manage this lead, log in to your LeadScan dashboard.
        </div>
      </div>
    </div>
  `;

  function row(label, value) {
    return `<tr>
      <td style="padding:8px 12px;background:#f7f5f0;font-weight:600;width:30%;border-radius:4px;vertical-align:top;">${label}</td>
      <td style="padding:8px 12px;color:#0d0d0d;">${value}</td>
    </tr>`;
  }

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || '"LeadScan" <noreply@leadscan.io>',
      to: user.notify_email,
      subject: `🎯 New Lead: ${lead.name} — ${user.company || 'Your Booth'}`,
      html
    });
  } catch(err) {
    console.error('Email send error:', err.message);
  }
}

// ══════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════

// ── AUTH: SIGNUP ──────────────────────────────────────────────
app.post('/api/auth/signup', authLimiter, async (req, res) => {
  const name    = sanitize(req.body.name);
  const email   = sanitize(req.body.email)?.toLowerCase();
  const company = sanitize(req.body.company);
  const password = req.body.password;

  if (!name || !email || !password)
    return res.status(400).json({ ok: false, message: 'Name, email and password are required.' });
  if (!isValidEmail(email))
    return res.status(400).json({ ok: false, message: 'Invalid email address.' });
  if (typeof password !== 'string' || password.length < 8)
    return res.status(400).json({ ok: false, message: 'Password must be at least 8 characters.' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing)
    return res.status(409).json({ ok: false, message: 'An account with this email already exists.' });

  const id = generateId();
  const hash = await bcrypt.hash(password, 12);

  db.prepare(
    'INSERT INTO users (id, name, email, password, company, notify_email) VALUES (?,?,?,?,?,?)'
  ).run(id, name, email, hash, company || null, email);

  const token = jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: '30d' });
  const user = { id, name, email, company, notifyEmail: email, emailEnabled: true };

  res.json({ ok: true, user, token });
});

// ── AUTH: LOGIN ───────────────────────────────────────────────
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const email    = sanitize(req.body.email)?.toLowerCase();
  const password = req.body.password;

  if (!email || !password)
    return res.status(400).json({ ok: false, message: 'Email and password are required.' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user)
    return res.status(401).json({ ok: false, message: 'No account found with this email.' });

  const match = await bcrypt.compare(password, user.password);
  if (!match)
    return res.status(401).json({ ok: false, message: 'Incorrect password.' });

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
  const safeUser = {
    id: user.id, name: user.name, email: user.email,
    company: user.company, notifyEmail: user.notify_email,
    emailEnabled: !!user.email_enabled
  };

  res.json({ ok: true, user: safeUser, token });
});

// ── USER: PUBLIC INFO (for form page) ────────────────────────
app.get('/api/user-info/:userId', (req, res) => {
  const user = db.prepare('SELECT name, company FROM users WHERE id = ?').get(req.params.userId);
  if (!user) return res.status(404).json({ ok: false, message: 'User not found.' });
  res.json({ ok: true, name: user.name, company: user.company });
});

// ── USER: GET SETTINGS ────────────────────────────────────────
app.get('/api/settings', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, company, notify_email, email_enabled FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ ok: false });
  res.json({ ok: true, user: { ...user, notifyEmail: user.notify_email, emailEnabled: !!user.email_enabled } });
});

// ── USER: UPDATE SETTINGS ─────────────────────────────────────
app.post('/api/settings', requireAuth, async (req, res) => {
  const name         = sanitize(req.body.name);
  const company      = sanitize(req.body.company);
  const notifyEmail  = sanitize(req.body.notifyEmail);
  const emailEnabled = req.body.emailEnabled ? 1 : 0;
  const newPassword  = req.body.newPassword;

  if (!name) return res.status(400).json({ ok: false, message: 'Name is required.' });
  if (notifyEmail && !isValidEmail(notifyEmail))
    return res.status(400).json({ ok: false, message: 'Invalid notification email.' });
  if (newPassword && newPassword.length < 8)
    return res.status(400).json({ ok: false, message: 'Password must be at least 8 characters.' });

  if (newPassword) {
    const hash = await bcrypt.hash(newPassword, 12);
    db.prepare('UPDATE users SET name=?, company=?, notify_email=?, email_enabled=?, password=? WHERE id=?')
      .run(name, company || null, notifyEmail || null, emailEnabled, hash, req.userId);
  } else {
    db.prepare('UPDATE users SET name=?, company=?, notify_email=?, email_enabled=? WHERE id=?')
      .run(name, company || null, notifyEmail || null, emailEnabled, req.userId);
  }

  res.json({ ok: true, message: 'Settings updated.' });
});

// ── LEADS: POST (capture) ─────────────────────────────────────
app.post('/api/leads', leadsLimiter, (req, res) => {
  // Honeypot check
  if (req.body.website) return res.status(200).json({ ok: true }); // silent discard

  const userId  = sanitize(req.body.userId);
  const name    = sanitize(req.body.name);
  const company = sanitize(req.body.company);
  const phone   = sanitize(req.body.phone);
  const email   = sanitize(req.body.email);
  const interest= sanitize(req.body.interest);
  const notes   = sanitize(req.body.notes, 1000);

  if (!userId || !name || !phone)
    return res.status(400).json({ ok: false, message: 'userId, name and phone are required.' });
  if (!isValidPhone(phone))
    return res.status(400).json({ ok: false, message: 'Invalid phone number.' });
  if (email && !isValidEmail(email))
    return res.status(400).json({ ok: false, message: 'Invalid email.' });

  // Duplicate check (same phone for this user in last 10 min)
  const tenMinsAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const dup = db.prepare(
    "SELECT id FROM leads WHERE user_id=? AND phone=? AND created_at > ?"
  ).get(userId, phone, tenMinsAgo);
  if (dup) return res.status(200).json({ ok: true, duplicate: true });

  const id = req.body.id || generateId();
  db.prepare(
    'INSERT OR IGNORE INTO leads (id, user_id, name, company, phone, email, interest, notes, source) VALUES (?,?,?,?,?,?,?,?,?)'
  ).run(id, userId, name, company || null, phone, email || null, interest || null, notes || null, 'form');

  // Send email notification (async, don't block response)
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (user) {
    const lead = { name, company, phone, email, interest, notes, created_at: new Date().toISOString() };
    sendLeadEmail(user, lead).catch(console.error);
  }

  res.json({ ok: true, id });
});

// ── LEADS: GET (dashboard) ────────────────────────────────────
app.get('/api/leads', requireAuth, (req, res) => {
  const { search, interest, status, from, to } = req.query;
  let query = 'SELECT * FROM leads WHERE user_id = ?';
  const params = [req.userId];

  if (interest) { query += ' AND interest = ?'; params.push(interest); }
  if (status)   { query += ' AND status = ?';   params.push(status); }
  if (from)     { query += ' AND created_at >= ?'; params.push(from); }
  if (to)       { query += ' AND created_at <= ?'; params.push(to + 'T23:59:59'); }
  if (search) {
    query += ' AND (name LIKE ? OR company LIKE ? OR email LIKE ? OR phone LIKE ?)';
    const s = `%${search}%`;
    params.push(s, s, s, s);
  }
  query += ' ORDER BY created_at DESC LIMIT 1000';

  const leads = db.prepare(query).all(...params);
  res.json({ ok: true, leads });
});

// ── LEADS: MARK CONTACTED ─────────────────────────────────────
app.patch('/api/leads/:id/contact', requireAuth, (req, res) => {
  const result = db.prepare(
    "UPDATE leads SET status='contacted' WHERE id=? AND user_id=?"
  ).run(req.params.id, req.userId);
  if (result.changes === 0) return res.status(404).json({ ok: false });
  res.json({ ok: true });
});

// ── LEADS: DELETE ─────────────────────────────────────────────
app.delete('/api/leads/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM leads WHERE id=? AND user_id=?').run(req.params.id, req.userId);
  if (result.changes === 0) return res.status(404).json({ ok: false });
  res.json({ ok: true });
});

// ── SPA FALLBACK ──────────────────────────────────────────────
// Serve form.html for /form/:userId routes
app.get('/tools/exhibition-lead-management/form/:userId', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/form.html'));
});
// Serve main app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ── START ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`LeadScan backend running on http://localhost:${PORT}`);
  console.log(`Form URL pattern: http://localhost:${PORT}/tools/exhibition-lead-management/form/{user_id}`);
});

module.exports = app;
