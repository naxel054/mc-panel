const express  = require('express');
const sqlite3  = require('sqlite3').verbose();
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = 'metsunevraimotdepasse123_jwt';
const AGENT_SECRET = 'metsunevraimotdepasse123';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./panel.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS server_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    status TEXT DEFAULT 'stopped',
    requested_by TEXT DEFAULT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`INSERT OR IGNORE INTO server_state (id, status) VALUES (1, 'stopped')`);

  // Créer admin depuis variables d'environnement
  const envUser = process.env.ADMIN_USER;
  const envPass = process.env.ADMIN_PASS;
  if (envUser && envPass) {
    const hash = bcrypt.hashSync(envPass, 10);
    db.run(`INSERT OR REPLACE INTO users (username, password, is_admin) VALUES (?, ?, 1)`, [envUser, hash], () => {
      console.log(`✅ Admin "${envUser}" prêt !`);
    });
  }
});

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Token manquant' });
  try {
    req.user = jwt.verify(header.split(' ')[1], SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Accès refusé' });
  next();
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, err => err ? reject(err) : resolve());
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
  });
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, SECRET, { expiresIn: '24h' });
  res.json({ token, username: user.username, is_admin: user.is_admin });
});

app.get('/api/status', authMiddleware, async (req, res) => {
  const state = await dbGet('SELECT * FROM server_state WHERE id = 1');
  res.json(state);
});

app.post('/api/start', authMiddleware, async (req, res) => {
  const state = await dbGet('SELECT status FROM server_state WHERE id = 1');
  if (state.status !== 'stopped') return res.status(409).json({ error: `Serveur déjà : ${state.status}` });
  await dbRun(`UPDATE server_state SET status='starting', requested_by=?, updated_at=datetime('now') WHERE id=1`, [req.user.username]);
  res.json({ success: true, message: 'Démarrage demandé !' });
});

app.post('/api/stop', authMiddleware, async (req, res) => {
  const state = await dbGet('SELECT status FROM server_state WHERE id = 1');
  if (state.status !== 'running') return res.status(409).json({ error: 'Serveur pas en ligne' });
  await dbRun(`UPDATE server_state SET status='stopping', requested_by=?, updated_at=datetime('now') WHERE id=1`, [req.user.username]);
  res.json({ success: true, message: 'Arrêt demandé !' });
});

app.get('/api/agent/poll', async (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  const state = await dbGet('SELECT * FROM server_state WHERE id = 1');
  res.json(state);
});

app.post('/api/agent/confirm', async (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  const { status } = req.body;
  if (!['running', 'stopped'].includes(status)) return res.status(400).json({ error: 'Statut invalide' });
  await dbRun(`UPDATE server_state SET status=?, updated_at=datetime('now') WHERE id=1`, [status]);
  res.json({ success: true });
});

app.post('/api/admin/create-user', authMiddleware, adminMiddleware, async (req, res) => {
  const { username, password, is_admin = 0 } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  try {
    await dbRun('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', [username, bcrypt.hashSync(password, 10), is_admin ? 1 : 0]);
    res.json({ success: true, message: `Compte "${username}" créé !` });
  } catch {
    res.status(409).json({ error: 'Nom déjà pris' });
  }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const users = await dbAll('SELECT id, username, is_admin FROM users');
  res.json(users);
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await dbRun('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

app.listen(PORT, () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));
