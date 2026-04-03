const express  = require('express');
const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = 'metsunevraimotdepasse123_jwt';    // ← change si tu veux
const AGENT_SECRET = 'metsunevraimotdepasse123';  // ← même que dans agent.py

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new Database('panel.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT    UNIQUE NOT NULL,
    password TEXT    NOT NULL,
    is_admin INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS server_state (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    status       TEXT DEFAULT 'stopped',
    requested_by TEXT DEFAULT NULL,
    updated_at   TEXT DEFAULT (datetime('now'))
  );
  INSERT OR IGNORE INTO server_state (id, status) VALUES (1, 'stopped');
`);

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

// Auth
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, SECRET, { expiresIn: '24h' });
  res.json({ token, username: user.username, is_admin: user.is_admin });
});

// Status
app.get('/api/status', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM server_state WHERE id = 1').get());
});

// Start
app.post('/api/start', authMiddleware, (req, res) => {
  const state = db.prepare('SELECT status FROM server_state WHERE id = 1').get();
  if (state.status !== 'stopped')
    return res.status(409).json({ error: `Serveur déjà : ${state.status}` });
  db.prepare(`UPDATE server_state SET status='starting', requested_by=?, updated_at=datetime('now') WHERE id=1`).run(req.user.username);
  res.json({ success: true, message: 'Démarrage demandé !' });
});

// Stop
app.post('/api/stop', authMiddleware, (req, res) => {
  const state = db.prepare('SELECT status FROM server_state WHERE id = 1').get();
  if (state.status !== 'running')
    return res.status(409).json({ error: 'Serveur pas en ligne' });
  db.prepare(`UPDATE server_state SET status='stopping', requested_by=?, updated_at=datetime('now') WHERE id=1`).run(req.user.username);
  res.json({ success: true, message: 'Arrêt demandé !' });
});

// Agent poll
app.get('/api/agent/poll', (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  res.json(db.prepare('SELECT * FROM server_state WHERE id = 1').get());
});

// Agent confirm
app.post('/api/agent/confirm', (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  const { status } = req.body;
  if (!['running', 'stopped'].includes(status)) return res.status(400).json({ error: 'Statut invalide' });
  db.prepare(`UPDATE server_state SET status=?, updated_at=datetime('now') WHERE id=1`).run(status);
  res.json({ success: true });
});

// Admin - créer user
app.post('/api/admin/create-user', authMiddleware, adminMiddleware, (req, res) => {
  const { username, password, is_admin = 0 } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  try {
    db.prepare('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)').run(username, bcrypt.hashSync(password, 10), is_admin ? 1 : 0);
    res.json({ success: true, message: `Compte "${username}" créé !` });
  } catch {
    res.status(409).json({ error: 'Nom déjà pris' });
  }
});

// Admin - liste users
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  res.json(db.prepare('SELECT id, username, is_admin FROM users').all());
});

// Admin - supprimer user
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Créer admin au premier lancement
if (process.argv[2] === '--create-admin') {
  const [,,, username, password] = process.argv;
  db.prepare('INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, 1)').run(username, bcrypt.hashSync(password, 10));
  console.log(`✅ Admin "${username}" créé !`);
  process.exit(0);
}

app.listen(PORT, () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));
