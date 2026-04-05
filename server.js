const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const path    = require('path');
const multer  = require('multer');

const app  = express();
const PORT = process.env.PORT || 3000;
const SECRET       = 'mcpanel_jwt_secret_2024';
const AGENT_SECRET = process.env.AGENT_SECRET || 'heloufSMP_secret_2024';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/health', (req, res) => res.send('ok'));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    file.originalname.endsWith('.jar') ? cb(null, true) : cb(new Error('Seuls les .jar'));
  }
});

// ── Données en mémoire ────────────────────────────────────────
const users = [];
let consoleLogs = [];
let pendingPlugins = [];

// Serveurs définis ici — ajoute-en autant que tu veux !
const SERVERS = [
  {
    id: 'heloufSMP',
    name: 'HeloufSMP',
    description: 'Serveur SMP principal',
    icon: '⛏️',
    port: 50000,
  },
  // Exemple pour ajouter un 2e serveur :
  // { id: 'heloufCreatif', name: 'HeloufCréatif', description: 'Serveur créatif', icon: '🏗️', port: 50001 },
];

// État de chaque serveur
const serverStates = {};
SERVERS.forEach(s => {
  serverStates[s.id] = { status: 'stopped', requested_by: null, updated_at: new Date().toISOString() };
});

// Accès des users aux serveurs : { userId: ['heloufSMP', ...] }
const userServerAccess = {};

const envUser = process.env.ADMIN_USER;
const envPass = process.env.ADMIN_PASS;
if (envUser && envPass) {
  users.push({ id: 1, username: envUser, password: bcrypt.hashSync(envPass, 10), is_admin: 1, permissions: {} });
  console.log(`✅ Admin "${envUser}" créé !`);
}

// ── Auth ──────────────────────────────────────────────────────
function auth(req, res, next) {
  try {
    req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], SECRET);
    next();
  } catch { res.status(401).json({ error: 'Token invalide' }); }
}

function adminOnly(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Accès refusé' });
  next();
}

function hasServerAccess(userId, serverId) {
  const user = users.find(u => u.id === userId);
  if (!user) return false;
  if (user.is_admin) return true;
  return (userServerAccess[userId] || []).includes(serverId);
}

// ── Login ─────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, SECRET, { expiresIn: '24h' });
  res.json({ token, username: user.username, is_admin: user.is_admin });
});

// ── Serveurs ──────────────────────────────────────────────────
// Liste des serveurs accessibles pour l'utilisateur
app.get('/api/servers', auth, (req, res) => {
  const accessible = SERVERS.filter(s => hasServerAccess(req.user.id, s.id));
  const result = accessible.map(s => ({
    ...s,
    state: serverStates[s.id]
  }));
  res.json(result);
});

// Status d'un serveur
app.get('/api/servers/:id/status', auth, (req, res) => {
  const { id } = req.params;
  if (!hasServerAccess(req.user.id, id)) return res.status(403).json({ error: 'Accès refusé' });
  const server = SERVERS.find(s => s.id === id);
  if (!server) return res.status(404).json({ error: 'Serveur introuvable' });
  res.json({ ...serverStates[id], logs: consoleLogs.slice(-50), server });
});

// Actions sur un serveur
function serverAction(action) {
  return (req, res) => {
    const { id } = req.params;
    if (!hasServerAccess(req.user.id, id)) return res.status(403).json({ error: 'Accès refusé' });
    const state = serverStates[id];
    if (!state) return res.status(404).json({ error: 'Serveur introuvable' });

    const user = users.find(u => u.id === req.user.id);
    const perms = user?.permissions || {};

    if (action === 'start') {
      if (!req.user.is_admin && !perms.can_start) return res.status(403).json({ error: 'Permission refusée' });
      if (state.status !== 'stopped') return res.status(409).json({ error: `Serveur déjà : ${state.status}` });
      serverStates[id] = { status: 'starting', requested_by: req.user.username, updated_at: new Date().toISOString() };
    } else if (action === 'stop') {
      if (!req.user.is_admin && !perms.can_stop) return res.status(403).json({ error: 'Permission refusée' });
      if (state.status !== 'running') return res.status(409).json({ error: 'Serveur pas en ligne' });
      serverStates[id] = { status: 'stopping', requested_by: req.user.username, updated_at: new Date().toISOString() };
    } else if (action === 'restart') {
      if (!req.user.is_admin && !perms.can_restart) return res.status(403).json({ error: 'Permission refusée' });
      if (state.status !== 'running') return res.status(409).json({ error: 'Serveur pas en ligne' });
      serverStates[id] = { status: 'restarting', requested_by: req.user.username, updated_at: new Date().toISOString() };
    } else if (action === 'fix') {
      if (!req.user.is_admin && !perms.can_fix) return res.status(403).json({ error: 'Permission refusée' });
      serverStates[id] = { status: 'fixing', requested_by: req.user.username, updated_at: new Date().toISOString() };
    }

    res.json({ success: true, message: `Action ${action} envoyée !` });
  };
}

app.post('/api/servers/:id/start',   auth, serverAction('start'));
app.post('/api/servers/:id/stop',    auth, serverAction('stop'));
app.post('/api/servers/:id/restart', auth, serverAction('restart'));
app.post('/api/servers/:id/fix',     auth, serverAction('fix'));

// Upload plugin
app.post('/api/servers/:id/upload-plugin', auth, adminOnly, upload.single('plugin'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier' });
  pendingPlugins.push({
    serverId: req.params.id,
    name: req.file.originalname,
    data: req.file.buffer.toString('base64'),
    uploaded_by: req.user.username,
  });
  res.json({ success: true, message: `Plugin "${req.file.originalname}" en attente !` });
});

// ── Agent ─────────────────────────────────────────────────────
app.get('/api/agent/poll', (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  res.json({ servers: serverStates, pending_plugins: pendingPlugins });
});

app.post('/api/agent/confirm', (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  const { serverId, status } = req.body;
  if (!['running', 'stopped'].includes(status)) return res.status(400).json({ error: 'Statut invalide' });
  if (serverStates[serverId]) {
    serverStates[serverId].status = status;
    serverStates[serverId].updated_at = new Date().toISOString();
  }
  res.json({ success: true });
});

app.post('/api/agent/logs', (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  consoleLogs = req.body.logs || [];
  res.json({ success: true });
});

app.post('/api/agent/plugin-installed', (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  pendingPlugins = pendingPlugins.filter(p => p.name !== req.body.name);
  res.json({ success: true });
});

// ── Admin users ───────────────────────────────────────────────
app.post('/api/admin/create-user', auth, adminOnly, (req, res) => {
  const { username, password, is_admin = 0, permissions = {}, serverAccess = [] } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  if (users.find(u => u.username === username)) return res.status(409).json({ error: 'Nom déjà pris' });
  const id = users.length + 1;
  users.push({ id, username, password: bcrypt.hashSync(password, 10), is_admin: is_admin ? 1 : 0, permissions });
  userServerAccess[id] = serverAccess;
  res.json({ success: true, message: `Compte "${username}" créé !` });
});

app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  res.json(users.map(u => ({
    id: u.id, username: u.username, is_admin: u.is_admin,
    permissions: u.permissions,
    serverAccess: userServerAccess[u.id] || []
  })));
});

app.patch('/api/admin/users/:id/permissions', auth, adminOnly, (req, res) => {
  const user = users.find(u => u.id == req.params.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  user.permissions = req.body.permissions || {};
  userServerAccess[user.id] = req.body.serverAccess || userServerAccess[user.id] || [];
  res.json({ success: true, message: 'Permissions sauvegardées !' });
});

app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const idx = users.findIndex(u => u.id == req.params.id);
  if (idx !== -1) users.splice(idx, 1);
  res.json({ success: true });
});

app.get('/api/admin/servers', auth, adminOnly, (req, res) => {
  res.json(SERVERS);
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));
