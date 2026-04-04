const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const SECRET       = 'mcpanel_jwt_secret_2024';
const AGENT_SECRET = process.env.AGENT_SECRET || 'heloufSMP_secret_2024';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (req, res) => res.send('ok'));

const users = [];
let serverState = { status: 'stopped', requested_by: null, updated_at: new Date().toISOString() };
let consoleLogs = [];

const envUser = process.env.ADMIN_USER;
const envPass = process.env.ADMIN_PASS;
if (envUser && envPass) {
  users.push({ id: 1, username: envUser, password: bcrypt.hashSync(envPass, 10), is_admin: 1 });
  console.log(`✅ Admin "${envUser}" créé !`);
}

function auth(req, res, next) {
  try {
    req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], SECRET);
    next();
  } catch { res.status(401).json({ error: 'Token invalide' }); }
}

function admin(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Accès refusé' });
  next();
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, SECRET, { expiresIn: '24h' });
  res.json({ token, username: user.username, is_admin: user.is_admin });
});

app.get('/api/status', auth, (req, res) => res.json({ ...serverState, logs: consoleLogs.slice(-50) }));

app.post('/api/start', auth, (req, res) => {
  if (!['stopped'].includes(serverState.status))
    return res.status(409).json({ error: `Serveur déjà : ${serverState.status}` });
  serverState = { status: 'starting', requested_by: req.user.username, updated_at: new Date().toISOString() };
  res.json({ success: true, message: 'Démarrage demandé !' });
});

app.post('/api/stop', auth, (req, res) => {
  if (serverState.status !== 'running')
    return res.status(409).json({ error: 'Serveur pas en ligne' });
  serverState = { status: 'stopping', requested_by: req.user.username, updated_at: new Date().toISOString() };
  res.json({ success: true, message: 'Arrêt demandé !' });
});

app.post('/api/restart', auth, (req, res) => {
  if (serverState.status !== 'running')
    return res.status(409).json({ error: 'Serveur pas en ligne' });
  serverState = { status: 'restarting', requested_by: req.user.username, updated_at: new Date().toISOString() };
  res.json({ success: true, message: 'Restart demandé !' });
});

app.post('/api/fix', auth, (req, res) => {
  serverState = { status: 'fixing', requested_by: req.user.username, updated_at: new Date().toISOString() };
  res.json({ success: true, message: 'Fix demandé !' });
});

app.get('/api/agent/poll', (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  res.json(serverState);
});

app.post('/api/agent/confirm', (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  const { status } = req.body;
  if (!['running', 'stopped'].includes(status)) return res.status(400).json({ error: 'Statut invalide' });
  serverState.status = status;
  serverState.updated_at = new Date().toISOString();
  res.json({ success: true });
});

app.post('/api/agent/logs', (req, res) => {
  if (req.query.secret !== AGENT_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  consoleLogs = req.body.logs || [];
  res.json({ success: true });
});

app.post('/api/admin/create-user', auth, admin, (req, res) => {
  const { username, password, is_admin = 0 } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  if (users.find(u => u.username === username)) return res.status(409).json({ error: 'Nom déjà pris' });
  users.push({ id: users.length + 1, username, password: bcrypt.hashSync(password, 10), is_admin: is_admin ? 1 : 0 });
  res.json({ success: true, message: `Compte "${username}" créé !` });
});

app.get('/api/admin/users', auth, admin, (req, res) => {
  res.json(users.map(u => ({ id: u.id, username: u.username, is_admin: u.is_admin })));
});

app.delete('/api/admin/users/:id', auth, admin, (req, res) => {
  const idx = users.findIndex(u => u.id == req.params.id);
  if (idx !== -1) users.splice(idx, 1);
  res.json({ success: true });
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));
