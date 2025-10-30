const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const fsp = fs.promises;
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

// Fonction de normalisation tolérante pour les réponses texte
function normalizeText(text) {
  if (typeof text !== 'string') return '';
  return text
    .trim()
    .toLowerCase()
    .normalize('NFD') // Décompose les caractères accentués
    .replace(/[\u0300-\u036f]/g, '') // Supprime les accents
    .replace(/[^\w\s]/g, '') // Supprime la ponctuation
    .replace(/\s+/g, ' ') // Normalise les espaces
    .trim();
}

// Middlewares
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
if (isProd) app.set('trust proxy', 1);
app.use(session({
  secret: 'lunaverse-schoolrp-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60, sameSite: isProd ? 'none' : 'lax', secure: isProd } // 1h, cookies cross-site en prod
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Paths for JSON DB
const dataDir = path.join(__dirname, 'data');
const usersFile = path.join(dataDir, 'users.json');
const questionsFile = path.join(dataDir, 'questions.json');
const resultsFile = path.join(dataDir, 'results.json');

async function ensureDataFiles() {
  await fsp.mkdir(dataDir, { recursive: true });
  try { await fsp.access(usersFile); } catch {
    await fsp.writeFile(usersFile, JSON.stringify([], null, 2));
  }
  try { await fsp.access(questionsFile); } catch {
    const sampleQuestions = [
      { id: 'q1', type: 'mcq', prompt: 'Quelle est la capitale de la France ?', options: ['Lyon','Marseille','Paris','Toulouse'], correctIndex: 2 },
      { id: 'q2', type: 'mcq', prompt: '2 + 2 = ?', options: ['3','4','5','2'], correctIndex: 1 },
      { id: 'q3', type: 'mcq', prompt: 'Dans RP pédagogique, un professeur doit...', options: ['Ignorer les consignes','Respecter les règles','Donner des notes arbitraires','Être absent'], correctIndex: 1 },
      { id: 'q4', type: 'text', prompt: 'Citez une valeur clé de LunaVerse School RP (un mot).', answer: 'respect' },
      { id: 'q5', type: 'mcq', prompt: 'CSS sert principalement à...', options: ['Structurer le contenu','Styliser le contenu','Exécuter du backend','Gérer la base de données'], correctIndex: 1 },
      { id: 'q6', type: 'text', prompt: 'Quel est le langage côté client principal du web ?', answer: 'javascript' },
      { id: 'q7', type: 'mcq', prompt: 'Un QCM signifie...', options: ['Question à Choix Multiples','Question à Choix Uniques','Question Libre','Question Technique'], correctIndex: 0 },
      { id: 'q8', type: 'mcq', prompt: 'Pour évaluer un texte dans ce test...', options: ['On lit et juge subjectivement','On compare avec une réponse attendue','On ignore','On donne automatiquement 0'], correctIndex: 1 },
      { id: 'q9', type: 'mcq', prompt: 'Dans une évaluation, quitter l’onglet pendant le test est...', options: ['Autorisé','Toléré','Interdit','Obligatoire'], correctIndex: 2 },
      { id: 'q10', type: 'text', prompt: 'Écrivez \"LunaVerse\" sans les guillemets.', answer: 'lunaverse' },
      { id: 'q11', type: 'mcq', prompt: 'Le HTML sert à...', options: ['Styliser','Structurer','Programmer serveur','Compiler'], correctIndex: 1 },
      { id: 'q12', type: 'mcq', prompt: 'Dans une classe RP, le professeur...', options: ['Doit interrompre souvent','Doit encadrer de façon cohérente','Doit favoriser le chaos','Doit quitter le serveur'], correctIndex: 1 }
    ];
    await fsp.writeFile(questionsFile, JSON.stringify(sampleQuestions, null, 2));
  }
  try { await fsp.access(resultsFile); } catch {
    await fsp.writeFile(resultsFile, JSON.stringify([], null, 2));
  }
}

async function readJson(file) {
  const data = await fsp.readFile(file, 'utf8');
  return JSON.parse(data || '[]');
}
async function writeJson(file, content) {
  await fsp.writeFile(file, JSON.stringify(content, null, 2));
}

async function ensureDefaultAdmin() {
  const users = await readJson(usersFile);
  const hasAdmin = users.some(u => u.role === 'admin');
  if (!hasAdmin) {
    const hash = await bcrypt.hash('admin123', 10);
    users.push({ id: uuidv4(), username: 'admin', passwordHash: hash, role: 'admin' });
    await writeJson(usersFile, users);
    console.log('Admin par défaut créé: login \"admin\" / mdp \"admin123\"');
  }
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Non authentifié' });
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role) return res.status(403).json({ error: 'Accès refusé' });
    next();
  };
}

// Auth routes
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Identifiants requis' });
  const users = await readJson(usersFile);
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Utilisateur introuvable' });
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Mot de passe incorrect' });
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ ok: true, user: req.session.user });
});
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// Test routes
const PASS_THRESHOLD = 0.5; // moyenne 50%
// Nombre de questions fixé à 15
function randomQuestionCount() {
  return 15;
}
function pickRandom(arr, n) {
  const copy = arr.slice();
  const result = [];
  while (copy.length && result.length < n) {
    const idx = Math.floor(Math.random() * copy.length);
    result.push(copy.splice(idx, 1)[0]);
  }
  return result;
}

app.get('/api/questions', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const results = await readJson(resultsFile);
  const already = results.find(r => r.userId === userId);
  if (already) {
    const msgMap = {
      refused_exit_tab: "Refusé automatiquement (quitter l'onglet)",
      passed: 'Test déjà envoyé',
      failed: 'Test déjà envoyé'
    };
    return res.status(400).json({ error: msgMap[already.status] || 'Test déjà envoyé', status: already.status });
  }
  const questions = await readJson(questionsFile);
  const count = randomQuestionCount();
  const selected = pickRandom(questions, count);
  req.session.currentTest = { questionIds: selected.map(q => q.id), startedAt: Date.now(), violated: false };
  res.json({ questions: selected });
});

app.post('/api/visibility-violation', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  req.session.currentTest = req.session.currentTest || {};
  req.session.currentTest.violated = true;
  const results = await readJson(resultsFile);
  const existing = results.find(r => r.userId === userId);
  if (!existing) {
    const outOf = (req.session.currentTest && Array.isArray(req.session.currentTest.questionIds))
      ? req.session.currentTest.questionIds.length
      : 15; // fallback à 15 pour éviter 0/0
    results.push({ id: uuidv4(), userId, status: 'refused_exit_tab', score: 0, scorePoints: 0, scoreOutOf: outOf, scoreOn20: 0, answers: [], date: new Date().toISOString() });
    await writeJson(resultsFile, results);
  }
  res.json({ ok: true });
});

app.post('/api/submit', requireAuth, async (req, res) => {
  const { answers } = req.body; // [{id, type, value}] or {id, type, selectedIndex}
  const userId = req.session.user.id;
  const results = await readJson(resultsFile);
  const existing = results.find(r => r.userId === userId);
  if (existing) {
    const msgMap = {
      refused_exit_tab: "Refusé automatiquement (quitter l'onglet)",
    };
    return res.status(400).json({ error: msgMap[existing.status] || 'Test déjà envoyé', status: existing.status });
  }
  const violated = req.session.currentTest && req.session.currentTest.violated;
  const questions = await readJson(questionsFile);
  let scorePoints = 0;
  let total = req.session.currentTest && Array.isArray(req.session.currentTest.questionIds) ? req.session.currentTest.questionIds.length : (answers ? answers.length : 0);
  if (!total) total = 10; // fallback
  for (const ans of answers || []) {
    const q = questions.find(qq => qq.id === ans.id);
    if (!q) continue;
    if (q.type === 'mcq' && typeof ans.selectedIndex === 'number') {
      const correctIdx = typeof q.correctIndex === 'number'
        ? (q.correctIndex >= 1 ? q.correctIndex - 1 : q.correctIndex)
        : -1;
      if (ans.selectedIndex === correctIdx) scorePoints += 1;
    } else if (q.type === 'text' && typeof ans.value === 'string') {
      const expected = normalizeText(q.answer || '');
      const got = normalizeText(ans.value || '');
      if (expected && got === expected) scorePoints += 1;
    }
  }
  const avg = scorePoints / total;
  let status = violated ? 'refused_exit_tab' : (avg >= PASS_THRESHOLD ? 'passed' : 'failed');
  const scoreOn20 = Math.round((scorePoints / total) * 20);
  const record = { id: uuidv4(), userId, status, score: avg, scorePoints, scoreOutOf: total, scoreOn20, answers, date: new Date().toISOString() };
  results.push(record);
  await writeJson(resultsFile, results);
  res.json({ ok: true, status, score: avg, scorePoints, scoreOutOf: total, scoreOn20 });
});

app.get('/api/user/progress', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const results = await readJson(resultsFile);
  const record = results.find(r => r.userId === userId) || null;
  const total = req.session.currentTest && Array.isArray(req.session.currentTest.questionIds) ? req.session.currentTest.questionIds.length : (record ? record.scoreOutOf || 0 : 0);
  const answered = (req.session.lastAnswers && req.session.lastAnswers.length) ? req.session.lastAnswers.length : (record ? total : 0);
  res.json({ total, answered, remaining: Math.max(0, total - answered), lastStatus: record ? record.status : null, score: record ? record.score : null, scorePoints: record ? record.scorePoints : null, scoreOutOf: record ? record.scoreOutOf : null, scoreOn20: record ? record.scoreOn20 : null });
});

// Admin routes
app.get('/api/admin/users', requireAuth, requireRole('admin'), async (req, res) => {
  const users = await readJson(usersFile);
  const results = await readJson(resultsFile);
  const list = users.map(u => ({ id: u.id, username: u.username, role: u.role, adminNote: u.adminNote || '', status: (results.find(r => r.userId === u.id) || {}).status || null }));
  res.json({ users: list });
});

app.post('/api/admin/users', requireAuth, requireRole('admin'), async (req, res) => {
  const { username, password, role = 'teacher' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username et password requis' });
  const users = await readJson(usersFile);
  if (users.some(u => u.username === username)) return res.status(400).json({ error: 'Utilisateur déjà existant' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), username, passwordHash: hash, role };
  users.push(user);
  await writeJson(usersFile, users);
  res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/admin/users/:id/note', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { note = '' } = req.body || {};
  const users = await readJson(usersFile);
  const u = users.find(x => x.id === id);
  if (!u) return res.status(404).json({ error: 'Utilisateur introuvable' });
  u.adminNote = String(note);
  await writeJson(usersFile, users);
  res.json({ ok: true, user: { id: u.id, username: u.username, role: u.role, adminNote: u.adminNote } });
});
app.delete('/api/admin/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const users = await readJson(usersFile);
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const [removed] = users.splice(idx, 1);
  await writeJson(usersFile, users);
  const results = await readJson(resultsFile);
  const filtered = results.filter(r => r.userId !== id);
  await writeJson(resultsFile, filtered);
  res.json({ ok: true, removed: { id: removed.id, username: removed.username } });
});

app.get('/api/admin/results', requireAuth, requireRole('admin'), async (req, res) => {
  const results = await readJson(resultsFile);
  res.json({ results });
});

app.get('/api/admin/questions', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    console.log('[HIT] GET /api/admin/questions');
    const questions = await readJson(questionsFile);
    res.json(questions);
  } catch (e) {
    console.error('Erreur lecture questions.json:', e);
    res.status(500).json({ error: 'Impossible de charger les questions' });
  }
});

// Aliases for robustness
app.get('/api/admin/questions.json', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    console.log('[HIT] GET /api/admin/questions.json');
    const questions = await readJson(questionsFile);
    res.json(questions);
  } catch (e) {
    console.error('Erreur lecture questions.json:', e);
    res.status(500).json({ error: 'Impossible de charger les questions' });
  }
});

// Public route for questions (fallback for admin interface)
app.get('/data/questions.json', async (req, res) => {
  try {
    console.log('[HIT] GET /data/questions.json');
    const questions = await readJson(questionsFile);
    res.json(questions);
  } catch (error) {
    console.error('Erreur lors de la lecture des questions:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Public aliases
app.get('/data/questions', async (req, res) => {
  try {
    console.log('[HIT] GET /data/questions');
    const questions = await readJson(questionsFile);
    res.json(questions);
  } catch (error) {
    console.error('Erreur lors de la lecture des questions:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.get('/questions.json', async (req, res) => {
  try {
    console.log('[HIT] GET /questions.json');
    const questions = await readJson(questionsFile);
    res.json(questions);
  } catch (error) {
    console.error('Erreur lors de la lecture des questions:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.get('/questions', async (req, res) => {
  try {
    console.log('[HIT] GET /questions');
    const questions = await readJson(questionsFile);
    res.json(questions);
  } catch (error) {
    console.error('Erreur lors de la lecture des questions:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Cache answers in session (progress helper)
app.post('/api/user/answers-cache', requireAuth, (req, res) => {
  req.session.lastAnswers = req.body.answers || [];
  res.json({ ok: true });
});

// Debug: list registered routes (temporary)
app.get('/__debug/routes', (req, res) => {
  try {
    const routes = [];
    app._router.stack.forEach(mw => {
      if (mw.route && mw.route.path) {
        const methods = Object.keys(mw.route.methods || {}).join(',');
        routes.push({ path: mw.route.path, methods });
      }
    });
    res.json({ routes });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Serve data files statically (after API routes to avoid conflicts)
app.use('/data', express.static(path.join(__dirname, 'data')));

(async () => {
  await ensureDataFiles();
  await ensureDefaultAdmin();
  app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));
})();