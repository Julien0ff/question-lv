const express = require('express');
const session = require('express-session');
const PGSession = require('connect-pg-simple')(session);
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const fsp = fs.promises;
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';
// Active la couche DB Neon si DATABASE_URL est défini
const useDb = !!process.env.DATABASE_URL;
let db = null;
try {
  if (useDb) {
    db = require('./db');
    console.log('[DB] Neon/Postgres activé');
  }
} catch (e) {
  console.warn('[DB] Impossible de charger db.js, fallback JSON:', e && e.message);
}

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

// Configure session store (Postgres in production when DATABASE_URL is set)
const sessionOptions = {
  secret: process.env.SESSION_SECRET || 'lunaverse-schoolrp-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60, sameSite: isProd ? 'none' : 'lax', secure: isProd }
};

try {
  if (useDb && db && db.pool) {
    sessionOptions.store = new PGSession({
      pool: db.pool,
      tableName: 'session',
      createTableIfMissing: true
    });
    console.log('[Session] connect-pg-simple store configuré (Postgres)');
  } else {
    console.warn('[Session] MemoryStore utilisé (sans DB)');
  }
} catch (e) {
  console.warn('[Session] Impossible de configurer le store Postgres, fallback MemoryStore:', e && e.message);
}

app.use(session(sessionOptions));

app.get('/api/questions', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  console.log('API /api/questions called for userId:', userId);
  const results = await readJson(resultsFile);
  const already = results.find(r => r.userId === userId);
  console.log('Value of already:', already);
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

app.get('/api/form/questions/:formId', requireAuth, async (req, res) => {
  const { formId } = req.params;
  const userId = req.session.user.id;
  console.log(`API /api/form/questions/${formId} called for userId:`, userId);

  let form = null;
  try {
    if (useDb && db) {
      const rows = await db.query('SELECT id, subject, title, description, questions FROM forms WHERE id=$1', [formId]);
      form = rows[0] || null;
    } else {
      const forms = await readJson(formsFile);
      form = forms.find(f => f.id === formId) || null;
    }
  } catch (e) {
    console.error('Erreur chargement formulaire:', e);
    return res.status(500).json({ error: 'Erreur serveur lors du chargement du formulaire' });
  }

  if (!form) {
    return res.status(404).json({ error: 'Formulaire non trouvé.' });
  }

  // Check if user has already completed this form
  try {
    if (useDb && db) {
      const rows = await db.query('SELECT 1 FROM form_results WHERE user_id=$1 AND form_id=$2 LIMIT 1', [userId, formId]);
      if ((rows && rows.length) || (rows && rows.rowCount > 0)) {
        return res.status(400).json({ error: 'Vous avez déjà complété ce formulaire.', status: 'done' });
      }
    } else {
      const results = await readJson(formResultsFile);
      const alreadyCompleted = (results || []).find(r => r.userId === userId && r.formId === formId);
      if (alreadyCompleted) {
        return res.status(400).json({ error: 'Vous avez déjà complété ce formulaire.', status: alreadyCompleted.status || 'done' });
      }
    }
  } catch (e) {
    console.error('Erreur vérification duplicat formulaire:', e);
    // Continuer quand même (optionnel) ou renvoyer une erreur générique
  }

  req.session.currentTest = { formId: form.id, questionIds: (form.questions || []).map(q => q.id), startedAt: Date.now(), violated: false };
  res.json({ questions: form.questions || [] });
});

// Serve static files


// Paths for JSON DB
// Permet de configurer le répertoire des données via une variable d'environnement
// Exemple: sur Render, définir DATA_DIR=/opt/render/project/src/data
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
const usersFile = path.join(dataDir, 'users.json');
const questionsFile = path.join(dataDir, 'questions.json');
const resultsFile = path.join(dataDir, 'results.json');
const formsFile = path.join(dataDir, 'forms.json');
const formResultsFile = path.join(dataDir, 'form_results.json');

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
  try { await fsp.access(formsFile); } catch {
    const sampleForms = [
      { id: 'form-aptitude-french', subject: 'français', title: 'Formulaire d\'aptitude professionnelle', description: 'Test initial d\'aptitude pour l\'enseignement de français.', questions: [{ id: 'q-apt-1', type: 'text', prompt: 'Conjuguez le verbe être au passé composé.', correctAnswer: 'j\'ai été' }] },
      { id: 'form-english-1', subject: 'anglais', title: 'Formulaire Anglais Niveau I', description: 'Niveau débutant en anglais.', questions: [{ id: 'q-eng-1', type: 'text', prompt: 'Traduisez "bonjour" en anglais.', correctAnswer: 'hello' }] },
      { id: 'form-english-2', subject: 'anglais', title: 'Formulaire Anglais Niveau II', description: 'Niveau intermédiaire 1 en anglais.', questions: [{ id: 'q-eng-2', type: 'text', prompt: 'Traduisez "au revoir" en anglais.', correctAnswer: 'goodbye' }] },
      { id: 'form-english-3', subject: 'anglais', title: 'Formulaire Anglais Niveau III', description: 'Niveau intermédiaire 2 en anglais.', questions: [{ id: 'q-eng-3', type: 'text', prompt: 'Traduisez "merci" en anglais.', correctAnswer: 'thank you' }] },
      { id: 'form-english-4', subject: 'anglais', title: 'Formulaire Anglais Niveau IIII', description: 'Niveau avancé en anglais.', questions: [{ id: 'q-eng-4', type: 'text', prompt: 'Traduisez "s\'il vous plaît" en anglais.', correctAnswer: 'please' }] }
    ];
    await fsp.writeFile(formsFile, JSON.stringify(sampleForms, null, 2));
  }
  try { await fsp.access(formResultsFile); } catch {
    await fsp.writeFile(formResultsFile, JSON.stringify([], null, 2));
  }}

async function readJson(file) {
  const data = await fsp.readFile(file, 'utf8');
  return JSON.parse(data || '[]');
}
async function writeJson(file, content) {
  await fsp.writeFile(file, JSON.stringify(content, null, 2));
}

async function ensureDefaultAdmin() {
  try {
    if (useDb && db) {
      const rows = await db.query('SELECT id FROM users WHERE role=$1 LIMIT 1', ['admin']);
      if (!rows || rows.length === 0) {
        const id = uuidv4();
        const hash = await bcrypt.hash('admin123', 10);
        await db.query('INSERT INTO users(id, username, password_hash, role, subject) VALUES($1,$2,$3,$4,$5)', [id, 'admin', hash, 'admin', 'general']);
        console.log('Admin par défaut créé en DB: login \"admin\" / mdp \"admin123\"');
      }
      return;
    }
  } catch (e) {
    console.warn('ensureDefaultAdmin DB error, fallback JSON:', e && e.message);
  }

  const users = await readJson(usersFile);
  const hasAdmin = users.some(u => u.role === 'admin');
  if (!hasAdmin) {
    const hash = await bcrypt.hash('admin123', 10);
    users.push({ id: uuidv4(), username: 'admin', passwordHash: hash, role: 'admin', subject: 'general' });
    await writeJson(usersFile, users);
    console.log('Admin par défaut créé (JSON): login \"admin\" / mdp \"admin123\"');
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
  // DB d'abord si disponible, sinon JSON
  if (useDb && db) {
    try {
      const rows = await db.query('SELECT id, username, password_hash AS "passwordHash", role, subject FROM users WHERE username=$1', [username]);
      const user = rows[0];
      if (!user) return res.status(401).json({ error: 'Utilisateur introuvable' });
      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) return res.status(401).json({ error: 'Mot de passe incorrect' });
      req.session.user = { id: user.id, username: user.username, role: user.role, subject: user.subject };
      return res.json({ ok: true, user: req.session.user });
    } catch (e) {
      console.error('[DB] /api/login erreur, fallback JSON:', e);
    }
  }
  try {
    const users = await readJson(usersFile);
    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).json({ error: 'Utilisateur introuvable' });
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Mot de passe incorrect' });
    req.session.user = { id: user.id, username: user.username, role: user.role, subject: user.subject };
    res.json({ ok: true, user: req.session.user });
  } catch (e) {
    console.error('[JSON] /api/login erreur:', e);
    res.status(500).json({ error: 'Erreur serveur lors de la connexion' });
  }
});
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});
app.get('/api/check-auth', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Non authentifié' });
  }
  res.json(req.session.user);
});

// Test routes
const PASS_THRESHOLD = 0.5; // moyenne 50%
// Nombre de questions fixé à 15
function randomQuestionCount() {
  return 20;
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



app.post('/api/visibility-violation', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  req.session.currentTest = req.session.currentTest || {};
  req.session.currentTest.violated = true;
  const results = await readJson(resultsFile);
  const existing = results.find(r => r.userId === userId);
  if (!existing) {
    const outOf = (req.session.currentTest && Array.isArray(req.session.currentTest.questionIds))
      ? req.session.currentTest.questionIds.length
      : 20; // fallback à 15 pour éviter 0/0
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
  const record = { id: uuidv4(), formId: 'base-form', title: 'Formulaire d\'aptitude professionnelle', subject: 'Général', userId, status, score: avg, scorePoints, scoreOutOf: total, scoreOn20, answers, date: new Date().toISOString() };
  try {
    if (useDb && db) {
      await db.query(
        `INSERT INTO results(id, form_id, title, subject, user_id, status, score, score_points, score_out_of, score_on20, answers, date)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [record.id, record.formId, record.title, record.subject, record.userId, record.status, record.score, record.scorePoints, record.scoreOutOf, record.scoreOn20, JSON.stringify(record.answers), record.date]
      );
    } else {
      results.push(record);
      await writeJson(resultsFile, results);
    }
  } catch (e) {
    console.error('[DB] insert base-form results failed, fallback JSON:', e);
    try {
      const jsonResults = await readJson(resultsFile);
      jsonResults.push(record);
      await writeJson(resultsFile, jsonResults);
    } catch (e2) {
      console.error('[JSON] write base-form results failed:', e2);
      return res.status(500).json({ error: 'Impossible d\'enregistrer le résultat du test' });
    }
  }
  res.json({ ok: true, status, score: avg, scorePoints, scoreOutOf: total, scoreOn20 });
});



app.get('/api/user/progress', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  let record = null;
  try {
    if (useDb && db) {
      const rows = await db.query(
        `SELECT id, form_id AS "formId", title, subject, user_id AS "userId", status,
                score, score_points AS "scorePoints", score_out_of AS "scoreOutOf", score_on20 AS "scoreOn20", answers, date
         FROM results
         WHERE user_id=$1 AND form_id='base-form'
         ORDER BY date DESC LIMIT 1`, [userId]
      );
      record = rows[0] || null;
    } else {
      const results = await readJson(resultsFile);
      record = results.find(r => r.userId === userId) || null;
    }
  } catch (e) {
    console.error('[DB] /api/user/progress erreur, fallback JSON:', e);
    const results = await readJson(resultsFile);
    record = results.find(r => r.userId === userId) || null;
  }
  console.log(`[API/user/progress] userId: ${userId}, record: ${JSON.stringify(record)}, lastStatus: ${record ? record.status : null}`);
  const total = req.session.currentTest && Array.isArray(req.session.currentTest.questionIds) ? req.session.currentTest.questionIds.length : (record ? record.scoreOutOf || 0 : 0);
  const answered = (req.session.lastAnswers && req.session.lastAnswers.length) ? req.session.lastAnswers.length : (record ? total : 0);
  res.json({
    total,
    answered,
    remaining: Math.max(0, total - answered),
    lastStatus: record ? record.status : null,
    score: record ? record.score : null,
    scorePoints: record ? record.scorePoints : null,
    scoreOutOf: record ? record.scoreOutOf : null,
    scoreOn20: record ? record.scoreOn20 : null,
    // extra fields to allow teacher dashboard to display base-form as completed
    formId: record ? record.formId : 'base-form',
    title: record ? record.title : 'Formulaire d\'aptitude professionnelle',
    subject: record ? record.subject : 'Général',
    answers: record ? record.answers || [] : [],
    date: record ? record.date || null : null
  });
});

// Admin routes
app.get('/api/admin/users', requireAuth, requireRole('admin'), async (req, res) => {
  if (useDb && db) {
    try {
      const rows = await db.query(
        `SELECT u.id, u.username, u.role, u.subject,
                (
                  SELECT r.status FROM results r
                  WHERE r.user_id = u.id
                  ORDER BY r.date DESC LIMIT 1
                ) AS status
         FROM users u
         ORDER BY u.username ASC`
      );
      return res.json({ users: rows.map(r => ({ id: r.id, username: r.username, role: r.role, subject: r.subject || '', status: r.status || null })) });
    } catch (e) {
      console.error('[DB] /api/admin/users erreur, fallback JSON:', e);
    }
  }
  const users = await readJson(usersFile);
  const results = await readJson(resultsFile);
  const list = users.map(u => ({ id: u.id, username: u.username, role: u.role, adminNote: u.adminNote || '', status: (results.find(r => r.userId === u.id) || {}).status || null }));
  res.json({ users: list });
});

app.post('/api/admin/users', requireAuth, requireRole('admin'), async (req, res) => {
  const { username, password, role = 'teacher', subject = '' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username et password requis' });
  // Subject requis uniquement pour les professeurs
  if (String(role) === 'teacher' && !subject) return res.status(400).json({ error: 'subject requis pour les professeurs' });
  if (useDb && db) {
    try {
      const exists = await db.query('SELECT 1 FROM users WHERE username=$1', [username]);
      if (exists && exists.length) return res.status(400).json({ error: 'Utilisateur déjà existant' });
      const hash = await bcrypt.hash(password, 10);
      const id = uuidv4();
      await db.query('INSERT INTO users(id, username, password_hash, role, subject) VALUES($1,$2,$3,$4,$5)', [id, username, hash, role, subject]);
      return res.json({ ok: true, user: { id, username, role, subject } });
    } catch (e) {
      console.error('[DB] /api/admin/users POST erreur, fallback JSON:', e);
    }
  }
  const users = await readJson(usersFile);
  if (users.some(u => u.username === username)) return res.status(400).json({ error: 'Utilisateur déjà existant' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), username, passwordHash: hash, role, subject };
  users.push(user);
  await writeJson(usersFile, users);
  res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role, subject: user.subject } });
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
  // Si une base de données est configurée, supprimer depuis la DB
  if (useDb && db) {
    try {
      const exists = await db.query('SELECT id, username FROM users WHERE id=$1', [id]);
      if (exists && exists.length) {
        const removed = exists[0];
        await db.query('DELETE FROM results WHERE user_id=$1', [id]);
        await db.query('DELETE FROM users WHERE id=$1', [id]);
        return res.json({ ok: true, removed: { id: removed.id, username: removed.username } });
      }
      // Si non trouvé en DB, tenter la suppression dans le JSON
    } catch (e) {
      console.error('[DB] /api/admin/users DELETE erreur, fallback JSON:', e);
      // Fallback JSON si la suppression DB échoue
    }
  }
  const users = await readJson(usersFile);
  const idx = users.findIndex(u => u.id === id);
  if (idx !== -1) {
    const [removed] = users.splice(idx, 1);
    await writeJson(usersFile, users);
    const results = await readJson(resultsFile);
    const filtered = results.filter(r => r.userId !== id);
    await writeJson(resultsFile, filtered);
    return res.json({ ok: true, removed: { id: removed.id, username: removed.username } });
  }
  return res.status(404).json({ error: 'Utilisateur introuvable' });
});

app.get('/api/admin/results', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    if (useDb && db) {
      const rows = await db.query('SELECT id, form_id AS "formId", title, subject, user_id AS "userId", status, score, score_points AS "scorePoints", score_out_of AS "scoreOutOf", score_on20 AS "scoreOn20", answers, date FROM results ORDER BY date DESC');
      return res.json({ results: rows });
    }
    const results = await readJson(resultsFile);
    res.json({ results });
  } catch (e) {
    console.error('[DB] /api/admin/results erreur, fallback JSON:', e);
    const results = await readJson(resultsFile);
    res.json({ results });
  }
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


// Forms routes
app.get('/api/forms', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    if (useDb && db) {
      const rows = await db.query('SELECT id, subject, title, description, questions, created_at AS "createdAt" FROM forms ORDER BY created_at DESC');
      return res.json(rows.map(r => ({ id: r.id, subject: r.subject, title: r.title, description: r.description, questions: r.questions, createdAt: r.createdAt })));
    }
    const forms = await readJson(formsFile);
    res.json(forms);
  } catch (e) {
    console.error('Erreur lecture forms.json:', e);
    res.status(500).json({ error: 'Impossible de charger les formulaires' });
  }
});

app.get('/api/forms/subject/:subject', requireAuth, async (req, res) => {
  try {
    const { subject } = req.params;
    if (useDb && db) {
      const rows = await db.query('SELECT id, subject, title, description, questions, created_at AS "createdAt" FROM forms WHERE LOWER(subject)=LOWER($1) ORDER BY created_at DESC', [subject]);
      return res.json(rows.map(r => ({ id: r.id, subject: r.subject, title: r.title, description: r.description, questions: r.questions, createdAt: r.createdAt })));
    }
    const forms = await readJson(formsFile);
    const filteredForms = forms.filter(form => form.subject.toLowerCase() === subject.toLowerCase());
    console.log(`Forms for subject ${subject}:`, filteredForms);
    res.json(filteredForms);
  } catch (e) {
    console.error('Erreur lecture forms.json par matière:', e);
    res.status(500).json({ error: 'Impossible de charger les formulaires pour cette matière' });
  }
});

app.post('/api/forms', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { subject, title, description, questions } = req.body;
    if (!subject || !title || !questions) {
      return res.status(400).json({ error: 'Matière, titre et questions sont requis' });
    }
    if (!Array.isArray(questions)) {
      return res.status(400).json({ error: 'Le champ questions doit être un tableau JSON' });
    }
    const id = uuidv4();
    const createdAt = new Date().toISOString();
    const newForm = { id, subject, title, description, questions, createdAt };
    if (useDb && db) {
      await db.query('INSERT INTO forms(id, subject, title, description, questions, created_at) VALUES($1,$2,$3,$4,$5,$6)', [id, subject, title, description, questions, createdAt]);
      return res.status(201).json(newForm);
    }
    const forms = await readJson(formsFile);
    forms.push(newForm);
    await writeJson(formsFile, forms);
    res.status(201).json(newForm);
  } catch (e) {
    console.error('Erreur lors de la création du formulaire:', e);
    res.status(500).json({ error: 'Impossible de créer le formulaire' });
  }
});

// Mettre à jour un formulaire
app.put('/api/forms/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { subject, title, description, questions } = req.body;
    if (!subject || !title || !questions) {
      return res.status(400).json({ error: 'Matière, titre et questions sont requis' });
    }
    const updated = { id, subject, title, description, questions };
    if (useDb && db) {
      const rows = await db.query('UPDATE forms SET subject=$1, title=$2, description=$3, questions=$4 WHERE id=$5 RETURNING id, subject, title, description, questions, created_at AS "createdAt"', [subject, title, description, questions, id]);
      const form = rows[0] || null;
      if (!form) return res.status(404).json({ error: 'Formulaire introuvable' });
      return res.json(form);
    }
    const forms = await readJson(formsFile);
    const idx = forms.findIndex(f => f.id === id);
    if (idx === -1) return res.status(404).json({ error: 'Formulaire introuvable' });
    forms[idx] = { ...forms[idx], ...updated };
    await writeJson(formsFile, forms);
    res.json(forms[idx]);
  } catch (e) {
    console.error('Erreur lors de la mise à jour du formulaire:', e);
    res.status(500).json({ error: 'Impossible de mettre à jour le formulaire' });
  }
});

// Supprimer un formulaire
app.delete('/api/forms/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    if (useDb && db) {
      await db.query('DELETE FROM forms WHERE id=$1', [id]);
      return res.json({ ok: true });
    }
    const forms = await readJson(formsFile);
    const filtered = forms.filter(f => f.id !== id);
    await writeJson(formsFile, filtered);
    res.json({ ok: true });
  } catch (e) {
    console.error('Erreur lors de la suppression du formulaire:', e);
    res.status(500).json({ error: 'Impossible de supprimer le formulaire' });
  }
});

app.get('/api/forms/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (useDb && db) {
      const rows = await db.query('SELECT id, subject, title, description, questions, created_at AS "createdAt" FROM forms WHERE id=$1', [id]);
      const form = rows[0];
      if (!form) return res.status(404).json({ error: 'Formulaire introuvable' });
      return res.json(form);
    }
    const forms = await readJson(formsFile);
    const form = forms.find(f => f.id === id);
    if (!form) {
      return res.status(404).json({ error: 'Formulaire introuvable' });
    }
    res.json(form);
  } catch (e) {
    console.error('Erreur lecture forms.json par ID:', e);
    res.status(500).json({ error: 'Impossible de charger le formulaire' });
  }
});

app.get('/api/forms/results', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    if (useDb && db) {
      const rows = await db.query('SELECT id, user_id AS "userId", form_id AS "formId", subject, title, score_points AS "scorePoints", total_questions AS "totalQuestions", answers, date FROM form_results ORDER BY date DESC');
      return res.json(rows);
    }
    const results = await readJson(formResultsFile);
    res.json(results);
  } catch (e) {
    console.error('Erreur lecture form_results pour les formulaires:', e);
    res.status(500).json({ error: 'Impossible de charger les résultats des formulaires' });
  }
});

app.get('/api/teacher/forms/results', requireAuth, requireRole('teacher'), async (req, res) => {
  try {
    const userId = req.session.user.id;
    if (useDb && db) {
      const rows = await db.query(
        `SELECT id, user_id AS "userId", form_id AS "formId", subject, title, score_points AS "scorePoints", total_questions AS "totalQuestions", answers, date
         FROM form_results
         WHERE user_id=$1
         ORDER BY date DESC`, [userId]
      );
      return res.json(rows);
    }
    const allFormResults = await readJson(formResultsFile);
    const teacherFormResults = allFormResults.filter(result => result.userId === userId);
    res.json(teacherFormResults);
  } catch (e) {
    console.error('Erreur lors de la récupération des résultats de formulaire pour le professeur:', e);
    res.status(500).json({ error: 'Impossible de charger les résultats de formulaire pour le professeur' });
  }
});

// Nouvelle route pour récupérer les formulaires matière complétés (pour la section Progression)
app.get('/api/teacher/forms/subject-results', requireAuth, requireRole('teacher'), async (req, res) => {
  try {
    const teacherSubject = req.session.user && req.session.user.subject;
    // Si aucune matière n'est définie pour le professeur, retourner une liste vide plutôt que 500
    if (!teacherSubject || !String(teacherSubject).trim()) {
      return res.json([]);
    }
    if (useDb && db) {
      const rows = await db.query(
        `SELECT fr.id, fr.user_id AS "userId", fr.form_id AS "formId", fr.subject, fr.title,
                fr.score_points AS "scorePoints", fr.total_questions AS "totalQuestions", fr.answers, fr.date
         FROM form_results fr
         WHERE fr.form_id <> 'base-form' AND LOWER(fr.subject) = LOWER($1)
         ORDER BY fr.date DESC`, [teacherSubject]
      );
      return res.json(rows);
    }
    const allFormResults = await readJson(formResultsFile);
    const forms = await readJson(formsFile);
    const subjectFormResults = allFormResults.filter(result => {
      if (result.formId === 'base-form') return false;
      const form = forms.find(f => f.id === result.formId);
      return form && teacherSubject && form.subject && String(form.subject).toLowerCase() === String(teacherSubject).toLowerCase();
    });
    res.json(subjectFormResults);
  } catch (e) {
    console.error('Erreur lors de la récupération des résultats de formulaire matière:', e);
    res.status(500).json({ error: 'Impossible de charger les résultats de formulaire matière' });
  }
});

app.post('/api/forms/submit-subject-form', requireAuth, async (req, res) => {
  try {
    const { formId, answers } = req.body; // answers: [{id,type,selectedIndex}|{id,type,value}] ou {questionId,value}
    const userId = req.session.user.id;
    if (!formId || !answers) {
      return res.status(400).json({ error: 'ID du formulaire et réponses sont requis' });
    }
    let form = null;
    if (useDb && db) {
      const rows = await db.query('SELECT id, subject, title, questions FROM forms WHERE id=$1', [formId]);
      form = rows[0] || null;
    } else {
      const forms = await readJson(formsFile);
      form = forms.find(f => f.id === formId) || null;
    }
    if (!form) return res.status(404).json({ error: 'Formulaire introuvable' });

    // Scoring robuste pour mcq/text (aligné avec format questions)
    let scorePoints = 0;
    let totalQuestions = Array.isArray(form.questions) ? form.questions.length : 0;

  (answers || []).forEach(answer => {
    const qid = answer.questionId || answer.id;
    const question = (form.questions || []).find(q => q.id === qid);
    if (!question) return;
    if (question.type === 'mcq') {
      const normalizedCorrectIdx = typeof question.correctIndex === 'number'
        ? (question.correctIndex >= 1 ? question.correctIndex - 1 : question.correctIndex)
        : -1;
      const selectedIdx = (typeof answer.selectedIndex === 'number') ? answer.selectedIndex : -1;
      if (selectedIdx === normalizedCorrectIdx) scorePoints += 1;
    } else if (question.type === 'text') {
      // Supporter deux schémas possibles: "answer" ou "correctAnswer"
      const expected = normalizeText(question.answer || question.correctAnswer || '');
      const got = normalizeText(String(answer.value || ''));
      if (expected && got === expected) scorePoints += 1;
    }
  });

    const newResult = {
      id: uuidv4(),
      userId,
      formId,
      subject: form.subject,
      title: form.title,
      scorePoints,
      totalQuestions,
      answers,
      date: new Date().toISOString()
    };

    if (useDb && db) {
      await db.query(
        'INSERT INTO form_results(id, user_id, form_id, subject, title, score_points, total_questions, answers, date) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [newResult.id, newResult.userId, newResult.formId, newResult.subject, newResult.title, newResult.scorePoints, newResult.totalQuestions, JSON.stringify(newResult.answers), newResult.date]
      );
    } else {
      const allFormResults = await readJson(formResultsFile);
      allFormResults.push(newResult);
      await writeJson(formResultsFile, allFormResults);
    }

    res.status(201).json({ ok: true, result: newResult });

  } catch (e) {
    console.error('Erreur lors de la soumission du formulaire de matière:', e);
    res.status(500).json({ error: 'Impossible de soumettre le formulaire de matière' });
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
app.use(express.static(path.join(__dirname, 'public')));
// Expose les fichiers du répertoire data (utile pour vérification). À restreindre en prod si nécessaire
app.use('/data', express.static(dataDir));

(async () => {
  await ensureDataFiles();
  await ensureDefaultAdmin();

  app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));
})();
