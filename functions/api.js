const express = require('express');
const serverless = require('serverless-http');
const path = require('path');
const fs = require('fs').promises;
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');
const session = require('express-session');

// Importer le code du serveur existant
const app = express();

// Configuration des middlewares
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'votre_secret_de_session',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Définir les chemins des fichiers de données
const dataDir = path.join(__dirname, '..', 'data');
const usersFile = path.join(dataDir, 'users.json');
const questionsFile = path.join(dataDir, 'questions.json');
const resultsFile = path.join(dataDir, 'results.json');
const formsFile = path.join(dataDir, 'forms.json');
const formResultsFile = path.join(dataDir, 'form-results.json');

// Fonctions utilitaires
async function readJson(file) {
  try {
    const data = await fs.readFile(file, 'utf8');
    return JSON.parse(data || '[]');
  } catch (error) {
    console.error(`Erreur lors de la lecture du fichier ${file}:`, error);
    return [];
  }
}

async function writeJson(file, content) {
  try {
    await fs.writeFile(file, JSON.stringify(content, null, 2));
  } catch (error) {
    console.error(`Erreur lors de l'écriture du fichier ${file}:`, error);
  }
}

// Middleware d'authentification
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentification requise' });
  }
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || (role && req.session.user.role !== role)) {
      return res.status(403).json({ error: 'Accès non autorisé' });
    }
    next();
  };
}

// Route pour vérifier l'authentification
app.get('/api/check-auth', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Non authentifié' });
  }
  
  // Renvoyer les informations de l'utilisateur sans le mot de passe
  const { password, ...userInfo } = req.session.user;
  res.json(userInfo);
});

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role) {
      return res.status(403).json({ error: 'Accès non autorisé' });
    }
    next();
  };
}

// Importer toutes les routes de l'API depuis server.js
// Note: Vous devrez copier ici toutes les routes de votre server.js

// Routes d'authentification
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Nom d\'utilisateur et mot de passe requis' });
  }

  try {
    const users = await readJson(usersFile);
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    // Créer une session
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      subject: user.subject
    };

    res.json({
      id: user.id,
      username: user.username,
      role: user.role,
      subject: user.subject
    });
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({ error: 'Erreur serveur lors de la connexion' });
  }
});

// Ajoutez ici toutes les autres routes de votre API
// ...

// Exportation pour Netlify Functions
module.exports.handler = serverless(app);