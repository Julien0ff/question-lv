const fs = require('fs');
const path = require('path');
const { v4: uuidv4, validate: uuidValidate } = require('uuid');
const { query } = require('../db');

async function run() {
  try {
    const usersPath = path.resolve(__dirname, '..', 'data', 'users.json');
    if (!fs.existsSync(usersPath)) {
      console.error('[migrate_users] Fichier introuvable:', usersPath);
      process.exit(1);
    }
    const raw = fs.readFileSync(usersPath, 'utf-8');
    const users = JSON.parse(raw);
    if (!Array.isArray(users)) {
      console.error('[migrate_users] Le JSON doit être un tableau d\'utilisateurs');
      process.exit(1);
    }

    let count = 0;
    for (const u of users) {
      const id = (u.id && uuidValidate(u.id)) ? u.id : uuidv4();
      const username = u.username;
      const passwordHash = u.passwordHash; // déjà hashé côté JSON
      const role = u.role || 'teacher';
      const subject = u.subject || '';
      if (!username || !passwordHash) {
        console.warn(`[migrate_users] Utilisateur ignoré (username/password manquant): ${JSON.stringify(u)}`);
        continue;
      }
      // Upsert basé sur username (doit être UNIQUE en DB)
      await query(
        `INSERT INTO users(id, username, password_hash, role, subject)
         VALUES($1,$2,$3,$4,$5)
         ON CONFLICT (username) DO UPDATE SET
           id=EXCLUDED.id,
           password_hash=EXCLUDED.password_hash,
           role=EXCLUDED.role,
           subject=EXCLUDED.subject`,
        [id, username, passwordHash, role, subject]
      );
      count++;
    }
    console.log(`[migrate_users] Import terminé: ${count} utilisateur(s) migré(s)`);
    process.exit(0);
  } catch (e) {
    console.error('[migrate_users] Erreur:', e);
    process.exit(1);
  }
}

run();

