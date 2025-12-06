const fs = require('fs');
const path = require('path');
const { v4: uuidv4, validate: uuidValidate } = require('uuid');
const { query } = require('../db');

async function run() {
  try {
    const formsPath = path.resolve(__dirname, '..', 'data', 'forms.json');
    if (!fs.existsSync(formsPath)) {
      console.error('[migrate_forms] Fichier introuvable:', formsPath);
      process.exit(1);
    }
    const raw = fs.readFileSync(formsPath, 'utf-8');
    const forms = JSON.parse(raw);
    if (!Array.isArray(forms)) {
      console.error('[migrate_forms] Le JSON doit être un tableau de formulaires');
      process.exit(1);
    }

    let count = 0;
    const idMap = {};
    for (const f of forms) {
      const legacyId = f.id || null;
      const id = (legacyId && uuidValidate(legacyId)) ? legacyId : uuidv4();
      const subject = f.subject || 'general';
      const title = f.title || 'Sans titre';
      const description = f.description || null;
      const questions = f.questions || [];
      const questionsJson = JSON.stringify(questions);
      const createdAt = new Date().toISOString();
      await query(
        `INSERT INTO forms(id, subject, title, description, questions, created_at)
         VALUES($1,$2,$3,$4,$5,$6)
         ON CONFLICT (id) DO UPDATE SET
           subject=EXCLUDED.subject,
           title=EXCLUDED.title,
           description=EXCLUDED.description,
           questions=EXCLUDED.questions`,
        [id, subject, title, description, questionsJson, createdAt]
      );
      if (legacyId && legacyId !== id) {
        idMap[legacyId] = id;
      }
      count++;
    }
    // Écrit un mapping des anciens IDs vers les nouveaux UUID (si conversion)
    const outDir = path.resolve(__dirname, 'output');
    fs.mkdirSync(outDir, { recursive: true });
    const mapPath = path.join(outDir, 'forms_id_map.json');
    fs.writeFileSync(mapPath, JSON.stringify(idMap, null, 2));
    console.log(`[migrate_forms] Import terminé: ${count} formulaire(s) migré(s). Mapping écrit dans ${mapPath}`);
    process.exit(0);
  } catch (e) {
    console.error('[migrate_forms] Erreur:', e);
    process.exit(1);
  }
}

run();
