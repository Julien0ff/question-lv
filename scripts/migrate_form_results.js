const fs = require('fs');
const path = require('path');
const { v4: uuidv4, validate: uuidValidate } = require('uuid');
const { query } = require('../db');

async function run() {
  try {
    const frPath = path.resolve(__dirname, '..', 'data', 'form_results.json');
    if (!fs.existsSync(frPath)) {
      console.error('[migrate_form_results] Fichier introuvable:', frPath);
      process.exit(1);
    }
    const raw = fs.readFileSync(frPath, 'utf-8');
    const results = JSON.parse(raw);
    if (!Array.isArray(results)) {
      console.error('[migrate_form_results] Le JSON doit être un tableau de résultats');
      process.exit(1);
    }

    // Mapping des IDs de formulaire (anciens → nouveaux UUIDs)
    const mapPath = path.resolve(__dirname, 'output', 'forms_id_map.json');
    const idMap = fs.existsSync(mapPath) ? JSON.parse(fs.readFileSync(mapPath, 'utf-8')) : {};
    let count = 0;
    let skipped = 0;

    for (const r of results) {
      const id = (r.id && uuidValidate(r.id)) ? r.id : uuidv4();
      const userId = r.userId;
      let formId = r.formId;
      if (!uuidValidate(formId)) {
        // Remap si possible via mapping
        if (idMap[formId]) {
          formId = idMap[formId];
        } else if (!uuidValidate(formId)) {
          console.warn(`[migrate_form_results] Résultat ignoré: formId non-UUID et aucun mapping trouvé (${formId})`);
          skipped++;
          continue;
        }
      }
      const subject = r.subject || '';
      const title = r.title || '';
      const scorePoints = r.scorePoints || 0;
      const totalQuestions = r.totalQuestions || 0;
      const answers = r.answers || [];
      const date = r.date || new Date().toISOString();

      await query(
        `INSERT INTO form_results(id, user_id, form_id, subject, title, score_points, total_questions, answers, date)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (id) DO NOTHING`,
        [id, userId, formId, subject, title, scorePoints, totalQuestions, JSON.stringify(answers), date]
      );
      count++;
    }
    console.log(`[migrate_form_results] Import terminé: ${count} résultat(s) migré(s), ${skipped} ignoré(s)`);
    process.exit(0);
  } catch (e) {
    console.error('[migrate_form_results] Erreur:', e);
    process.exit(1);
  }
}

run();

