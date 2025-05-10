const express = require('express');
const router = express.Router();
const db = require('../models/db');

// Add question
router.post('/ajouter', (req, res) => {
  const { examen_id, type_question, enonce, reponse_directe, tolerance, note, duree, qcm_options } = req.body;

  // Insert question
  db.query(
    `INSERT INTO questions (exam_id, type, texte, reponse_correcte, tolerance, note, duree)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [examen_id, type_question, enonce, reponse_directe || null, tolerance || 0, note, duree],
    (err, result) => {
      if (err) {
        console.error("SQL error:", err);
        return res.status(500).json({ error: 'Database error' });
      }

      const questionId = result.insertId;

      // Handle QCM options
      if (type_question === 'qcm' && qcm_options?.length) {
        const values = qcm_options.map(opt => [questionId, opt.texte, opt.est_correct ? 1 : 0]);
        
        db.query(
          'INSERT INTO qcm_options (question_id, option_text, est_correct) VALUES ?',
          [values],
          (err) => {
            if (err) {
              console.error("QCM SQL error:", err);
              return res.status(500).json({ error: 'QCM options error' });
            }
            res.json({ success: true, questionId });
          }
        );
      } else {
        res.json({ success: true, questionId });
      }
    }
  );
});

module.exports = router;