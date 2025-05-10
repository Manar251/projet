const express = require('express');
const router = express.Router();
const db = require('../models/db');

// Add exam
router.post('/ajouter', (req, res) => {
  const { titre, description, publicCible } = req.body;
  
  if (!titre || !description || !publicCible) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  const lien_unique = `exam-${Date.now()}`;

  db.query(
    'INSERT INTO exams (titre, description, classe_cible, lien_unique) VALUES (?, ?, ?, ?)',
    [titre, description, publicCible, lien_unique],
    (err, result) => {
      if (err) {
        console.error("SQL error:", err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ 
        success: true, 
        id: result.insertId, 
        lien: lien_unique 
      });
    }
  );
});

// List exams
router.get('/liste', (req, res) => {
  db.query('SELECT * FROM exams', (err, results) => {
    if (err) {
      console.error("SQL error:", err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ success: true, data: results });
  });
});

// Delete exam
router.delete('/supprimer/:id', (req, res) => {
  const examId = req.params.id;
  db.query('DELETE FROM exams WHERE id = ?', [examId], (err, result) => {
    if (err) {
      console.error("SQL error:", err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ success: true });
  });
});

module.exports = router;


