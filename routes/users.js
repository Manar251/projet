const express = require('express');
const router = express.Router();
const db = require('../models/db');
const bcrypt = require('bcryptjs');

// Inscription utilisateur
router.post('/inscription', async (req, res) => {
  const {
    type_utilisateur,
    email,
    nom,
    prenom,
    date,
    sexe,
    etablissement,
    filiere,
    password
  } = req.body;

  // Validation des champs obligatoires
  if (!type_utilisateur  !email  !nom  !prenom  !date || !password) {
    return res.status(400).json({ error: 'Veuillez remplir tous les champs obligatoires' });
  }

  try {
    // Vérifier si l'email existe déjà
    const [existingUser] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ error: 'Cet email est déjà utilisé' });
    }

    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insérer l'utilisateur dans la base de données
    const [result] = await db.promise().query(
      'INSERT INTO users (type, email, nom, prenom, date_naissance, etablissement, filiere, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [type_utilisateur, email, nom, prenom, date, etablissement, filiere, hashedPassword]
    );

    res.json({ 
      success: true,
      message: 'Inscription réussie',
      userId: result.insertId
    });
  } catch (err) {
    console.error("Erreur d'inscription:", err);
    res.status(500).json({ error: 'Erreur lors de l'inscription' });
  }
});

module.exports = router;