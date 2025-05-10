const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'ChangeThisSecret';  // change as needed

// — Connect to MongoDB —
mongoose.connect('mongodb://127.0.0.1:27017/exam_platform', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// — Define User schema & model —
const userSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true },
  nom:          { type: String, required: true },
  prenom:       { type: String, required: true },
  dob:          { type: Date,   required: true },
  sexe:         { type: String, enum: ['M','F'], required: true },
  etablissement:{ type: String, required: true },
  filiere:      { type: String, required: true },
  type:         { type: String, enum: ['enseignant','etudiant'], required: true },
  passwordHash: { type: String, required: true }
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

// — Middleware —
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname,'public')));

// — Auth middleware —
const authMiddleware = async (req, res, next) => {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ message:'Token manquant' });
  try {
    const payload = jwt.verify(h.slice(7), JWT_SECRET);
    const user = await User.findById(payload.id).select('-passwordHash');
    if (!user) throw new Error();
    req.user = user;
    next();
  } catch {
    res.status(401).json({ message:'Token invalide' });
  }
};

// — Page routes —
app.get('/',                    (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.get('/login/enseignant',    (req,res) => res.sendFile(path.join(__dirname,'public','connexion_enseignant.html')));
app.get('/login/etudiant',      (req,res) => res.sendFile(path.join(__dirname,'public','connexion_etudiant.html')));
app.get('/register/enseignant', (req,res) => res.sendFile(path.join(__dirname,'public','inscription_enseignant.html')));
app.get('/register/etudiant',   (req,res) => res.sendFile(path.join(__dirname,'public','inscription_etudiant.html')));
app.get('/app', authMiddleware, (req,res) => res.sendFile(path.join(__dirname,'public','espace_enseignant.html')));

// — API: Register —
app.post('/api/register', async (req, res) => {
  console.log('▶️ /api/register:', req.body);
  try {
    const { email, nom, prenom, dob, sexe, etablissement, filiere, type, password } = req.body;
    if (await User.findOne({ email })) {
      return res.status(400).json({ message:'Email déjà utilisé' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const user = new User({ email, nom, prenom, dob, sexe, etablissement, filiere, type, passwordHash });
    await user.save();
    console.log('✅ User created:', user.email);
    res.status(201).json({ message:'Inscription réussie' });
  } catch (err) {
    console.error('❌ Error in /api/register:', err);
    res.status(500).json({ message:'Erreur serveur' });
  }
});

// — API: Login —
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.passwordHash)) {
      return res.status(400).json({ message:'Email ou mot de passe incorrect' });
    }
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn:'24h' });
    res.json({
      token,
      user: {
        id: user._id,
        nom: user.nom,
        prenom: user.prenom,
        email: user.email,
        type: user.type
      }
    });
  } catch (err) {
    console.error('❌ Error in /api/login:', err);
    res.status(500).json({ message:'Erreur serveur' });
  }
});

// — API: current user —
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// — Start server —
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
