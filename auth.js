const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

// signup: client sends email, salt (random, generated on client), authHash (derived from master pw)
router.post('/signup', async (req, res) => {
  const { email, salt, authHash } = req.body || {};
  if (!email || !salt || !authHash) return res.status(400).json({ error: 'missing fields' });

  const exists = await User.findOne({ email: email.toLowerCase() });
  if (exists) return res.status(409).json({ error: 'email already registered' });

  const authHashBcrypt = await bcrypt.hash(authHash, 12);
  const user = await User.create({ email, salt, authHashBcrypt });
  return res.json({ ok: true, userId: user._id });
});

// step 1 of login: client asks for its salt so it can derive the key
router.post('/salt', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'missing email' });
  const user = await User.findOne({ email: email.toLowerCase() });
  // do not leak whether the email exists; return a deterministic-looking salt anyway
  // (cheap mitigation; for a real product use a per-email derived dummy salt)
  if (!user) return res.json({ salt: 'AAAAAAAAAAAAAAAAAAAAAA==' });
  return res.json({ salt: user.salt });
});

// step 2: client sends authHash, server verifies, returns JWT
router.post('/login', async (req, res) => {
  const { email, authHash } = req.body || {};
  if (!email || !authHash) return res.status(400).json({ error: 'missing fields' });
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(authHash, user.authHashBcrypt);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  const token = jwt.sign({ sub: user._id.toString() }, process.env.JWT_SECRET, { expiresIn: '12h' });
  return res.json({ token });
});

module.exports = router;
