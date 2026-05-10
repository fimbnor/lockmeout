const express = require('express');
const Secret = require('../models/Secret');
const auth = require('../middleware/auth');

const router = express.Router();
router.use(auth);

// store an encrypted secret with an unlock time
router.post('/', async (req, res) => {
  const { label, ciphertext, iv, drandRound, unlockAt } = req.body || {};
  if (!label || !ciphertext || !unlockAt) {
    return res.status(400).json({ error: 'missing fields' });
  }
  if (!iv && !drandRound) {
    return res.status(400).json({ error: 'need iv (legacy) or drandRound (tlock)' });
  }
  const unlockDate = new Date(unlockAt);
  if (isNaN(unlockDate.getTime())) return res.status(400).json({ error: 'bad unlockAt' });
  if (unlockDate.getTime() <= Date.now()) {
    return res.status(400).json({ error: 'unlockAt must be in the future' });
  }
  const secret = await Secret.create({
    userId: req.userId, label, ciphertext, iv, drandRound, unlockAt: unlockDate,
  });
  res.json({ ok: true, id: secret._id });
});

// list secrets — metadata only, never ciphertext for locked items
router.get('/', async (req, res) => {
  const secrets = await Secret.find({ userId: req.userId }).sort({ createdAt: -1 });
  const now = Date.now();
  res.json(secrets.map(s => ({
    id: s._id,
    label: s.label,
    unlockAt: s.unlockAt,
    unlocked: s.unlockAt.getTime() <= now,
    createdAt: s.createdAt,
  })));
});

// retrieve a single secret. server enforces the time lock here.
router.get('/:id', async (req, res) => {
  const s = await Secret.findOne({ _id: req.params.id, userId: req.userId });
  if (!s) return res.status(404).json({ error: 'not found' });
  if (s.unlockAt.getTime() > Date.now()) {
    return res.status(403).json({
      error: 'locked',
      unlockAt: s.unlockAt,
      msRemaining: s.unlockAt.getTime() - Date.now(),
    });
  }
  res.json({
    id: s._id, label: s.label, ciphertext: s.ciphertext, iv: s.iv,
    drandRound: s.drandRound, unlockAt: s.unlockAt,
  });
});

// extending the lock is allowed. shortening is NOT — that's the whole point.
router.patch('/:id/extend', async (req, res) => {
  const { unlockAt } = req.body || {};
  const newDate = new Date(unlockAt);
  if (isNaN(newDate.getTime())) return res.status(400).json({ error: 'bad unlockAt' });
  const s = await Secret.findOne({ _id: req.params.id, userId: req.userId });
  if (!s) return res.status(404).json({ error: 'not found' });
  if (s.drandRound) {
    return res.status(400).json({
      error: 'cannot extend tlock-encrypted secret; reveal at unlock and re-create with later unlock time',
    });
  }
  if (newDate.getTime() <= s.unlockAt.getTime()) {
    return res.status(400).json({ error: 'new unlockAt must be later than current' });
  }
  s.unlockAt = newDate;
  await s.save();
  res.json({ ok: true, unlockAt: s.unlockAt });
});

// delete is only allowed if already unlocked. otherwise users would just delete to bypass.
router.delete('/:id', async (req, res) => {
  const s = await Secret.findOne({ _id: req.params.id, userId: req.userId });
  if (!s) return res.status(404).json({ error: 'not found' });
  if (s.unlockAt.getTime() > Date.now()) {
    return res.status(403).json({ error: 'cannot delete locked secret' });
  }
  await s.deleteOne();
  res.json({ ok: true });
});

module.exports = router;
