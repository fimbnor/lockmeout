const express = require('express');
const Secret = require('../models/Secret');
const auth = require('../middleware/auth');

const router = express.Router();
router.use(auth);

function getAccessMode(secret) {
  return secret.lockAt ? 'lock' : 'unlock';
}

function isAccessible(secret, now = Date.now()) {
  if (secret.lockAt) return secret.lockAt.getTime() > now;
  if (secret.unlockAt) return secret.unlockAt.getTime() <= now;
  return true;
}

// store an encrypted secret with either a future unlock time or lock time
router.post('/', async (req, res) => {
  const {
    label, ciphertext, iv, drandRound, unlockAt, lockAt,
  } = req.body || {};
  if (!label || !ciphertext) {
    return res.status(400).json({ error: 'missing fields' });
  }
  const hasDrandRound = Object.prototype.hasOwnProperty.call(req.body || {}, 'drandRound');
  const hasUnlockAt = Boolean(unlockAt);
  const hasLockAt = Boolean(lockAt);
  if (hasUnlockAt === hasLockAt) {
    return res.status(400).json({ error: 'provide exactly one of unlockAt or lockAt' });
  }
  if (hasUnlockAt && !iv && !drandRound) {
    return res.status(400).json({ error: 'need iv (legacy) or drandRound (tlock)' });
  }
  if (hasLockAt && (!iv || hasDrandRound)) {
    return res.status(400).json({ error: 'lockAt secrets must use AES-GCM ciphertext with an iv only' });
  }
  const scheduleField = hasLockAt ? 'lockAt' : 'unlockAt';
  const scheduleDate = new Date(hasLockAt ? lockAt : unlockAt);
  if (isNaN(scheduleDate.getTime())) return res.status(400).json({ error: `bad ${scheduleField}` });
  if (scheduleDate.getTime() <= Date.now()) {
    return res.status(400).json({ error: `${scheduleField} must be in the future` });
  }

  const secret = await Secret.create({
    userId: req.userId,
    label,
    ciphertext,
    iv,
    drandRound,
    unlockAt: hasUnlockAt ? scheduleDate : undefined,
    lockAt: hasLockAt ? scheduleDate : undefined,
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
    accessMode: getAccessMode(s),
    unlockAt: s.unlockAt,
    lockAt: s.lockAt,
    scheduleAt: s.lockAt || s.unlockAt,
    accessible: isAccessible(s, now),
    createdAt: s.createdAt,
    canRescheduleLater: Boolean(s.lockAt) && s.lockAt.getTime() > now,
  })));
});

// retrieve a single secret. server enforces the schedule here.
router.get('/:id', async (req, res) => {
  const s = await Secret.findOne({ _id: req.params.id, userId: req.userId });
  if (!s) return res.status(404).json({ error: 'not found' });
  if (!isAccessible(s)) {
    return res.status(403).json({
      error: 'locked',
      unlockAt: s.unlockAt,
      lockAt: s.lockAt,
      msRemaining: s.unlockAt ? s.unlockAt.getTime() - Date.now() : null,
    });
  }
  res.json({
    id: s._id, label: s.label, ciphertext: s.ciphertext, iv: s.iv,
    drandRound: s.drandRound, unlockAt: s.unlockAt, lockAt: s.lockAt,
  });
});

// postponing a future lock is allowed. tlock schedules must still be recreated.
router.patch('/:id/extend', async (req, res) => {
  const scheduleAt = req.body?.scheduleAt ?? req.body?.unlockAt;
  const newDate = new Date(scheduleAt);
  if (isNaN(newDate.getTime())) return res.status(400).json({ error: 'bad scheduleAt' });
  const s = await Secret.findOne({ _id: req.params.id, userId: req.userId });
  if (!s) return res.status(404).json({ error: 'not found' });
  if (s.lockAt) {
    if (s.lockAt.getTime() <= Date.now()) {
      return res.status(400).json({ error: 'cannot reschedule an already locked secret' });
    }
    if (newDate.getTime() <= s.lockAt.getTime()) {
      return res.status(400).json({ error: 'new lock time must be later than current' });
    }
    s.lockAt = newDate;
    await s.save();
    return res.json({ ok: true, lockAt: s.lockAt });
  }
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

// unlock-later secrets cannot be deleted before they unlock. lock-later secrets may be deleted any time.
router.delete('/:id', async (req, res) => {
  const s = await Secret.findOne({ _id: req.params.id, userId: req.userId });
  if (!s) return res.status(404).json({ error: 'not found' });
  if (s.unlockAt && s.unlockAt.getTime() > Date.now()) {
    return res.status(403).json({ error: 'cannot delete locked secret' });
  }
  await s.deleteOne();
  res.json({ ok: true });
});

module.exports = router;
