const express = require('express');
const rateLimit = require('express-rate-limit');
const { roundAt, defaultChainInfo } = require('tlock-js');
const Secret = require('../models/Secret');
const auth = require('../middleware/auth');

const router = express.Router();
router.use(auth);
const relockLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

function getAccessMode(secret) {
  return secret.lockAt ? 'lock' : 'unlock';
}

function isAccessible(secret, now = Date.now()) {
  if (secret.lockAt && secret.unlockAt) {
    return now < secret.lockAt.getTime() || now >= secret.unlockAt.getTime();
  }
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
  const hasDrandRound = drandRound !== undefined;
  const hasLockAt = Boolean(lockAt);
  const hasUnlockAt = Boolean(unlockAt);
  if (!hasLockAt && !hasUnlockAt) {
    return res.status(400).json({ error: 'provide unlockAt or lockAt' });
  }
  if (hasUnlockAt && !hasLockAt && !iv && !drandRound) {
    return res.status(400).json({ error: 'need iv (legacy) or drandRound (tlock)' });
  }
  if (hasLockAt && (!iv || hasDrandRound)) {
    return res.status(400).json({ error: 'lockAt secrets must use AES-GCM ciphertext with an iv only' });
  }
  const now = Date.now();
  const lockDate = hasLockAt ? new Date(lockAt) : null;
  const unlockDate = hasUnlockAt ? new Date(unlockAt) : null;
  if (lockDate && Number.isNaN(lockDate.getTime())) return res.status(400).json({ error: 'bad lockAt' });
  if (unlockDate && Number.isNaN(unlockDate.getTime())) return res.status(400).json({ error: 'bad unlockAt' });
  if (lockDate && lockDate.getTime() <= now) {
    return res.status(400).json({ error: 'lockAt must be in the future' });
  }
  if (unlockDate && unlockDate.getTime() <= now) {
    return res.status(400).json({ error: 'unlockAt must be in the future' });
  }
  if (lockDate && unlockDate && unlockDate.getTime() <= lockDate.getTime()) {
    return res.status(400).json({ error: 'unlockAt must be later than lockAt' });
  }

  const secret = await Secret.create({
    userId: req.userId,
    label,
    ciphertext,
    iv,
    drandRound,
    unlockAt: unlockDate || undefined,
    lockAt: lockDate || undefined,
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

// replace an accessible unlock-later secret with a newly timelocked copy.
router.post('/:id/relock', relockLimiter, async (req, res) => {
  const {
    label, ciphertext, drandRound, unlockAt,
  } = req.body || {};
  if (!label || !ciphertext || !unlockAt) {
    return res.status(400).json({ error: 'missing fields' });
  }
  if (!Number.isInteger(drandRound) || drandRound <= 0) {
    return res.status(400).json({ error: 'bad drandRound' });
  }
  const unlockDate = new Date(unlockAt);
  if (Number.isNaN(unlockDate.getTime())) return res.status(400).json({ error: 'bad unlockAt' });
  if (unlockDate.getTime() <= Date.now()) {
    return res.status(400).json({ error: 'unlockAt must be in the future' });
  }
  if (drandRound !== roundAt(unlockDate.getTime(), defaultChainInfo)) {
    return res.status(400).json({ error: 'invalid drand round for the specified unlock time' });
  }

  const existing = await Secret.findOne({ _id: req.params.id, userId: req.userId });
  if (!existing) return res.status(404).json({ error: 'not found' });
  if (!existing.unlockAt) return res.status(400).json({ error: 'only unlock-later secrets can be re-locked' });
  if (!isAccessible(existing)) {
    return res.status(403).json({
      error: 'secret is currently locked and cannot be re-locked until it becomes accessible',
      unlockAt: existing.unlockAt,
    });
  }

  const replacement = await Secret.create({
    userId: req.userId,
    label,
    ciphertext,
    drandRound,
    unlockAt: unlockDate,
  });

  try {
    await existing.deleteOne();
  } catch (err) {
    await replacement.deleteOne().catch((cleanupErr) => {
      console.error(`failed to clean up replacement secret ${replacement._id}:`, cleanupErr.message);
    });
    return res.status(500).json({
      error: 'failed to delete original secret; the re-locked version has been removed to maintain consistency',
    });
  }

  res.json({ ok: true, id: replacement._id });
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
  if (Number.isNaN(newDate.getTime())) return res.status(400).json({ error: 'bad scheduleAt' });
  const s = await Secret.findOne({ _id: req.params.id, userId: req.userId });
  if (!s) return res.status(404).json({ error: 'not found' });
  if (s.lockAt) {
    if (s.lockAt.getTime() <= Date.now()) {
      return res.status(400).json({ error: 'cannot extend an already locked secret' });
    }
    if (newDate.getTime() <= s.lockAt.getTime()) {
      return res.status(400).json({ error: 'new lock time must be later than current' });
    }
    if (s.unlockAt && newDate.getTime() >= s.unlockAt.getTime()) {
      return res.status(400).json({ error: 'new lock time must be earlier than unlock time' });
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
