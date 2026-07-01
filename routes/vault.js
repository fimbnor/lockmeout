const express = require('express');
const rateLimit = require('express-rate-limit');
const { roundAt, defaultChainInfo } = require('tlock-js');
const Secret = require('../models/Secret');
const auth = require('../middleware/auth');

const router = express.Router();
router.use(auth);
const relockLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
const MILLISECONDS_PER_WEEK = 7 * 24 * 60 * 60 * 1000;

function getAccessMode(secret) {
  return secret.lockAt || (Array.isArray(secret.weeklyLockSchedule) && secret.weeklyLockSchedule.length > 0) ? 'lock' : 'unlock';
}

function parseTimeToMinutes(time) {
  if (!/^\d{2}:\d{2}$/.test(time)) return null;
  const [hours, minutes] = time.split(':').map(Number);
  if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59) return null;
  return hours * 60 + minutes;
}

function isWithinWeeklyLockWindow(secret, now = Date.now()) {
  const schedule = secret.weeklyLockSchedule;
  if (!Array.isArray(schedule) || schedule.length === 0) return false;

  const offsetMinutes = Number(secret.scheduleTimezoneOffsetMinutes) || 0;
  const localNowMs = now - (offsetMinutes * 60 * 1000);

  if (!secret.repeatWeekly && secret.createdAt) {
    const localCreatedAt = new Date(secret.createdAt.getTime() - (offsetMinutes * 60 * 1000));
    const localWeekStartMs = Date.UTC(
      localCreatedAt.getUTCFullYear(),
      localCreatedAt.getUTCMonth(),
      localCreatedAt.getUTCDate() - localCreatedAt.getUTCDay()
    );
    if (localNowMs >= localWeekStartMs + MILLISECONDS_PER_WEEK) return false;
  }

  const localNow = new Date(localNowMs);
  const dayOfWeek = localNow.getUTCDay();
  const minutesNow = localNow.getUTCHours() * 60 + localNow.getUTCMinutes();

  return schedule.some((entry) => {
    const start = parseTimeToMinutes(entry.startTime);
    const end = parseTimeToMinutes(entry.endTime);
    if (start === null || end === null || start === end) return false;

    if (start < end) {
      return entry.dayOfWeek === dayOfWeek && minutesNow >= start && minutesNow < end;
    }

    const nextDay = (entry.dayOfWeek + 1) % 7;
    return (entry.dayOfWeek === dayOfWeek && minutesNow >= start)
      || (nextDay === dayOfWeek && minutesNow < end);
  });
}

function validateWeeklyLockSchedule(weeklyLockSchedule) {
  if (weeklyLockSchedule === undefined) return { ok: true };
  if (!Array.isArray(weeklyLockSchedule) || weeklyLockSchedule.length === 0) {
    return { ok: false, error: 'weeklyLockSchedule must contain at least one day' };
  }
  for (const item of weeklyLockSchedule) {
    if (!Number.isInteger(item?.dayOfWeek) || item.dayOfWeek < 0 || item.dayOfWeek > 6) {
      return { ok: false, error: 'bad weeklyLockSchedule dayOfWeek' };
    }
    const start = parseTimeToMinutes(item?.startTime);
    const end = parseTimeToMinutes(item?.endTime);
    if (start === null || end === null || start === end) {
      return { ok: false, error: 'bad weeklyLockSchedule time range' };
    }
  }
  return { ok: true };
}

function isAccessible(secret, now = Date.now()) {
  if (isWithinWeeklyLockWindow(secret, now)) return false;
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
    label, ciphertext, iv, drandRound, unlockAt, lockAt, weeklyLockSchedule, repeatWeekly, scheduleTimezoneOffsetMinutes,
  } = req.body || {};
  if (!label || !ciphertext) {
    return res.status(400).json({ error: 'missing fields' });
  }
  const hasDrandRound = drandRound !== undefined;
  const hasLockAt = Boolean(lockAt);
  const hasUnlockAt = Boolean(unlockAt);
  const hasWeeklySchedule = Array.isArray(weeklyLockSchedule) && weeklyLockSchedule.length > 0;
  if (!hasLockAt && !hasUnlockAt && !hasWeeklySchedule) {
    return res.status(400).json({ error: 'provide unlockAt, lockAt, or weeklyLockSchedule' });
  }
  if (hasUnlockAt && !hasLockAt && !iv && !drandRound) {
    return res.status(400).json({ error: 'need iv (legacy) or drandRound (tlock)' });
  }
  if (hasLockAt && (!iv || hasDrandRound)) {
    return res.status(400).json({ error: 'lockAt secrets must use AES-GCM ciphertext with an iv only' });
  }
  if (hasWeeklySchedule && !iv) {
    return res.status(400).json({ error: 'weeklyLockSchedule secrets must include iv' });
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
  const weeklyValidation = validateWeeklyLockSchedule(weeklyLockSchedule);
  if (!weeklyValidation.ok) return res.status(400).json({ error: weeklyValidation.error });

  const secret = await Secret.create({
    userId: req.userId,
    label,
    ciphertext,
    iv,
    drandRound,
    unlockAt: unlockDate || undefined,
    lockAt: lockDate || undefined,
    weeklyLockSchedule: hasWeeklySchedule ? weeklyLockSchedule : undefined,
    repeatWeekly: Boolean(repeatWeekly),
    scheduleTimezoneOffsetMinutes: Number.isFinite(Number(scheduleTimezoneOffsetMinutes))
      ? Number(scheduleTimezoneOffsetMinutes)
      : 0,
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
    weeklyLockSchedule: s.weeklyLockSchedule,
    repeatWeekly: s.repeatWeekly,
    scheduleTimezoneOffsetMinutes: s.scheduleTimezoneOffsetMinutes,
    accessible: isAccessible(s, now),
    createdAt: s.createdAt,
    canRescheduleLater: Boolean(s.lockAt) && s.lockAt.getTime() > now,
  })));
});

// replace an accessible unlock-later secret with a newly timelocked copy.
router.post('/:id/relock', relockLimiter, async (req, res) => {
  const {
    label, ciphertext, drandRound, unlockAt, iv, lockAt,
  } = req.body || {};
  if (!label || !ciphertext || !unlockAt) {
    return res.status(400).json({ error: 'missing fields' });
  }

  const isLockMode = Boolean(lockAt);
  const isTlockMode = drandRound !== undefined;

  if (!isLockMode && !isTlockMode) {
    return res.status(400).json({ error: 'provide either drandRound (tlock) or lockAt with iv (lock-later)' });
  }
  if (isLockMode && isTlockMode) {
    return res.status(400).json({ error: 'cannot use both drandRound and lockAt' });
  }

  const unlockDate = new Date(unlockAt);
  if (Number.isNaN(unlockDate.getTime())) return res.status(400).json({ error: 'bad unlockAt' });
  if (unlockDate.getTime() <= Date.now()) {
    return res.status(400).json({ error: 'unlockAt must be in the future' });
  }

  let lockDate = null;
  if (isTlockMode) {
    if (!Number.isInteger(drandRound) || drandRound <= 0) {
      return res.status(400).json({ error: 'bad drandRound' });
    }
    if (drandRound !== roundAt(unlockDate.getTime(), defaultChainInfo)) {
      return res.status(400).json({ error: 'invalid drand round for the specified unlock time' });
    }
  } else {
    if (!iv) return res.status(400).json({ error: 'iv required for lock-later mode' });
    lockDate = new Date(lockAt);
    if (Number.isNaN(lockDate.getTime())) return res.status(400).json({ error: 'bad lockAt' });
    if (lockDate.getTime() <= Date.now()) {
      return res.status(400).json({ error: 'lockAt must be in the future' });
    }
    if (unlockDate.getTime() <= lockDate.getTime()) {
      return res.status(400).json({ error: 'unlockAt must be later than lockAt' });
    }
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
    ...(isLockMode && { iv }),
    ...(isTlockMode && { drandRound }),
    unlockAt: unlockDate,
    ...(lockDate && { lockAt: lockDate }),
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
    drandRound: s.drandRound, unlockAt: s.unlockAt, lockAt: s.lockAt, weeklyLockSchedule: s.weeklyLockSchedule,
    repeatWeekly: s.repeatWeekly, scheduleTimezoneOffsetMinutes: s.scheduleTimezoneOffsetMinutes,
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
