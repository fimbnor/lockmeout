const mongoose = require('mongoose');

const SecretSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  label: { type: String, required: true },
  ciphertext: { type: String, required: true },
  iv: { type: String },
  drandRound: { type: Number },
  unlockAt: { type: Date },
  lockAt: { type: Date },
  weeklyLockSchedule: [{
    dayOfWeek: { type: Number, min: 0, max: 6, required: true },
    startTime: { type: String, required: true },
    endTime: { type: String, required: true },
  }],
  repeatWeekly: { type: Boolean, default: false },
  scheduleTimezoneOffsetMinutes: { type: Number, default: 0 },
}, { timestamps: true });

module.exports = mongoose.model('Secret', SecretSchema);
