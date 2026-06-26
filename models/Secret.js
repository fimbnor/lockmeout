const mongoose = require('mongoose');

const SecretSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  label: { type: String, required: true },
  ciphertext: { type: String, required: true },
  iv: { type: String },
  drandRound: { type: Number },
  unlockAt: { type: Date },
  lockAt: { type: Date },
}, { timestamps: true });

module.exports = mongoose.model('Secret', SecretSchema);
