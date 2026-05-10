const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  salt: { type: String, required: true },
  authHashBcrypt: { type: String, required: true },
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);
