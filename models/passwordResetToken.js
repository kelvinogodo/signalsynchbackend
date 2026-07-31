const mongoose = require('mongoose')

const passwordResetTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
  tokenHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 900 }, // TTL: mongo purges ~15 min after creation
})

const PasswordResetToken =
  mongoose.models.PasswordResetToken || mongoose.model('PasswordResetToken', passwordResetTokenSchema)
module.exports = PasswordResetToken
