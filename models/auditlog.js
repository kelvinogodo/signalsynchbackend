const mongoose = require('mongoose')

const auditLogSchema = new mongoose.Schema(
  {
    adminEmail: { type: String, required: true },
    action: { type: String, required: true },
    target: { type: String, default: '' },
    ip: { type: String, default: '' },
    success: { type: Boolean, required: true },
    details: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true }
)

const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', auditLogSchema)
module.exports = AuditLog
