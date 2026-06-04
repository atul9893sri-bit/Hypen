const mongoose = require("mongoose");

const authSessionSchema = new mongoose.Schema({
  sessionId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
    index: true,
  },
  deviceId: {
    type: String,
    required: true,
    index: true,
  },
  deviceName: {
    type: String,
    required: true,
  },
  platform: {
    type: String,
    enum: ["android", "ios", "windows", "macos", "linux", "unknown"],
    default: "unknown",
  },
  type: {
    type: String,
    enum: ["qr", "pin"],
    required: true,
    index: true,
  },
  pinHash: {
    type: String,
    default: null,
  },
  expiresAt: {
    type: Date,
    required: true,
    index: true,
  },
  status: {
    type: String,
    enum: ["pending", "approved", "expired", "used", "revoked"],
    default: "pending",
    index: true,
  },
  attemptCount: {
    type: Number,
    default: 0,
  },
  approvedAt: {
    type: Date,
    default: null,
  },
  consumedAt: {
    type: Date,
    default: null,
  },
  authPayload: {
    type: mongoose.Schema.Types.Mixed,
    default: null,
  },
}, {
  timestamps: true,
});

authSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("AuthSession", authSessionSchema);
