const mongoose = require("mongoose");

const deviceSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },
  deviceId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  deviceName: {
    type: String,
    required: true,
  },
  type: {
    type: String,
    enum: ["mobile", "desktop"],
    required: true,
    index: true,
  },
  platform: {
    type: String,
    enum: ["android", "ios", "windows", "macos", "linux", "unknown"],
    default: "unknown",
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true,
  },
  lastActive: {
    type: Date,
    default: Date.now,
    index: true,
  },
  tokenVersion: {
    type: Number,
    default: 1,
  },
  socketId: {
    type: String,
    default: null,
  },
  fcmToken: {
    type: String,
    default: null,
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
}, {
  timestamps: true,
});

deviceSchema.index({ userId: 1, type: 1 });

module.exports = mongoose.model("Device", deviceSchema);
