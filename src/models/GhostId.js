const mongoose = require("mongoose");

const ghostIdSchema = new mongoose.Schema({
  ghostId: { type: String, required: true, unique: true },
  realChatId: { type: String, required: true, index: true },
  peerChatId: { type: String, default: null, index: true },
  createdAt: { type: Date, default: Date.now },
  consumedAt: { type: Date, default: null },
  expiresAt: { type: Date, required: true },
  isActive: { type: Boolean, default: true },
  releasedAt: { type: Date, default: null },
});

module.exports = mongoose.model("GhostId", ghostIdSchema);
