const mongoose = require("mongoose");

const groupPinnedMessageSchema = new mongoose.Schema(
  {
    groupId: { type: String, required: true, index: true },
    messageId: { type: String, required: true, index: true },
    pinnedBy: { type: String, required: true, index: true },
    pinnedAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, default: null },
  },
  {
    timestamps: true,
  },
);

groupPinnedMessageSchema.index({ groupId: 1, pinnedAt: -1 });
groupPinnedMessageSchema.index({ groupId: 1, messageId: 1 }, { unique: true });

module.exports = mongoose.model("GroupPinnedMessage", groupPinnedMessageSchema);
