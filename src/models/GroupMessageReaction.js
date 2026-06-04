const mongoose = require("mongoose");

const groupMessageReactionSchema = new mongoose.Schema(
  {
    groupId: { type: String, required: true, index: true },
    messageId: { type: String, required: true, index: true },
    userId: { type: String, required: true, index: true },
    emoji: { type: String, required: true, maxlength: 32 },
    reactedAt: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
  },
);

groupMessageReactionSchema.index({ messageId: 1, userId: 1 }, { unique: true });
groupMessageReactionSchema.index({ groupId: 1, messageId: 1, reactedAt: -1 });

module.exports = mongoose.model("GroupMessageReaction", groupMessageReactionSchema);
