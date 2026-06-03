const mongoose = require("mongoose");

const groupMessageReceiptSchema = new mongoose.Schema(
  {
    groupId: { type: String, required: true, index: true },
    messageId: { type: String, required: true, index: true },
    userId: { type: String, required: true, index: true },
    deliveredAt: { type: Date, default: null },
    readAt: { type: Date, default: null },
    deletedForMeAt: { type: Date, default: null },
  },
  {
    timestamps: true,
  },
);

groupMessageReceiptSchema.index({ messageId: 1, userId: 1 }, { unique: true });
groupMessageReceiptSchema.index({ groupId: 1, userId: 1, readAt: 1 });

module.exports = mongoose.model("GroupMessageReceipt", groupMessageReceiptSchema);
