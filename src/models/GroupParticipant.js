const mongoose = require("mongoose");

const groupParticipantSchema = new mongoose.Schema(
  {
    groupId: { type: String, required: true, index: true },
    userId: { type: String, required: true, index: true },
    role: {
      type: String,
      enum: ["owner", "admin", "co_admin", "member"],
      default: "member",
    },
    status: {
      type: String,
      enum: ["active", "pending", "left", "removed", "banned"],
      default: "active",
    },
    joinedAt: { type: Date, default: Date.now },
    joinedBy: { type: String, default: null },
    removedAt: { type: Date, default: null },
    removedBy: { type: String, default: null },
    lastReadMessageId: { type: String, default: null },
    lastReadAt: { type: Date, default: null },
    lastDeliveredMessageId: { type: String, default: null },
    lastDeliveredAt: { type: Date, default: null },
    unreadCount: { type: Number, default: 0, min: 0 },
    muteUntil: { type: Date, default: null },
    notifications: {
      type: String,
      enum: ["all", "mentions", "none"],
      default: "all",
    },
    isArchived: { type: Boolean, default: false },
    customPermissions: {
      sendMessages: { type: Boolean, default: undefined },
      editInfo: { type: Boolean, default: undefined },
      addMembers: { type: Boolean, default: undefined },
    },
    encryption: {
      senderKeyAcceptedEpoch: { type: Number, default: 0, min: 0 },
      deviceCountSnapshot: { type: Number, default: 0, min: 0 },
    },
  },
  {
    timestamps: true,
  },
);

groupParticipantSchema.index({ groupId: 1, userId: 1 }, { unique: true });
groupParticipantSchema.index({ userId: 1, status: 1, updatedAt: -1 });
groupParticipantSchema.index({ groupId: 1, role: 1, status: 1 });

module.exports = mongoose.model("GroupParticipant", groupParticipantSchema);
