const mongoose = require("mongoose");

const groupJoinRequestSchema = new mongoose.Schema(
  {
    requestId: { type: String, required: true, unique: true },
    groupId: { type: String, required: true, index: true },
    requesterId: { type: String, required: true, index: true },
    inviteId: { type: String, default: null, index: true },
    source: {
      type: String,
      enum: ["invite_link", "direct", "qr"],
      default: "invite_link",
    },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected", "cancelled", "expired"],
      default: "pending",
    },
    requestedRole: {
      type: String,
      enum: ["member", "co_admin"],
      default: "member",
    },
    note: { type: String, default: "", maxlength: 280 },
    reviewedBy: { type: String, default: null },
    reviewedAt: { type: Date, default: null },
    decisionReason: { type: String, default: "", maxlength: 280 },
  },
  {
    timestamps: true,
  },
);

groupJoinRequestSchema.index({ groupId: 1, status: 1, createdAt: -1 });
groupJoinRequestSchema.index({ requesterId: 1, status: 1, createdAt: -1 });
groupJoinRequestSchema.index(
  { groupId: 1, requesterId: 1 },
  { unique: true, partialFilterExpression: { status: "pending" } },
);

module.exports = mongoose.model("GroupJoinRequest", groupJoinRequestSchema);
