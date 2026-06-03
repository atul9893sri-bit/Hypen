const mongoose = require("mongoose");

const groupInviteLinkSchema = new mongoose.Schema(
  {
    inviteId: { type: String, required: true, unique: true },
    groupId: { type: String, required: true, index: true },
    tokenHash: { type: String, required: true, unique: true },
    createdBy: { type: String, required: true, index: true },
    status: {
      type: String,
      enum: ["active", "revoked", "expired"],
      default: "active",
    },
    approvalRequired: { type: Boolean, default: true },
    maxUses: { type: Number, default: 0, min: 0 },
    usedCount: { type: Number, default: 0, min: 0 },
    expiresAt: { type: Date, default: null },
    lastUsedAt: { type: Date, default: null },
    revokedAt: { type: Date, default: null },
    revokedBy: { type: String, default: null },
    label: { type: String, default: "", maxlength: 80 },
  },
  {
    timestamps: true,
  },
);

groupInviteLinkSchema.index({ groupId: 1, status: 1, createdAt: -1 });
groupInviteLinkSchema.index({ groupId: 1, expiresAt: 1 });

module.exports = mongoose.model("GroupInviteLink", groupInviteLinkSchema);
