const mongoose = require("mongoose");

const permissionScopes = ["all", "members", "admins", "co_admins", "owner"];
const joinModes = ["open", "admin_approval", "invite_only"];
const encryptionModes = ["plaintext", "sender_keys", "mls_ready"];

function normalizeChatIds(values) {
  return [...new Set(
    (Array.isArray(values) ? values : [])
      .map((value) => String(value || "").trim().replace(/^@+/, ""))
      .filter(Boolean),
  )];
}

function normalizeStrings(values) {
  return [...new Set(
    (Array.isArray(values) ? values : [])
      .map((value) => String(value || "").trim())
      .filter(Boolean),
  )];
}

const groupSettingsSchema = new mongoose.Schema(
  {
    sendMessages: {
      type: String,
      enum: permissionScopes,
      default: "all",
    },
    editInfo: {
      type: String,
      enum: permissionScopes,
      default: "admins",
    },
    addMembers: {
      type: String,
      enum: permissionScopes,
      default: "admins",
    },
    approveJoinRequests: {
      type: String,
      enum: permissionScopes,
      default: "admins",
    },
    allowInviteLinks: {
      type: Boolean,
      default: true,
    },
    joinMode: {
      type: String,
      enum: joinModes,
      default: "admin_approval",
    },
    memberListVisibility: {
      type: String,
      enum: ["members", "admins", "owner"],
      default: "members",
    },
    disappearingMessagesSeconds: {
      type: Number,
      default: 0,
      min: 0,
      max: 7776000,
    },
  },
  { _id: false },
);

const groupInviteConfigSchema = new mongoose.Schema(
  {
    activeInviteId: {
      type: String,
      default: null,
    },
    joinApprovalRequired: {
      type: Boolean,
      default: true,
    },
    revokeVersion: {
      type: Number,
      default: 0,
      min: 0,
    },
    lastRotatedAt: {
      type: Date,
      default: null,
    },
  },
  { _id: false },
);

const groupEncryptionSchema = new mongoose.Schema(
  {
    mode: {
      type: String,
      enum: encryptionModes,
      default: "sender_keys",
    },
    senderKeyEpoch: {
      type: Number,
      default: 0,
      min: 0,
    },
    lastSenderKeyRotationAt: {
      type: Date,
      default: null,
    },
  },
  { _id: false },
);

const groupLastMessageSchema = new mongoose.Schema(
  {
    messageId: {
      type: String,
      default: null,
    },
    senderId: {
      type: String,
      default: null,
    },
    preview: {
      type: String,
      default: "",
      maxlength: 280,
    },
    type: {
      type: String,
      default: "text",
    },
    at: {
      type: Date,
      default: null,
    },
  },
  { _id: false },
);

const groupSchema = new mongoose.Schema(
  {
    groupId: { type: String, required: true, unique: true, index: true },
    name: { type: String, required: true, trim: true, maxlength: 100 },
    description: { type: String, default: "", trim: true, maxlength: 1024 },
    profilePhoto: { type: String, default: "" },
    ownerId: { type: String, required: true, index: true },
    admins: { type: [String], default: [] },
    coAdmins: { type: [String], default: [] },
    members: { type: [String], default: [] },
    participantCount: { type: Number, default: 0, min: 0 },
    activeParticipantCount: { type: Number, default: 0, min: 0 },
    pinnedMessageIds: { type: [String], default: [] },
    settings: { type: groupSettingsSchema, default: () => ({}) },
    inviteLink: { type: groupInviteConfigSchema, default: () => ({}) },
    encryption: { type: groupEncryptionSchema, default: () => ({}) },
    lastMessage: { type: groupLastMessageSchema, default: () => ({}) },
    profilePhotoUpdatedAt: { type: Date, default: null },
    descriptionUpdatedAt: { type: Date, default: null },
    nameUpdatedAt: { type: Date, default: null },
    createdBy: { type: String, default: null },
    updatedBy: { type: String, default: null },
    deletedAt: { type: Date, default: null },
  },
  {
    timestamps: true,
  },
);

groupSchema.pre("validate", function normalizeGroupState() {
  this.ownerId = String(this.ownerId || "").trim().replace(/^@+/, "");
  this.members = normalizeChatIds([this.ownerId, ...this.members]);
  this.admins = normalizeChatIds([this.ownerId, ...this.admins]);
  this.coAdmins = normalizeChatIds(this.coAdmins).filter(
    (chatId) => chatId !== this.ownerId && !this.admins.includes(chatId),
  );
  this.pinnedMessageIds = normalizeStrings(this.pinnedMessageIds);
  this.participantCount = this.members.length;
  this.activeParticipantCount = this.members.length;
});

groupSchema.index({ members: 1, updatedAt: -1 });
groupSchema.index({ admins: 1, updatedAt: -1 });
groupSchema.index({ coAdmins: 1, updatedAt: -1 });
groupSchema.index({ deletedAt: 1, updatedAt: -1 });
groupSchema.index({ "lastMessage.at": -1 });

module.exports = mongoose.model("Group", groupSchema);
