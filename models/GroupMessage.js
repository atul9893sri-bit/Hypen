const mongoose = require("mongoose");

const encryptionModes = ["plaintext", "sender_keys", "mls_ready"];

function normalizeChatIds(values) {
  return [...new Set(
    (Array.isArray(values) ? values : [])
      .map((value) => String(value || "").trim().replace(/^@+/, ""))
      .filter(Boolean),
  )];
}

const mentionSchema = new mongoose.Schema(
  {
    chatId: { type: String, required: true },
    start: { type: Number, default: 0, min: 0 },
    length: { type: Number, default: 0, min: 0 },
  },
  { _id: false },
);

const encryptionSchema = new mongoose.Schema(
  {
    scheme: {
      type: String,
      enum: encryptionModes,
      default: "sender_keys",
    },
    senderKeyId: {
      type: String,
      default: null,
    },
    keyEpoch: {
      type: Number,
      default: 0,
      min: 0,
    },
    payload: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
  },
  { _id: false },
);

const groupMessageSchema = new mongoose.Schema(
  {
    messageId: { type: String, required: true, unique: true, index: true },
    clientMessageId: { type: String, default: null, index: true },
    groupId: { type: String, required: true, index: true },
    senderId: { type: String, required: true, index: true },
    senderDeviceId: { type: String, default: null },
    content: { type: String, default: "" },
    type: { type: Number, default: 0 },
    messageType: {
      type: String,
      enum: [
        "text",
        "image",
        "video",
        "audio",
        "document",
        "sticker",
        "system",
      ],
      default: "text",
    },
    mediaUrl: { type: String, default: null },
    fileName: { type: String, default: null },
    fileSize: { type: Number, default: null },
    replyToId: { type: String, default: null, index: true },
    replyToContent: { type: String, default: null },
    threadRootMessageId: { type: String, default: null, index: true },
    mentionedUserIds: { type: [String], default: [] },
    mentions: { type: [mentionSchema], default: [] },
    isViewOnce: { type: Boolean, default: false },
    isEdited: { type: Boolean, default: false },
    editedAt: { type: Date, default: null },
    editedBy: { type: String, default: null },
    deletedForEveryoneAt: { type: Date, default: null },
    deletedForEveryoneBy: { type: String, default: null },
    deletedForUserIds: { type: [String], default: [] },
    encryption: { type: encryptionSchema, default: () => ({}) },
    readReceiptSummary: {
      deliveredCount: { type: Number, default: 0, min: 0 },
      readCount: { type: Number, default: 0, min: 0 },
    },
    timestamp: { type: Date, default: Date.now, index: true },
    systemType: { type: String, default: null },
  },
  {
    timestamps: true,
  },
);

groupMessageSchema.pre("validate", function normalizeMessageState() {
  this.mentionedUserIds = normalizeChatIds([
    ...this.mentionedUserIds,
    ...this.mentions.map((mention) => mention.chatId),
  ]);
  this.deletedForUserIds = normalizeChatIds(this.deletedForUserIds);
  if (!this.threadRootMessageId && this.replyToId) {
    this.threadRootMessageId = this.replyToId;
  }
});

groupMessageSchema.index({ groupId: 1, timestamp: 1 });
groupMessageSchema.index({ groupId: 1, threadRootMessageId: 1, timestamp: 1 });
groupMessageSchema.index({ groupId: 1, mentionedUserIds: 1, timestamp: -1 });
groupMessageSchema.index({ groupId: 1, deletedForEveryoneAt: 1, timestamp: -1 });

module.exports = mongoose.model("GroupMessage", groupMessageSchema);
