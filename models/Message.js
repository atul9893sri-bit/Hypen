const mongoose = require("mongoose");

const encryptedPayloadSchema = new mongoose.Schema({
  deviceId: {
    type: String,
    required: true
  },
  ciphertext: {
    type: String,
    required: true
  },
  header: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  }
});

const messageSchema = new mongoose.Schema({
  messageId: {
    type: String,
    required: true,
    unique: true
  },
  clientMessageId: {
    type: String,
    default: null
  },
  senderChatId: {
    type: String,
    required: true
  },
  receiverChatId: {
    type: String,
    required: true
  },
  groupId: {
    type: String,
    default: null
  },
  senderDeviceId: {
    type: String,
    required: true
  },
  senderDevicePublicKey: {
    type: String,
    default: null
  },
  content: {
    type: String,
    default: null
  },
  type: {
    type: Number,
    default: 0
  },
  status: {
    type: String,
    enum: ["sent", "delivered", "read"],
    default: "sent"
  },
  payloads: [encryptedPayloadSchema],
  replyToId: {
    type: String,
    default: null
  },
  replyToContent: {
    type: String,
    default: null
  },
  mediaUrl: {
    type: String,
    default: null
  },
  fileName: {
    type: String,
    default: null
  },
  fileSize: {
    type: Number,
    default: null
  },
  isViewOnce: {
    type: Boolean,
    default: false
  },
  ghostSessionId: {
    type: String,
    default: null
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("Message", messageSchema);
