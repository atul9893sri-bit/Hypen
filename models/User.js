const mongoose = require("mongoose");

const deviceSchema = new mongoose.Schema({
  deviceId: {
    type: String,
    required: true
  },
  encryptionPublicKey: {
    type: String,
    required: true
  },
  signingPublicKey: {
    type: String,
    required: true
  },
  signedPrekey: {
    type: String,
    required: true
  },
  oneTimePrekeys: [
    {
      keyId: String,
      publicKey: String
    }
  ],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  about: {
    type: String,
    default: "Available"
  },
  chatId: {
    type: String,
    required: true,
    unique: true
  },
  phoneNumber: {
    type: String,
    sparse: true,
    unique: true,
    default: undefined,
    set: (value) => {
      if (!value || typeof value !== "string") return undefined;
      const trimmed = value.trim();
      if (trimmed.length === 0) return undefined;
      const hasPlus = trimmed.startsWith("+");
      const digits = trimmed.replace(/[^\d]/g, "");
      if (digits.length === 0) return undefined;
      return hasPlus ? `+${digits}` : digits;
    }
  },
  firebaseUid: {
    type: String,
    unique: true,
    sparse: true,
    default: undefined,
    set: (value) => {
      if (!value || typeof value !== "string") return undefined;
      const normalized = value.trim();
      return normalized.length === 0 ? undefined : normalized;
    }
  },
  profilePhoto: {
    type: String,
    default: ""
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  email: {
    type: String,
    default: undefined,
    set: (value) => {
      if (typeof value !== "string") {
        return value;
      }
      const normalized = value.trim();
      return normalized.length === 0 ? undefined : normalized;
    }
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  mood: {
    label: { type: String, default: "" },
    emoji: { type: String, default: "" },
    color: { type: String, default: "#4A55FF" },
    expiresAt: { type: Date, default: null }
  },
  identityPublicKey: {
    type: String,
    required: true
  },
  devices: [deviceSchema],
  activeMobileDeviceId: {
    type: String,
    default: null,
    index: true,
  },
  mobileLastHeartbeatAt: {
    type: Date,
    default: null,
  },
  socketId: {
    type: String,
    default: null
  },
  fcmToken: {
    type: String,
    default: null
  },
  savedContacts: {
    type: [String],
    default: []
  },
  privacy: {
    lastSeen: { type: String, enum: ["everyone", "contacts", "except", "none"], default: "everyone" },
    lastSeenExceptions: { type: [String], default: [] },
    onlineStatus: { type: String, enum: ["everyone", "contacts", "except", "none"], default: "everyone" },
    onlineStatusExceptions: { type: [String], default: [] },
    profilePhoto: { type: String, enum: ["everyone", "contacts", "except", "none"], default: "everyone" },
    profilePhotoExceptions: { type: [String], default: [] },
    about: { type: String, enum: ["everyone", "contacts", "except", "none"], default: "everyone" },
    aboutExceptions: { type: [String], default: [] },
    moments: { type: String, enum: ["contacts", "except", "only"], default: "contacts" },
    momentsExceptions: { type: [String], default: [] },
    groups: { type: String, enum: ["everyone", "contacts", "except", "none"], default: "everyone" },
    groupsExceptions: { type: [String], default: [] },
    calls: { type: String, enum: ["everyone", "contacts", "none"], default: "everyone" },
    callsExceptions: { type: [String], default: [] },
    messages: { type: String, enum: ["everyone", "contacts", "none"], default: "everyone" },
    readReceipts: { type: Boolean, default: true },
    typingIndicator: { type: Boolean, default: true },
    forwarding: { type: String, enum: ["all", "contacts", "disable"], default: "all" },
    unknownCallersSilence: { type: Boolean, default: false },
    unknownCallersReject: { type: Boolean, default: false },
    screenshotProtection: { type: Boolean, default: false },
  },
  blockedUsers: {
    type: [String],
    default: []
  },
  subscription: {
    plan: {
      type: String,
      enum: ["none", "monthly", "yearly"],
      default: "none",
    },
    status: {
      type: String,
      enum: ["inactive", "active", "expired", "pending"],
      default: "inactive",
    },
    startsAt: {
      type: Date,
      default: null,
    },
    endsAt: {
      type: Date,
      default: null,
    },
    lastPaymentAt: {
      type: Date,
      default: null,
    },
  },
  lastChatIdChangeAt: {
    type: Date,
    default: null
  },
  previousChatIds: {
    type: [String],
    default: []
  },
  historyClearedAt: {
    type: Date,
    default: null,
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("User", userSchema);
