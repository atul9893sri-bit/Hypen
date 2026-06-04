require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const { rateLimit, ipKeyGenerator } = require("express-rate-limit");
const { RedisStore } = require("rate-limit-redis");
const { createClient } = require("redis");

const app = express();
app.set("trust proxy", 1);
const server = http.createServer(app);
const Message = require("./models/Message");
const GhostId = require("./models/GhostId");
const User = require("./models/User");
const Device = require("./models/Device");
const AuthSession = require("./models/AuthSession");
const Call = require("./models/Call");
const Moment = require("./models/Moment");
const MomentReport = require("./models/MomentReport");
const Group = require("./models/Group");
const GroupMessage = require("./models/GroupMessage");
const GroupParticipant = require("./models/GroupParticipant");
const GroupInviteLink = require("./models/GroupInviteLink");
const GroupJoinRequest = require("./models/GroupJoinRequest");
const GroupMessageReceipt = require("./models/GroupMessageReceipt");
const GroupMessageReaction = require("./models/GroupMessageReaction");
const GroupPinnedMessage = require("./models/GroupPinnedMessage");
const PaymentTransaction = require("./models/PaymentTransaction");
const PaymentRefund = require("./models/PaymentRefund");
const { requireAuth, requireDeviceType } = require("./middleware/auth");
const {
  issueAccessToken,
  verifyAccessToken,
  verifyAccessTokenAllowExpired,
  isTokenExpiredError,
} = require("./services/auth-token");
const {
  createQrSession,
  createPinSession,
  isExpired,
  markApproved,
  consumeApprovedSession,
  validatePinSession,
} = require("./services/auth-session");
const {
  getActiveMobileDevice,
  ensureDeviceLimit,
  revokeDevice,
  revokeAllDesktopDevices,
} = require("./services/device-state");
const admin = require("firebase-admin");

const UPDATE_CONFIG_PATH = path.join(__dirname, "./config/update-config.json");
const UPDATE_API_KEY = process.env.UPDATE_API_KEY || "CHANGE_ME_UPDATE_API_KEY";
const CHANGE_CHAT_ID_PRICES = {
  random: 59,
  custom: 99,
};
const CHANGE_CHAT_ID_SUBSCRIBER_DISCOUNT = 20;
const SUBSCRIPTION_PRICES = {
  monthly: 149,
  yearly: 1299,
};

const razorpayKeyId = process.env.RAZORPAY_KEY_ID || "";
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET || "";
const razorpayWebhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET || "";
const razorpayClient =
  razorpayKeyId && razorpayKeySecret
    ? new Razorpay({
        key_id: razorpayKeyId,
        key_secret: razorpayKeySecret,
      })
    : null;

const allowedOrigins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
const redisUrl = String(process.env.REDIS_URL || "").trim();
const useRedisRateLimit =
  redisUrl && process.env.USE_REDIS_RATE_LIMIT === "true";
let redisClient = null;
if (useRedisRateLimit) {
  redisClient = createClient({
    url: redisUrl,
    socket: {
      reconnectStrategy: false,
    },
  });
  redisClient.on("error", (error) => {
    console.warn("Redis unavailable; rate limit checks will fall back:", error.message);
  });
  redisClient.connect().catch((error) => {
    console.warn("Redis connection failed; continuing without Redis:", error.message);
  });
} else {
  console.warn(
    "Using in-memory rate limiting. Set USE_REDIS_RATE_LIMIT=true with REDIS_URL to enable Redis-backed limits.",
  );
}

function isAllowedCorsOrigin(origin) {
  if (!origin) {
    // Allow non-browser clients (mobile apps, CLI, server-to-server).
    return true;
  }
  return allowedOrigins.includes(origin);
}

const io = socketIo(server, {
  cors: {
    origin: (origin, callback) => {
      if (isAllowedCorsOrigin(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error("Socket origin not allowed"));
    },
    credentials: true,
  },
});

function makeRateLimiter({ windowMs, max, keyPrefix }) {
  const options = {
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    passOnStoreError: true,
    keyGenerator: (req) => {
      const ip = ipKeyGenerator(
        req.ip || req.connection?.remoteAddress || "unknown",
      );
      const userKey = req.auth?.chatId || req.params?.chatId || "anon";
      return `${keyPrefix}:${ip}:${userKey}`;
    },
    handler: (req, res) => {
      const retryAfter = Number(res.getHeader("Retry-After") || 60);
      res.status(429).json({
        error: "Too many requests. Please try again later.",
        retryAfterSeconds: retryAfter,
      });
    },
  };

  if (redisClient) {
    options.store = new RedisStore({
      sendCommand: (...args) => redisClient.sendCommand(args),
      prefix: `rl:${keyPrefix}:`,
    });
  }

  return rateLimit(options);
}

const createOrderRateLimiter = makeRateLimiter({
  windowMs: 60 * 1000,
  max: 10,
  keyPrefix: "create_order",
});
const verifyPaymentRateLimiter = makeRateLimiter({
  windowMs: 60 * 1000,
  max: 20,
  keyPrefix: "verify_payment",
});
const chatIdAvailabilityRateLimiter = makeRateLimiter({
  windowMs: 60 * 1000,
  max: 20,
  keyPrefix: "chatid_availability",
});

function initializeFirebaseAdmin() {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY;
  const serviceAccountPath = path.join(__dirname, "..", "serviceAccountKey.json");

  try {
    if (projectId && clientEmail && privateKey) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          privateKey: privateKey.replace(/\\n/g, "\n"),
        }),
      });
      console.log("Firebase Admin Initialized from environment variables");
      return;
    }

    if (fs.existsSync(serviceAccountPath)) {
      const serviceAccount = JSON.parse(
        fs.readFileSync(serviceAccountPath, "utf8"),
      );
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
      });
      console.log("Firebase Admin Initialized from serviceAccountKey.json");
      return;
    }

    console.warn(
      "Firebase Admin credentials are missing. Push notifications and mobile auth verification will stay disabled.",
    );
    return;
  } catch (err) {
    console.error("Firebase Init Error:", err);
  }
}

function isFirebaseAdminReady() {
  return Array.isArray(admin.apps) && admin.apps.length > 0;
}

async function syncEmailToFirebaseStore({ chatId, email, emailVerified }) {
  if (!isFirebaseAdminReady()) return;
  try {
    await admin.firestore().collection("convooUsers").doc(String(chatId)).set(
      {
        chatId: String(chatId),
        email: String(email || ""),
        emailVerified: Boolean(emailVerified),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
  } catch (error) {
    console.error("Firebase email sync failed:", error?.message || error);
  }
}

async function connectMongo() {
  if (!process.env.MONGO_URI) {
    throw new Error("MONGO_URI is missing");
  }

  await mongoose.connect(process.env.MONGO_URI);
  console.log("MongoDB Connected");

  await Message.collection.createIndex(
    { timestamp: 1 },
    { expireAfterSeconds: 7 * 24 * 60 * 60, background: true },
  );

  await User.collection.updateMany(
    { email: "" },
    { $unset: { email: "" }, $set: { emailVerified: false } },
  );
  await User.collection.updateMany(
    { phoneNumber: "" },
    { $unset: { phoneNumber: "" } },
  );
  await User.collection.updateMany(
    { firebaseUid: "" },
    { $unset: { firebaseUid: "" } },
  );

  await Promise.all([
    User.createIndexes(),
    Call.createIndexes(),
    Group.createIndexes(),
    GroupMessage.createIndexes(),
    GroupParticipant.createIndexes(),
    GroupInviteLink.createIndexes(),
    GroupJoinRequest.createIndexes(),
    GroupMessageReceipt.createIndexes(),
    GroupMessageReaction.createIndexes(),
    GroupPinnedMessage.createIndexes(),
  ]);
}

function ensureUpdateConfig() {
  const folder = path.dirname(UPDATE_CONFIG_PATH);
  if (!fs.existsSync(folder)) {
    fs.mkdirSync(folder, { recursive: true });
  }
  if (!fs.existsSync(UPDATE_CONFIG_PATH)) {
    fs.writeFileSync(
      UPDATE_CONFIG_PATH,
      JSON.stringify(
        {
          latest_version: "0.0.9+2",
          apk_url: "",
          force_update: false,
          required: false,
          play_store_enabled: false,
          play_store_url: "",
          changelog: "Initial release.",
        },
        null,
        2,
      ),
      "utf8",
    );
  }
}

function readUpdateConfig() {
  ensureUpdateConfig();
  try {
    const raw = fs.readFileSync(UPDATE_CONFIG_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return {
      latest_version: String(parsed.latest_version || "0.0.9+2"),
      apk_url: String(parsed.apk_url || ""),
      force_update: Boolean(parsed.required ?? parsed.force_update),
      required: Boolean(parsed.required ?? parsed.force_update),
      play_store_enabled: Boolean(parsed.play_store_enabled),
      play_store_url: String(parsed.play_store_url || ""),
      changelog: String(parsed.changelog || ""),
    };
  } catch (e) {
    return {
      latest_version: "0.0.9+2",
      apk_url: "",
      force_update: false,
      required: false,
      play_store_enabled: false,
      play_store_url: "",
      changelog: "",
    };
  }
}

function writeUpdateConfig(next) {
  ensureUpdateConfig();
  fs.writeFileSync(
    UPDATE_CONFIG_PATH,
    JSON.stringify(next, null, 2),
    "utf8",
  );
}

function requireUpdateApiKey(req, res, next) {
  const supplied = req.header("x-api-key") || req.query.key;
  if (!supplied || supplied !== UPDATE_API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

async function generateUniqueChatId() {
  let chatId, exists = true;
  while (exists) {
    chatId = Math.floor(1000000 + Math.random() * 9000000).toString();
    exists = !!(await User.findOne({ chatId }));
  }
  return chatId;
}

function normalizePhoneNumber(phoneNumber) {
  const trimmed = String(phoneNumber || "").trim();
  if (!trimmed) {
    return undefined;
  }

  const hasPlus = trimmed.startsWith("+");
  const digits = trimmed.replace(/[^\d]/g, "");
  if (!digits) {
    return undefined;
  }

  return hasPlus ? `+${digits}` : digits;
}

function normalizeChatId(chatId) {
  return String(chatId || "")
    .trim()
    .replace(/^@+/, "");
}

function isValidSevenDigitChatId(chatId) {
  return /^\d{7}$/.test(normalizeChatId(chatId));
}

function normalizePlatform(platform) {
  const value = String(platform || "").trim().toLowerCase();
  if (["android", "ios", "windows", "macos", "linux"].includes(value)) {
    return value;
  }
  return "unknown";
}

function sanitizeDeviceName(name, fallback) {
  const trimmed = String(name || "").trim();
  if (trimmed) {
    return trimmed.slice(0, 80);
  }
  return fallback;
}

async function ensureMobileOtpAllowed(req, res) {
  const platform = normalizePlatform(req.body.platform);
  if (["windows", "macos", "linux"].includes(platform)) {
    res.status(403).json({ error: "OTP is not allowed on desktop platforms" });
    return false;
  }
  return true;
}

function buildAuthResponse(user, device, options = {}) {
  const historyCleared = options.historyCleared === true;
  return {
    accessToken: issueAccessToken({ user, device }),
    chatId: user.chatId,
    name: user.name,
    profilePhoto: user.profilePhoto || "",
    phoneNumber: user.phoneNumber || "",
    device: {
      deviceId: device.deviceId,
      deviceName: device.deviceName,
      type: device.type,
      platform: device.platform,
      lastActive: device.lastActive,
    },
    historyCleared,
  };
}

function buildLinkedDeviceResponse(device) {
  return {
    deviceId: device.deviceId,
    deviceName: device.deviceName,
    type: device.type,
    platform: device.platform,
    isActive: device.isActive,
    lastActive: device.lastActive,
    createdAt: device.createdAt,
    updatedAt: device.updatedAt,
  };
}

async function clearUserCommunicationHistory(chatId) {
  const normalizedChatId = normalizeChatId(chatId);
  if (!normalizedChatId) {
    return;
  }

  await Message.deleteMany({
    $or: [{ senderChatId: normalizedChatId }, { receiverChatId: normalizedChatId }],
  });
  await Call.deleteMany({
    $or: [{ caller: normalizedChatId }, { receiver: normalizedChatId }],
  });
}

function generateGroupId() {
  return `grp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

function generateInviteToken() {
  return crypto.randomBytes(24).toString("base64url");
}

function hashInviteToken(token) {
  return crypto.createHash("sha256").update(String(token || "")).digest("hex");
}

async function canBeAddedToGroup(targetChatId, actorChatId) {
  const user = await User.findOne({ chatId: targetChatId });
  if (!user) return { ok: false, error: "User not found" };
  if (user.blockedUsers?.includes(actorChatId)) {
    return { ok: false, error: "User has blocked you" };
  }
  const p = user.privacySettings || {};
  const groupSetting = p.groups || "everyone";
  const except = p.groupsExceptions || [];
  if (groupSetting === "none") return { ok: false, error: "User blocks all group adds" };
  if (groupSetting === "contacts") {
    const actorInSaved = Array.isArray(user.savedContacts)
      ? user.savedContacts.includes(actorChatId)
      : false;
    if (!actorInSaved) return { ok: false, error: "User allows only contacts" };
  }
  if (groupSetting === "except" && except.includes(actorChatId)) {
    return { ok: false, error: "User disallowed group adds from you" };
  }
  return { ok: true };
}

function canViewerSeePresence(targetUser, viewerChatId, field) {
  const privacy = targetUser?.privacy || {};
  const setting = privacy[field];
  const exceptions = privacy[`${field}Exceptions`] || [];
  const isContact = Array.isArray(targetUser.savedContacts)
    ? targetUser.savedContacts.includes(viewerChatId)
    : false;

  if (setting === "everyone") return true;
  if (setting === "contacts") return isContact;
  if (setting === "except") return isContact && !exceptions.includes(viewerChatId);
  return false;
}

function hasReciprocalPresencePermission(viewer, field) {
  if (!viewer) return true;
  const privacy = viewer?.privacy || {};
  // Reciprocity rule:
  // if you hide your own field, you cannot see others for the same field.
  return privacy[field] !== "none";
}

const GHOST_PREFIX = "GHOST_";
const GHOST_DEFAULT_TTL_MS = 2 * 60 * 60 * 1000;

async function generateUniqueGhostId() {
  let ghostId = "";
  let exists = true;
  while (exists) {
    ghostId =
      GHOST_PREFIX +
      Math.random().toString(36).substring(2, 8).toUpperCase();
    exists = !!(await GhostId.findOne({ ghostId }));
  }
  return ghostId;
}

/**
 * @returns {{ receiverChatId: string, ghostSessionId: string|null, ghostInvalid: boolean }}
 */
async function resolveGhostReceiverId(rawReceiver) {
  const id = normalizeChatId(rawReceiver);
  if (!id.startsWith(GHOST_PREFIX)) {
    return {
      receiverChatId: id,
      ghostSessionId: null,
      ghostInvalid: false,
    };
  }

  const doc = await GhostId.findOne({
    ghostId: id,
    isActive: true,
    expiresAt: { $gt: new Date() },
  });

  if (!doc) {
    return {
      receiverChatId: id,
      ghostSessionId: null,
      ghostInvalid: true,
    };
  }

  return {
    receiverChatId: doc.realChatId,
    ghostSessionId: id,
    ghostInvalid: false,
  };
}

async function resolveGhostSenderId(rawSender) {
  const id = normalizeChatId(rawSender);
  if (!id.startsWith(GHOST_PREFIX)) {
    return { senderPublicId: id, senderRealId: id, ghostInvalid: false };
  }

  const doc = await GhostId.findOne({
    ghostId: id,
    isActive: true,
    expiresAt: { $gt: new Date() },
  });

  if (!doc) {
    return { senderPublicId: id, senderRealId: id, ghostInvalid: true };
  }

  return {
    senderPublicId: id,
    senderRealId: doc.realChatId,
    ghostInvalid: false,
  };
}

async function purgeExpiredGhostSessions() {
  const now = new Date();
  const expired = await GhostId.find({
    $or: [
      { expiresAt: { $lte: now } },
      { isActive: false },
    ],
  });

  for (const g of expired) {
    try {
      await Message.deleteMany({ ghostSessionId: g.ghostId });
      if (g.isActive !== false || !g.releasedAt) {
        await GhostId.updateOne(
          { _id: g._id },
          {
            $set: {
              isActive: false,
              releasedAt: g.releasedAt || now,
            },
          },
        );
      }
    } catch (e) {
      console.error("Ghost purge error:", e);
    }
  }
}

async function updateUserReferenceArrays(oldChatId, newChatId) {
  const users = await User.find({
    $or: [{ savedContacts: oldChatId }, { blockedUsers: oldChatId }],
  });

  for (const user of users) {
    let changed = false;

    if (user.savedContacts.includes(oldChatId)) {
      user.savedContacts = user.savedContacts.map((id) =>
        id === oldChatId ? newChatId : id,
      );
      changed = true;
    }

    if (user.blockedUsers.includes(oldChatId)) {
      user.blockedUsers = user.blockedUsers.map((id) =>
        id === oldChatId ? newChatId : id,
      );
      changed = true;
    }

    if (changed) {
      user.markModified("savedContacts");
      user.markModified("blockedUsers");
      await user.save();
    }
  }

  return users;
}

async function updateCallReferences(oldChatId, newChatId) {
  const calls = await Call.find({
    $or: [
      { caller: oldChatId },
      { receiver: oldChatId },
      { participants: oldChatId },
    ],
  });

  for (const call of calls) {
    if (call.caller === oldChatId) {
      call.caller = newChatId;
    }
    if (call.receiver === oldChatId) {
      call.receiver = newChatId;
    }
    if (Array.isArray(call.participants) && call.participants.includes(oldChatId)) {
      call.participants = call.participants.map((id) =>
        id === oldChatId ? newChatId : id,
      );
      call.markModified("participants");
    }
    await call.save();
  }
}

async function updateMomentReferences(oldChatId, newChatId) {
  const moments = await Moment.find({
    $or: [
      { userId: oldChatId },
      { likes: oldChatId },
      { "views.viewerId": oldChatId },
      { "comments.userId": oldChatId },
    ],
  });

  for (const moment of moments) {
    let changed = false;

    if (moment.userId === oldChatId) {
      moment.userId = newChatId;
      changed = true;
    }

    if (Array.isArray(moment.likes) && moment.likes.includes(oldChatId)) {
      moment.likes = moment.likes.map((id) =>
        id === oldChatId ? newChatId : id,
      );
      changed = true;
    }

    if (Array.isArray(moment.views)) {
      for (const view of moment.views) {
        if (view.viewerId === oldChatId) {
          view.viewerId = newChatId;
          changed = true;
        }
      }
    }

    if (Array.isArray(moment.comments)) {
      for (const comment of moment.comments) {
        if (comment.userId === oldChatId) {
          comment.userId = newChatId;
          changed = true;
        }
      }
    }

    if (changed) {
      moment.markModified("likes");
      moment.markModified("views");
      moment.markModified("comments");
      await moment.save();
    }
  }
}

function migrateOnlinePresence(oldChatId, newChatId) {
  if (!onlineUsers.has(oldChatId)) {
    return;
  }

  const sockets = onlineUsers.get(oldChatId);
  onlineUsers.delete(oldChatId);
  onlineUsers.set(newChatId, sockets);

  for (const socketId of sockets) {
    const liveSocket = io.sockets.sockets.get(socketId);
    if (!liveSocket) {
      continue;
    }
    liveSocket.leave(oldChatId);
    liveSocket.join(newChatId);
    liveSocket.data.chatId = newChatId;
  }
}

// Track connected sockets by chatId for instant-delivery detection
const onlineUsers = new Map(); // chatId → Set<socketId>
const activeCallRooms = new Map();
const activeGroupCallsByGroupId = new Map(); // groupId -> { roomId, groupName, callType, hostId, hostName, startedAt }
const activePeerCalls = new Map();
const CALL_DISCONNECT_GRACE_MS = Number(process.env.CALL_DISCONNECT_GRACE_MS || 15000);
const CALL_SIGNAL_TTL_MS = Number(process.env.CALL_SIGNAL_TTL_MS || 20000);
const CALL_RING_TIMEOUT_MS = Number(process.env.CALL_RING_TIMEOUT_MS || 45000);

// Presence subscriptions: sockets join presence:<chatId> rooms for people they care about.
function presenceRoom(chatId) {
  return `presence:${chatId}`;
}

function peerCallRoom(callId) {
  return `call:${callId}`;
}

function normalizeActorChatId(socket, value) {
  return normalizeChatId(socket.data.auth?.chatId || value || "");
}

function isUserOnline(chatId) {
  return onlineUsers.has(chatId) && onlineUsers.get(chatId).size > 0;
}

function clearCallTimer(timer) {
  if (timer) {
    clearTimeout(timer);
  }
}

function queueRealtimeSignal(container, targetId, event, payload) {
  if (!targetId) {
    return;
  }
  if (!container.pendingSignals.has(targetId)) {
    container.pendingSignals.set(targetId, []);
  }
  const next = container.pendingSignals
    .get(targetId)
    .filter((item) => Date.now() - item.createdAt < CALL_SIGNAL_TTL_MS);
  next.push({ event, payload, createdAt: Date.now() });
  container.pendingSignals.set(targetId, next.slice(-50));
}

function flushRealtimeSignals(container, targetId) {
  const queued = container.pendingSignals.get(targetId) || [];
  if (!queued.length) {
    return;
  }
  container.pendingSignals.delete(targetId);
  for (const item of queued) {
    if (Date.now() - item.createdAt < CALL_SIGNAL_TTL_MS) {
      io.to(targetId).emit(item.event, item.payload);
    }
  }
}

function createPeerCallSnapshot(call) {
  return {
    callId: call.callId,
    roomId: peerCallRoom(call.callId),
    callerId: call.callerId,
    calleeId: call.calleeId,
    callType: call.callType,
    status: call.status,
    createdAt: call.createdAt,
    startedAt: call.startedAt || null,
    participants: Array.from(call.participants.values()).map((participant) => ({
      chatId: participant.chatId,
      name: participant.name,
      joinedAt: participant.joinedAt,
      connected: participant.connected !== false,
      reconnectDeadline: participant.reconnectDeadline || null,
      media: participant.media || { audio: true, video: call.callType === "video" },
      networkQuality: participant.networkQuality || "good",
    })),
  };
}

function emitPeerCallState(call) {
  const snapshot = createPeerCallSnapshot(call);
  io.to(peerCallRoom(call.callId)).emit("call_state_sync", snapshot);
  io.to(call.callerId).emit("call_state_sync", snapshot);
  io.to(call.calleeId).emit("call_state_sync", snapshot);
}

function clearPeerDisconnectTimer(call, chatId) {
  if (!call?.disconnectTimers?.has(chatId)) {
    return;
  }
  clearCallTimer(call.disconnectTimers.get(chatId));
  call.disconnectTimers.delete(chatId);
}

function finalizePeerCall(call, { status = "ended", reason = "ended", endedBy = null, duration = 0 } = {}) {
  if (!call) {
    return;
  }
  clearPeerDisconnectTimer(call, call.callerId);
  clearPeerDisconnectTimer(call, call.calleeId);
  clearCallTimer(call.ringTimer);
  call.status = status;
  const payload = {
    callId: call.callId,
    roomId: peerCallRoom(call.callId),
    from: call.callerId,
    to: call.calleeId,
    reason,
    duration,
  };
  const eventName = status === "missed" ? "call_missed" : "call_ended";
  io.to(peerCallRoom(call.callId)).emit(eventName, payload);
  io.to(call.callerId).emit(eventName, payload);
  io.to(call.calleeId).emit(eventName, payload);
  activePeerCalls.delete(call.callId);
  Call.findByIdAndUpdate(call.callId, {
    status,
    endTime: new Date(),
    duration,
    endedBy,
    endReason: reason,
    reconnectGraceUntil: null,
  }).catch((error) => {
    console.error("Peer call finalize failed:", error);
  });
}

function schedulePeerDisconnectGrace(call, chatId) {
  if (!call || !chatId || call.status !== "accepted") {
    return;
  }
  const participant = call.participants.get(chatId);
  if (!participant) {
    return;
  }
  clearPeerDisconnectTimer(call, chatId);
  participant.connected = false;
  participant.reconnectDeadline = new Date(Date.now() + CALL_DISCONNECT_GRACE_MS);
  const payload = {
    callId: call.callId,
    participantId: chatId,
    reconnectDeadline: participant.reconnectDeadline,
  };
  io.to(peerCallRoom(call.callId)).emit("call_participant_reconnecting", payload);
  io.to(call.callerId).emit("call_participant_reconnecting", payload);
  io.to(call.calleeId).emit("call_participant_reconnecting", payload);
  call.disconnectTimers.set(
    chatId,
    setTimeout(() => {
      const current = activePeerCalls.get(call.callId);
      if (!current) {
        return;
      }
      finalizePeerCall(current, {
        status: "ended",
        reason: "disconnect_timeout",
        endedBy: chatId,
      });
    }, CALL_DISCONNECT_GRACE_MS),
  );
}

function ensurePeerCall(callId, { callerId, callerName, calleeId, calleeName, callType }) {
  let call = activePeerCalls.get(callId);
  if (!call) {
    call = {
      callId,
      callerId,
      calleeId,
      callType,
      status: "ringing",
      createdAt: new Date(),
      startedAt: null,
      participants: new Map(),
      pendingSignals: new Map(),
      disconnectTimers: new Map(),
      ringTimer: setTimeout(() => {
        const current = activePeerCalls.get(callId);
        if (!current || current.status !== "ringing") {
          return;
        }
        finalizePeerCall(current, {
          status: "missed",
          reason: "ring_timeout",
        });
      }, CALL_RING_TIMEOUT_MS),
    };
    activePeerCalls.set(callId, call);
  }

  if (!call.participants.has(callerId)) {
    call.participants.set(callerId, {
      chatId: callerId,
      name: callerName || callerId,
      joinedAt: new Date(),
      connected: true,
      reconnectDeadline: null,
      media: { audio: true, video: callType === "video" },
      networkQuality: "good",
    });
  }
  if (!call.participants.has(calleeId)) {
    call.participants.set(calleeId, {
      chatId: calleeId,
      name: calleeName || calleeId,
      joinedAt: new Date(),
      connected: true,
      reconnectDeadline: null,
      media: { audio: true, video: callType === "video" },
      networkQuality: "good",
    });
  }

  return call;
}

// Throttle typing floods per pair (from->to)
const typingThrottle = new Map(); // key -> lastEmitMs

function addOnlineSocket(chatId, socketId) {
  if (!chatId) {
    return;
  }
  if (!onlineUsers.has(chatId)) {
    onlineUsers.set(chatId, new Set());
  }
  onlineUsers.get(chatId).add(socketId);
}

function removeOnlineSocket(socketId) {
  for (const [chatId, sockets] of onlineUsers.entries()) {
    sockets.delete(socketId);
    if (sockets.size === 0) {
      onlineUsers.delete(chatId);
    }
  }
}

function restoreActiveCallsForSocket(socket) {
  const chatId = socket.data.auth?.chatId;
  if (!chatId) {
    return;
  }

  for (const call of activePeerCalls.values()) {
    if (chatId !== call.callerId && chatId !== call.calleeId) {
      continue;
    }
    socket.join(peerCallRoom(call.callId));
    rememberSocketRoom(socket, peerCallRoom(call.callId));
    const participant = call.participants.get(chatId);
    if (participant) {
      participant.connected = true;
      participant.reconnectDeadline = null;
      clearPeerDisconnectTimer(call, chatId);
    }
    if (call.status === "ringing" && chatId === call.calleeId) {
      socket.emit("call_offer", {
        callId: call.callId,
        from: call.callerId,
        to: call.calleeId,
        type: call.callType,
        fromName: call.participants.get(call.callerId)?.name || call.callerId,
        resumed: true,
      });
    }
    socket.emit("call_state_sync", createPeerCallSnapshot(call));
    flushRealtimeSignals(call, chatId);
  }

  for (const room of activeCallRooms.values()) {
    if (!room.participants.has(chatId) && !room.invited.has(chatId)) {
      continue;
    }
    socket.join(room.roomId);
    rememberSocketRoom(socket, room.roomId);
    if (room.disconnectTimers.has(chatId)) {
      clearCallTimer(room.disconnectTimers.get(chatId));
      room.disconnectTimers.delete(chatId);
    }
    if (room.disconnectedParticipants.has(chatId)) {
      room.disconnectedParticipants.delete(chatId);
    }
    if (room.participants.has(chatId)) {
      const participant = room.participants.get(chatId);
      participant.connected = true;
      participant.reconnectDeadline = null;
    }
    if (room.invited.has(chatId)) {
      socket.emit("group_call_invite", {
        roomId: room.roomId,
        from: room.hostId,
        fromName: room.participants.get(room.hostId)?.name || room.hostId,
        callType: room.callType,
        invitedParticipants: Array.from(room.invited.keys()),
        participants: createRoomSnapshot(room).participants,
        resumed: true,
      });
    }
    socket.emit("group_call_state", createRoomSnapshot(room));
    flushRealtimeSignals(room, chatId);
  }
}

async function attachAuthenticatedSocket(socket) {
  const auth = socket.data.auth;
  if (!auth?.chatId || !auth?.deviceId) {
    return;
  }
  socket.data.chatId = auth.chatId;
  socket.data.deviceId = auth.deviceId;
  socket.join(auth.chatId);
  socket.join(`user:${auth.chatId}`);
  socket.join(`device:${auth.deviceId}`);
  addOnlineSocket(auth.chatId, socket.id);
  const presencePayload = {
    chatId: auth.chatId,
    isOnline: true,
    lastSeen: null,
    serverNow: new Date().toISOString(),
  };
  io.to(`user:${auth.chatId}`).emit("presence_changed", presencePayload);
  io.to(presenceRoom(auth.chatId)).emit("presence_changed", presencePayload);

  await Device.updateOne(
    { deviceId: auth.deviceId },
    { $set: { socketId: socket.id, lastActive: new Date(), isActive: true } },
  );
  await User.updateOne(
    { _id: auth.sub },
    { $set: { socketId: socket.id, lastSeen: new Date() } },
  );

  try {
    const groups = await Group.find({ members: auth.chatId }).select("groupId");
    for (const g of groups) {
      socket.join(g.groupId);
    }
  } catch (e) {
    console.error("Group room join failed:", e);
  }

  restoreActiveCallsForSocket(socket);
}

function createRoomSnapshot(room) {
  return {
    roomId: room.roomId,
    hostId: room.hostId,
    callType: room.callType,
    reconnectingParticipants: Array.from(room.disconnectedParticipants.entries()).map(
      ([chatId, reconnectDeadline]) => ({
        chatId,
        reconnectDeadline,
      }),
    ),
    participants: Array.from(room.participants.values()).map((participant) => ({
      chatId: participant.chatId,
      name: participant.name,
      joinedAt: participant.joinedAt,
      connected: participant.connected !== false,
      reconnectDeadline: participant.reconnectDeadline || null,
    })),
    invited: Array.from(room.invited.values()).map((invited) => ({
      chatId: invited.chatId,
      name: invited.name,
      status: invited.status,
    })),
  };
}

function emitRoomState(room) {
  const snapshot = createRoomSnapshot(room);
  io.to(room.roomId).emit("group_call_state", snapshot);
  const notifiedChatIds = new Set();
  for (const participant of room.participants.values()) {
    if (participant.chatId && !notifiedChatIds.has(participant.chatId)) {
      notifiedChatIds.add(participant.chatId);
      io.to(participant.chatId).emit("group_call_state", snapshot);
    }
  }
  for (const invited of room.invited.values()) {
    if (invited.chatId && !notifiedChatIds.has(invited.chatId)) {
      notifiedChatIds.add(invited.chatId);
      io.to(invited.chatId).emit("group_call_state", snapshot);
    }
  }
}

function closeRoomIfNeeded(room, reason = "ended") {
  if (!room) {
    return false;
  }

  const connectedParticipants = Array.from(room.participants.values()).filter(
    (participant) => participant.connected !== false,
  ).length;
  const shouldClose =
    room.participants.size === 0 ||
    (room.hasEverConnected === true &&
      connectedParticipants <= 1 &&
      room.disconnectedParticipants.size === 0);

  if (!shouldClose) {
    return false;
  }

  const endedPayload = {
    roomId: room.roomId,
    reason,
    message: "Call ended",
  };

  io.to(room.roomId).emit("group_call_ended", endedPayload);
  const recipients = new Set();
  for (const participant of room.participants.values()) {
    if (participant.chatId && !recipients.has(participant.chatId)) {
      recipients.add(participant.chatId);
      io.to(participant.chatId).emit("group_call_ended", endedPayload);
    }
  }
  for (const invited of room.invited.values()) {
    if (invited.chatId && !recipients.has(invited.chatId)) {
      recipients.add(invited.chatId);
      io.to(invited.chatId).emit("group_call_ended", endedPayload);
    }
  }

  for (const timer of room.disconnectTimers.values()) {
    clearCallTimer(timer);
  }
  activeCallRooms.delete(room.roomId);
  return true;
}

function ensureCallRoom(roomId, { hostId, hostName, callType }) {
  let room = activeCallRooms.get(roomId);
  if (!room) {
    room = {
      roomId,
      hostId,
      callType,
      createdAt: new Date(),
      participants: new Map(),
      invited: new Map(),
      pendingSignals: new Map(),
      disconnectTimers: new Map(),
      disconnectedParticipants: new Map(),
    };
    activeCallRooms.set(roomId, room);
  }

  if (!room.participants.has(hostId)) {
    room.participants.set(hostId, {
      chatId: hostId,
      name: hostName || hostId,
      joinedAt: new Date(),
      connected: true,
      reconnectDeadline: null,
    });
  }

  return room;
}

function rememberSocketRoom(socket, roomId) {
  if (!socket.data.callRooms) {
    socket.data.callRooms = new Set();
  }
  socket.data.callRooms.add(roomId);
}

function removeParticipantFromRooms(chatId, socket, { temporary = false } = {}) {
  for (const [roomId, room] of activeCallRooms.entries()) {
    let changed = false;

    if (room.participants.has(chatId)) {
      if (temporary) {
        const participant = room.participants.get(chatId);
        participant.connected = false;
        participant.reconnectDeadline = new Date(Date.now() + CALL_DISCONNECT_GRACE_MS);
        room.disconnectedParticipants.set(chatId, participant.reconnectDeadline);
        if (room.disconnectTimers.has(chatId)) {
          clearCallTimer(room.disconnectTimers.get(chatId));
        }
        room.disconnectTimers.set(
          chatId,
          setTimeout(() => {
            const liveRoom = activeCallRooms.get(roomId);
            if (!liveRoom || !liveRoom.participants.has(chatId)) {
              return;
            }
            liveRoom.participants.delete(chatId);
            liveRoom.invited.delete(chatId);
            liveRoom.disconnectedParticipants.delete(chatId);
            liveRoom.disconnectTimers.delete(chatId);
            io.to(roomId).emit("group_participant_left", {
              roomId,
              participantId: chatId,
            });
            if (!closeRoomIfNeeded(liveRoom, "disconnect_timeout")) {
              emitRoomState(liveRoom);
            }
          }, CALL_DISCONNECT_GRACE_MS),
        );
        io.to(roomId).emit("group_participant_reconnecting", {
          roomId,
          participantId: chatId,
          reconnectDeadline: participant.reconnectDeadline,
        });
      } else {
        room.participants.delete(chatId);
        room.disconnectedParticipants.delete(chatId);
        if (room.disconnectTimers.has(chatId)) {
          clearCallTimer(room.disconnectTimers.get(chatId));
          room.disconnectTimers.delete(chatId);
        }
        io.to(roomId).emit("group_participant_left", {
          roomId,
          participantId: chatId,
        });
      }
      changed = true;
    }

    if (!temporary && room.invited.has(chatId)) {
      room.invited.delete(chatId);
      changed = true;
    }

    if (changed) {
      emitRoomState(room);
    }

    if (!closeRoomIfNeeded(room, temporary ? "reconnecting" : "disconnect") &&
        room.participants.size === 0 &&
        room.invited.size === 0) {
      activeCallRooms.delete(roomId);
    }
  }
}

async function isCallAllowed({ caller, recipient, recipientChatId }) {
  if (!caller || !recipient) {
    return false;
  }

  if (caller.blockedUsers.includes(recipientChatId)) {
    return false;
  }

  if (recipient.blockedUsers.includes(caller.chatId)) {
    return false;
  }

  const isContact = recipient.savedContacts.includes(caller.chatId);
  if (recipient.privacy.calls === "none") {
    return false;
  }

  if (recipient.privacy.calls === "contacts" && !isContact) {
    if (recipient.privacy.unknownCallersReject) {
      return false;
    }
  }

  return true;
}

async function sendCallPushNotification({
  token,
  callerId,
  callerName,
  callerAvatar = "",
  callType = "voice",
  callId,
  channelId,
  participantIds = [],
  participantNames = {},
  addedBy = "",
  isGroup = false,
  groupId = "",
  groupName = "",
}) {
  if (!token || !admin.apps.length) {
    return;
  }

  const payload = {
    token,
    data: {
      type: isGroup ? "group_call_invite" : "call",
      callerId: String(callerId || ""),
      callerName: String(callerName || callerId || "Unknown"),
      callerAvatar: String(callerAvatar || ""),
      callType: String(callType || "voice"),
      callId: String(callId || channelId || ""),
      channelId: String(channelId || callId || ""),
      roomId: String(channelId || callId || ""),
      groupId: String(groupId || ""),
      groupName: String(groupName || ""),
      participantCount: String((participantIds || []).length + 1),
      participantIds: JSON.stringify(participantIds || []),
      participantNames: JSON.stringify(participantNames || {}),
      addedBy: String(addedBy || callerName || callerId || ""),
      click_action: "FLUTTER_NOTIFICATION_CLICK",
    },
    android: {
      priority: "high",
      ttl: 120000,
      notification: {
        channelId: "convoo_calls",
        sound: "default",
        priority: "MAX",
        visibility: "PUBLIC",
      },
    },
  };

  await admin.messaging().send(payload);
}

async function getUserMobileCallTokens(user) {
  if (!user?._id) {
    return [];
  }
  const tokens = new Set();
  if (user.fcmToken) {
    tokens.add(String(user.fcmToken));
  }
  const devices = await Device.find({
    userId: user._id,
    type: "mobile",
    fcmToken: { $ne: null },
  }).select("fcmToken");
  for (const device of devices) {
    const token = String(device.fcmToken || "").trim();
    if (token) {
      tokens.add(token);
    }
  }
  return [...tokens];
}

function notifyGroupCallStartedToMembers({
  group,
  room,
  hostId,
  hostName,
  groupName,
  callType,
}) {
  const payload = {
    type: "group_call_started",
    groupId: group.groupId,
    groupName,
    roomId: room.roomId,
    callType,
    hostId,
    hostName,
    startedAt: room.createdAt,
  };
  for (const member of group.members || []) {
    io.to(member).emit("group_call_started", payload);
  }
}

/**
 * Sends a DATA-ONLY FCM payload (no "notification" field) to wake up the app in background.
 * This ensures the background handler is triggered in Flutter.
 */
async function sendDataOnlyPushNotification({
  token,
  senderId,
  senderName,
  senderAvatar = "",
  type = "text",
  messageId,
  content = null, // For non-E2EE or if we want to send encrypted blob
  payloads = [], // E2EE payloads
  groupId = null,
  groupName = null,
  isGroup = false,
}) {
  if (!token || !admin.apps.length) {
    return;
  }

  // Find the specific payload for the device (if applicable) or just send the first one
  // In practice, for a single FCM token (device), we should send the payload meant for it.
  const data = {
    type: isGroup ? "group_message" : "message",
    senderId: String(senderId || ""),
    senderName: String(senderName || "Unknown"),
    senderAvatar: String(senderAvatar || ""),
    messageType: String(type || "0"),
    messageId: String(messageId || ""),
    timestamp: new Date().toISOString(),
    click_action: "FLUTTER_NOTIFICATION_CLICK",
  };

  if (isGroup) {
    data.groupId = String(groupId || "");
    data.groupName = String(groupName || "");
  }

  if (payloads && payloads.length > 0) {
    // For E2EE, we send the encrypted payloads. 
    // The background handler will pick the one for its deviceId.
    data.payloads = JSON.stringify(payloads);
  } else if (content) {
    data.content = String(content);
  }

  const message = {
    token,
    data,
    android: {
      priority: "high",
      // Important for background waking:
      ttl: 3600 * 1000, // 1 hour
    },
    apns: {
      payload: {
        aps: {
          "content-available": 1, // Required for background delivery on iOS
        },
      },
    },
  };

  try {
    await admin.messaging().send(message);
    console.log(`[FCM] Data-only push sent to token: ${token.substring(0, 10)}...`);
  } catch (err) {
    console.error("[FCM] Push Error:", err);
  }
}

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, true);
      }
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("CORS origin not allowed"));
    },
  }),
);
app.post(
  "/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      if (!razorpayWebhookSecret) {
        return res.status(503).json({ error: "Webhook secret not configured" });
      }
      const signature = req.headers["x-razorpay-signature"];
      if (!signature) {
        return res.status(400).json({ error: "Missing webhook signature" });
      }
      const expected = crypto
        .createHmac("sha256", razorpayWebhookSecret)
        .update(req.body)
        .digest("hex");
      if (String(signature) !== expected) {
        return res.status(400).json({ error: "Invalid webhook signature" });
      }

      const event = JSON.parse(req.body.toString("utf8"));
      if (event?.event === "payment.captured") {
        const payment = event?.payload?.payment?.entity || {};
        const orderId = String(payment.order_id || "");
        const paymentId = String(payment.id || "");
        const amountInPaise = Number(payment.amount || 0);
        const tx = await PaymentTransaction.findOne({ razorpayOrderId: orderId });
        if (tx && tx.status !== "consumed") {
          const duplicate = await PaymentTransaction.findOne({
            razorpayPaymentId: paymentId,
            _id: { $ne: tx._id },
          }).select("_id");
          if (!duplicate && payment.status === "captured") {
            if (amountInPaise === Math.round(Number(tx.amount) * 100)) {
              tx.status = "confirmed";
              tx.razorpayPaymentId = paymentId;
              await tx.save();
              if (tx.purpose === "subscription") {
                await activateSubscriptionForUser({
                  chatId: tx.chatId,
                  plan: tx.plan || "monthly",
                  paymentAt: new Date(),
                });
              }
              console.log(
                `[PAYMENT_WEBHOOK] Captured payment confirmed: tx=${tx._id.toString()} order=${orderId}`,
              );
            }
          }
        }
      }
      return res.json({ received: true });
    } catch (error) {
      console.error("Webhook processing failed:", error);
      return res.status(500).json({ error: "Webhook processing failed" });
    }
  },
);
app.use(express.json());
app.use(
  cors({
    origin: (origin, callback) => {
      if (isAllowedCorsOrigin(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error("Origin not allowed by CORS"));
    },
    credentials: true,
  }),
);
app.use("/uploads", express.static(path.join(__dirname, "../uploads")));

// ── Multer Storage Configuration ───────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "../uploads");
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const allowedMediaMimeTypes = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
  "video/mp4",
  "video/webm",
  "audio/mpeg",
  "audio/mp4",
  "audio/aac",
  "audio/ogg",
  "audio/wav",
  "application/pdf",
]);
const upload = multer({
  storage,
  limits: {
    fileSize: 25 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const allowedExt = new Set([
      ".jpg",
      ".jpeg",
      ".png",
      ".webp",
      ".gif",
      ".mp4",
      ".webm",
      ".mp3",
      ".m4a",
      ".aac",
      ".ogg",
      ".wav",
      ".pdf",
    ]);
    if (!allowedMediaMimeTypes.has(file.mimetype) || !allowedExt.has(ext)) {
      cb(new Error("Unsupported file type"));
      return;
    }
    cb(null, true);
  },
});

const apkStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const apkDir = path.join(__dirname, "../uploads/apk");
    if (!fs.existsSync(apkDir)) fs.mkdirSync(apkDir, { recursive: true });
    cb(null, apkDir);
  },
  filename: (req, file, cb) => {
    const sanitized = (req.body.version || "latest")
      .toString()
      .replace(/[^0-9A-Za-z.+_-]/g, "_");
    cb(null, `convoo_${sanitized}_${Date.now()}.apk`);
  },
});
const apkUpload = multer({
  storage: apkStorage,
  limits: {
    fileSize: 250 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    if (file.mimetype !== "application/vnd.android.package-archive" || ext !== ".apk") {
      cb(new Error("Only APK files are allowed"));
      return;
    }
    cb(null, true);
  },
});

app.get("/", (req, res) => res.send("Convoo Server Running 🚀 (E2EE)"));

app.post("/groups/create", async (req, res) => {
  try {
    const ownerId = normalizeChatId(req.body.ownerId);
    const name = String(req.body.name || "").trim();
    const description = String(req.body.description || "").trim();
    const profilePhoto = String(req.body.profilePhoto || "").trim();
    const membersRaw = Array.isArray(req.body.members) ? req.body.members : [];
    const members = [...new Set(membersRaw.map((m) => normalizeChatId(m)).filter(Boolean))];
    if (!ownerId || !name) {
      return res.status(400).json({ error: "ownerId and name are required" });
    }
    if (!members.includes(ownerId)) members.unshift(ownerId);
    if (members.some((m) => m.startsWith(GHOST_PREFIX))) {
      return res.status(400).json({ error: "Ghost IDs cannot be added to groups" });
    }
    for (const member of members) {
      if (member === ownerId) continue;
      const allowed = await canBeAddedToGroup(member, ownerId);
      if (!allowed.ok) {
        return res.status(400).json({ error: `Cannot add ${member}: ${allowed.error}` });
      }
    }
    const groupId = generateGroupId();
    const group = await Group.create({
      groupId,
      name,
      description,
      profilePhoto,
      ownerId,
      admins: [ownerId],
      members,
      settings: {
        sendMessages: "all",
        editInfo: "admins",
        addMembers: "admins",
      },
    });
    await GroupParticipant.bulkWrite(
      members.map((memberId) => ({
        updateOne: {
          filter: { groupId, userId: memberId },
          update: {
            $set: {
              role:
                memberId === ownerId
                  ? "owner"
                  : group.admins.includes(memberId)
                  ? "admin"
                  : "member",
              status: "active",
              joinedBy: ownerId,
              removedAt: null,
              removedBy: null,
            },
            $setOnInsert: {
              joinedAt: new Date(),
            },
          },
          upsert: true,
        },
      })),
    );
    await GroupMessage.create({
      messageId: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      groupId,
      senderId: ownerId,
      content: `${ownerId} created the group`,
      systemType: "group_created",
      timestamp: new Date(),
    });
    for (const member of members) {
      if (member === ownerId) {
        continue;
      }
      await GroupMessage.create({
        messageId: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        groupId,
        senderId: ownerId,
        content: `${ownerId} added ${member}`,
        systemType: "member_added",
        timestamp: new Date(),
      });
      io.to(member).emit("group_added", {
        groupId,
        group: group.toObject(),
        addedBy: ownerId,
        message: `${ownerId} added you`,
      });
    }
    return res.json(group);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to create group" });
  }
});

app.get("/groups/:chatId", async (req, res) => {
  try {
    const chatId = normalizeChatId(req.params.chatId);
    const groups = await Group.find({ members: chatId }).sort({ createdAt: -1 });
    return res.json(groups);
  } catch (e) {
    return res.status(500).json({ error: "Failed to fetch groups" });
  }
});

app.get("/groups/detail/:groupId", async (req, res) => {
  try {
    const group = await Group.findOne({ groupId: req.params.groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    return res.json(group);
  } catch (e) {
    return res.status(500).json({ error: "Failed to fetch group" });
  }
});

app.get("/groups/messages/:groupId", async (req, res) => {
  try {
    // Plaintext group message history is disabled.
    // Group chat uses E2EE fan-out via /send (per-device encrypted payloads),
    // and history lives only on devices.
    return res.status(410).json({
      error: "Group plaintext history disabled (E2EE only)",
      code: "group_plaintext_disabled",
      messages: [],
    });
  } catch (e) {
    return res.status(500).json({ error: "Failed to fetch group messages" });
  }
});

app.post("/groups/send", async (req, res) => {
  try {
    // Plaintext group messages are disabled (E2EE only).
    // Use /send with encrypted payloads and include groupId metadata.
    return res.status(410).json({
      error: "Group plaintext messaging disabled (E2EE only)",
      code: "group_plaintext_disabled",
    });
  } catch (e) {
    return res.status(500).json({ error: "Failed to send group message" });
  }
});

app.post("/groups/update-settings", async (req, res) => {
  try {
    const { groupId, actorId, settings } = req.body;
    const group = await Group.findOne({ groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    if (!(group.ownerId === actorId || group.admins.includes(actorId))) {
      return res.status(403).json({ error: "Only owner/admin can update settings" });
    }
    group.settings = {
      sendMessages: settings?.sendMessages === "admins" ? "admins" : "all",
      editInfo: settings?.editInfo === "all" ? "all" : "admins",
      addMembers: settings?.addMembers === "all" ? "all" : "admins",
    };
    await group.save();
    return res.json(group);
  } catch (e) {
    return res.status(500).json({ error: "Failed to update settings" });
  }
});

app.post("/groups/add-members", async (req, res) => {
  try {
    const { groupId, actorId, members } = req.body;
    const group = await Group.findOne({ groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    const canAdd =
      group.settings?.addMembers === "all" ||
      group.ownerId === actorId ||
      group.admins.includes(actorId);
    if (!canAdd) return res.status(403).json({ error: "No permission to add members" });
    const normalized = [...new Set((Array.isArray(members) ? members : []).map((m) => normalizeChatId(m)).filter(Boolean))];
    if (normalized.some((m) => m.startsWith(GHOST_PREFIX))) {
      return res.status(400).json({ error: "Ghost IDs cannot be added to groups" });
    }
    for (const member of normalized) {
      const allowed = await canBeAddedToGroup(member, actorId);
      if (!allowed.ok) {
        return res.status(400).json({ error: `Cannot add ${member}: ${allowed.error}` });
      }
      if (!group.members.includes(member)) {
        group.members.push(member);
        await GroupParticipant.updateOne(
          { groupId: group.groupId, userId: member },
          {
            $set: {
              role: "member",
              status: "active",
              joinedBy: actorId,
              removedAt: null,
              removedBy: null,
            },
            $setOnInsert: { joinedAt: new Date() },
          },
          { upsert: true },
        );
        await GroupMessage.create({
          messageId: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
          groupId: group.groupId,
          senderId: actorId,
          content: `${actorId} added ${member}`,
          systemType: "member_added",
          timestamp: new Date(),
        });
        io.to(member).emit("group_added", {
          groupId: group.groupId,
          group: group.toObject(),
          addedBy: actorId,
          message: `${actorId} added you`,
        });
      }
    }
    await group.save();
    io.to(group.groupId).emit("group_updated", group.toObject());
    return res.json(group);
  } catch (e) {
    return res.status(500).json({ error: "Failed to add members" });
  }
});

app.post("/groups/invite-link", async (req, res) => {
  try {
    const { groupId, actorId } = req.body;
    const group = await Group.findOne({ groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    const canInvite =
      group.ownerId === actorId ||
      group.admins.includes(actorId) ||
      group.members.includes(actorId);
    if (!canInvite) return res.status(403).json({ error: "No permission to invite" });

    const token = generateInviteToken();
    const invite = await GroupInviteLink.create({
      inviteId: `inv_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      groupId: group.groupId,
      tokenHash: hashInviteToken(token),
      createdBy: actorId,
      approvalRequired: false,
      label: "direct_chat_invite",
    });
    return res.json({ token, inviteId: invite.inviteId, group });
  } catch (e) {
    return res.status(500).json({ error: "Failed to create invite link" });
  }
});

app.get("/groups/invite/:token", async (req, res) => {
  try {
    const invite = await GroupInviteLink.findOne({
      tokenHash: hashInviteToken(req.params.token),
      status: "active",
    });
    if (!invite) return res.status(404).json({ error: "Invite not found" });
    if (invite.expiresAt && invite.expiresAt < new Date()) {
      invite.status = "expired";
      await invite.save();
      return res.status(410).json({ error: "Invite expired" });
    }
    const group = await Group.findOne({ groupId: invite.groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    return res.json({
      groupId: group.groupId,
      name: group.name,
      description: group.description,
      profilePhoto: group.profilePhoto,
      memberCount: group.members.length,
    });
  } catch (e) {
    return res.status(500).json({ error: "Failed to fetch invite" });
  }
});

app.post("/groups/join-invite", async (req, res) => {
  try {
    const { token, chatId } = req.body;
    const memberId = normalizeChatId(chatId);
    const invite = await GroupInviteLink.findOne({
      tokenHash: hashInviteToken(token),
      status: "active",
    });
    if (!invite) return res.status(404).json({ error: "Invite not found" });
    if (invite.expiresAt && invite.expiresAt < new Date()) {
      invite.status = "expired";
      await invite.save();
      return res.status(410).json({ error: "Invite expired" });
    }
    const group = await Group.findOne({ groupId: invite.groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    if (!group.members.includes(memberId)) {
      group.members.push(memberId);
      await group.save();
      invite.usedCount += 1;
      invite.lastUsedAt = new Date();
      await invite.save();
      await GroupParticipant.updateOne(
        { groupId: group.groupId, userId: memberId },
        {
          $set: {
            role: "member",
            status: "active",
            joinedBy: invite.createdBy,
            removedAt: null,
            removedBy: null,
          },
          $setOnInsert: { joinedAt: new Date() },
        },
        { upsert: true },
      );
      await GroupMessage.create({
        messageId: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        groupId: group.groupId,
        senderId: memberId,
        content: `${memberId} joined using invite link`,
        systemType: "member_joined",
        timestamp: new Date(),
      });
      io.to(memberId).emit("group_added", {
        groupId: group.groupId,
        group: group.toObject(),
        addedBy: invite.createdBy,
        message: "You joined the group",
      });
      io.to(group.groupId).emit("group_updated", group.toObject());
    }
    return res.json(group);
  } catch (e) {
    return res.status(500).json({ error: "Failed to join group" });
  }
});

app.post("/groups/remove-member", async (req, res) => {
  try {
    const { groupId, actorId, memberId } = req.body;
    const group = await Group.findOne({ groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    if (group.ownerId === memberId) {
      return res.status(400).json({ error: "Owner cannot be removed" });
    }
    const actorIsOwner = group.ownerId === actorId;
    const actorIsManager = group.admins.includes(actorId);
    const targetIsManager = group.admins.includes(memberId);
    if (!(actorIsOwner || actorIsManager)) {
      return res.status(403).json({ error: "No permission to remove member" });
    }
    if (!actorIsOwner && targetIsManager) {
      return res.status(403).json({ error: "Managers can remove members only" });
    }
    group.members = group.members.filter((m) => m !== memberId);
    group.admins = group.admins.filter((m) => m !== memberId);
    await group.save();
    await GroupParticipant.updateOne(
      { groupId: group.groupId, userId: memberId },
      {
        $set: {
          status: "removed",
          removedAt: new Date(),
          removedBy: actorId,
        },
      },
    );
    await GroupMessage.create({
      messageId: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      groupId: group.groupId,
      senderId: actorId,
      content: `${actorId} removed ${memberId}`,
      systemType: "member_removed",
      timestamp: new Date(),
    });
    io.to(group.groupId).emit("group_updated", group.toObject());
    return res.json(group);
  } catch (e) {
    return res.status(500).json({ error: "Failed to remove member" });
  }
});

app.post("/groups/promote-admin", async (req, res) => {
  try {
    const { groupId, actorId, memberId } = req.body;
    const group = await Group.findOne({ groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    if (group.ownerId !== actorId) {
      return res.status(403).json({ error: "Only owner can promote admins" });
    }
    if (!group.members.includes(memberId)) {
      return res.status(400).json({ error: "Member is not in group" });
    }
    if (!group.admins.includes(memberId)) {
      group.admins.push(memberId);
      await group.save();
      await GroupParticipant.updateOne(
        { groupId: group.groupId, userId: memberId },
        { $set: { role: "admin", status: "active" } },
      );
      await GroupMessage.create({
        messageId: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        groupId: group.groupId,
        senderId: actorId,
        content: `${actorId} promoted ${memberId} to admin`,
        systemType: "admin_promoted",
        timestamp: new Date(),
      });
      io.to(group.groupId).emit("group_updated", group.toObject());
    }
    return res.json(group);
  } catch (e) {
    return res.status(500).json({ error: "Failed to promote admin" });
  }
});

app.post("/groups/demote-admin", async (req, res) => {
  try {
    const { groupId, actorId, memberId } = req.body;
    const group = await Group.findOne({ groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    if (group.ownerId !== actorId) {
      return res.status(403).json({ error: "Only owner can demote admins" });
    }
    if (memberId === group.ownerId) {
      return res.status(400).json({ error: "Owner cannot be demoted" });
    }
    group.admins = group.admins.filter((id) => id !== memberId && id !== group.ownerId);
    await group.save();
    await GroupParticipant.updateOne(
      { groupId: group.groupId, userId: memberId },
      { $set: { role: "member", status: "active" } },
    );
    await GroupMessage.create({
      messageId: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      groupId: group.groupId,
      senderId: actorId,
      content: `${actorId} demoted ${memberId}`,
      systemType: "admin_demoted",
      timestamp: new Date(),
    });
    io.to(group.groupId).emit("group_updated", group.toObject());
    return res.json(group);
  } catch (e) {
    return res.status(500).json({ error: "Failed to demote admin" });
  }
});

app.post("/groups/transfer-ownership", async (req, res) => {
  try {
    const { groupId, actorId, memberId } = req.body;
    const group = await Group.findOne({ groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    if (group.ownerId !== actorId) {
      return res.status(403).json({ error: "Only owner can transfer ownership" });
    }
    if (!group.members.includes(memberId)) {
      return res.status(400).json({ error: "Member is not in group" });
    }
    if (memberId === group.ownerId) {
      return res.json(group);
    }

    const previousOwnerId = group.ownerId;
    group.ownerId = memberId;
    if (!group.admins.includes(previousOwnerId)) {
      group.admins.push(previousOwnerId);
    }
    if (!group.admins.includes(memberId)) {
      group.admins.push(memberId);
    }
    await group.save();

    await GroupParticipant.updateOne(
      { groupId: group.groupId, userId: previousOwnerId },
      { $set: { role: "admin", status: "active" } },
    );
    await GroupParticipant.updateOne(
      { groupId: group.groupId, userId: memberId },
      { $set: { role: "owner", status: "active" } },
    );

    await GroupMessage.create({
      messageId: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      groupId: group.groupId,
      senderId: actorId,
      content: `${actorId} transferred ownership to ${memberId}`,
      systemType: "ownership_transferred",
      timestamp: new Date(),
    });
    io.to(group.groupId).emit("group_updated", group.toObject());
    return res.json(group);
  } catch (e) {
    return res.status(500).json({ error: "Failed to transfer ownership" });
  }
});

app.post("/groups/exit", async (req, res) => {
  try {
    const { groupId, chatId } = req.body;
    const group = await Group.findOne({ groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    if (group.ownerId === chatId) {
      return res.status(400).json({ error: "Owner must transfer ownership or delete group" });
    }
    group.members = group.members.filter((m) => m !== chatId);
    group.admins = group.admins.filter((m) => m !== chatId);
    await group.save();
    await GroupParticipant.updateOne(
      { groupId: group.groupId, userId: chatId },
      {
        $set: {
          status: "left",
          removedAt: new Date(),
          removedBy: chatId,
        },
      },
    );
    await GroupMessage.create({
      messageId: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      groupId: group.groupId,
      senderId: chatId,
      content: `${chatId} left`,
      systemType: "member_left",
      timestamp: new Date(),
    });
    io.to(group.groupId).emit("group_updated", group.toObject());
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: "Failed to exit group" });
  }
});

app.post("/groups/delete", async (req, res) => {
  try {
    const { groupId, actorId } = req.body;
    const group = await Group.findOne({ groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    if (group.ownerId !== actorId) {
      return res.status(403).json({ error: "Only owner can delete group" });
    }
    await GroupMessage.deleteMany({ groupId });
    await Group.deleteOne({ groupId });
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: "Failed to delete group" });
  }
});

app.get("/check-update", (req, res) => {
  const cfg = readUpdateConfig();
  return res.json({
    latest_version: cfg.latest_version,
    apk_url: cfg.apk_url,
    force_update: cfg.force_update,
    required: cfg.required,
    play_store_enabled: cfg.play_store_enabled,
    play_store_url: cfg.play_store_url,
    changelog: cfg.changelog,
  });
});

app.get("/admin/update-panel", (req, res) => {
  if ((req.query.key || "") !== UPDATE_API_KEY) {
    return res.status(401).send("Unauthorized");
  }
  const cfg = readUpdateConfig();
  const html = `
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Convoo APK Update Admin</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 24px; max-width: 760px; }
      .card { border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin-bottom: 16px; }
      input, textarea { width: 100%; padding: 10px; margin-top: 6px; margin-bottom: 12px; }
      button { background: #4A55FF; color: white; border: 0; border-radius: 8px; padding: 10px 16px; cursor: pointer; }
      .muted { color: #666; font-size: 12px; }
    </style>
  </head>
  <body>
    <h2>Convoo APK Update Admin</h2>
    <div class="card">
      <div><strong>Current Version:</strong> ${cfg.latest_version}</div>
      <div><strong>APK URL:</strong> ${cfg.apk_url || "-"}</div>
      <div><strong>Required:</strong> ${cfg.required ? "Yes" : "No"}</div>
      <div><strong>Play Store:</strong> ${cfg.play_store_enabled ? "Enabled" : "Disabled"}</div>
      <div><strong>Changelog:</strong> ${cfg.changelog || "-"}</div>
    </div>
    <form class="card" method="POST" action="/admin/update/upload?key=${encodeURIComponent(req.query.key)}" enctype="multipart/form-data">
      <h3>Upload APK + Publish</h3>
      <label>Version</label>
      <input name="version" placeholder="e.g. 0.0.10+3" required />
      <label>Required (important update popup)</label>
      <input type="checkbox" name="force_update" value="true" />
      <label>Play Store URL (optional)</label>
      <input name="play_store_url" placeholder="https://play.google.com/store/apps/details?id=..." />
      <label>Enable Play Store button</label>
      <input type="checkbox" name="play_store_enabled" value="true" />
      <label>Changelog</label>
      <textarea name="changelog" rows="4" placeholder="What changed"></textarea>
      <label>APK file</label>
      <input type="file" name="apk" accept=".apk,application/vnd.android.package-archive" required />
      <button type="submit">Upload & Publish</button>
      <p class="muted">This updates /check-update and sends an FCM topic alert (app_updates).</p>
    </form>
  </body>
</html>`;
  res.setHeader("content-type", "text/html; charset=utf-8");
  return res.send(html);
});

app.post(
  "/admin/update/upload",
  requireUpdateApiKey,
  apkUpload.single("apk"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "APK file is required" });
      }
      const version = String(req.body.version || "").trim();
      if (!version) {
        return res.status(400).json({ error: "version is required" });
      }
      const changelog = String(req.body.changelog || "").trim();
      const forceUpdate =
        String(req.body.force_update || "").toLowerCase() === "true" ||
        String(req.body.force_update || "").toLowerCase() === "on";
      const playStoreEnabled =
        String(req.body.play_store_enabled || "").toLowerCase() === "true" ||
        String(req.body.play_store_enabled || "").toLowerCase() === "on";
      const playStoreUrl = String(req.body.play_store_url || "").trim();
      const apkUrl = `${req.protocol}://${req.get("host")}/uploads/apk/${req.file.filename}`;

      const next = {
        latest_version: version,
        apk_url: apkUrl,
        force_update: forceUpdate,
        required: forceUpdate,
        play_store_enabled: playStoreEnabled,
        play_store_url: playStoreUrl,
        changelog,
      };
      writeUpdateConfig(next);

      try {
        if (admin.apps.length > 0) {
          await admin.messaging().send({
            topic: "app_updates",
            notification: {
              title: "Convoo update available",
              body: `Version ${version} is now available`,
            },
            data: {
              type: "APP_UPDATE",
              latest_version: version,
              force_update: forceUpdate ? "true" : "false",
            },
          });
        }
      } catch (pushErr) {
        console.error("Update push failed:", pushErr);
      }

      return res.json({ success: true, ...next });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "Failed to publish update" });
    }
  },
);

// ── Legacy stub — E2EE sends payloads, not readable history ─────────────────
app.get("/messages/:chatId", async (req, res) => {
  try {
    const messages = await Message.find({
      receiverChatId: req.params.chatId,
      status: { $ne: "read" }
    });
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/messages/:user1/:user2", (req, res) => res.json([]));

// ── Offline messages for a specific device ───────────────────────────────────
app.get("/messages/offline/:chatId/:deviceId", async (req, res) => {
  try {
    const { chatId, deviceId } = req.params;
    const query = {
      $or: [{ receiverChatId: chatId }, { senderChatId: chatId }],
      "payloads.deviceId": { $in: [deviceId, "all"] }
    };
    if (req.query.messageId) {
      query.messageId = String(req.query.messageId);
    }

    const messages = await Message.find(query).sort({ timestamp: 1 });

    const formatted = messages.map(msg => {
      const payload =
        msg.payloads.find(p => p.deviceId === deviceId) ||
        msg.payloads.find(p => p.deviceId === "all");
      return {
        messageId: msg.messageId,
        clientMessageId: msg.clientMessageId || null,
        senderChatId: msg.senderChatId,
        receiverChatId: msg.receiverChatId,
        groupId: msg.groupId || null,
        senderDeviceId: msg.senderDeviceId,
        senderDevicePublicKey: msg.senderDevicePublicKey || null,
        timestamp: msg.timestamp,
        ghostSessionId: msg.ghostSessionId || null,
        type: typeof msg.type === "number" ? msg.type : 0,
        mediaUrl: msg.mediaUrl || null,
        fileName: msg.fileName || null,
        fileSize: typeof msg.fileSize === "number" ? msg.fileSize : null,
        replyToId: msg.replyToId || null,
        replyToContent: msg.replyToContent || null,
        isViewOnce: Boolean(msg.isViewOnce),
        isForwarded: Boolean(msg.isForwarded),
        expiresAt: msg.expiresAt || null,
        payload
      };
    }).filter(m => m.payload != null);

    res.json(formatted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── ACK: delete payload, delete message if none remain ───────────────────────
app.post("/messages/ack", async (req, res) => {
  try {
    const { messageId, deviceId } = req.body;
    const message = await Message.findOne({ messageId });
    if (!message) return res.status(404).json({ message: "Message not found" });

    message.payloads = message.payloads.filter(p => p.deviceId !== deviceId);

    if (message.payloads.length === 0) {
      await Message.deleteOne({ messageId });
      return res.json({ message: "Message fully deleted ✅" });
    }
    await message.save();
    return res.json({ message: "Payload ACK'd" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Send encrypted message ───────────────────────────────────────────────────
app.post("/send", async (req, res) => {
  try {
    const {
      messageId,
      clientMessageId,
      senderChatId,
      receiverChatId,
      senderDeviceId,
      senderDevicePublicKey,
      payloads,
      groupId,
      timestamp,
      replyToId,
      replyToContent,
      type,
      mediaUrl,
      fileName,
      fileSize,
      isViewOnce,
    } = req.body;

    if (!messageId || !senderChatId || !receiverChatId || !senderDeviceId || !payloads) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const normalizedReceiver = normalizeChatId(receiverChatId);
    const senderRealId = normalizeChatId(senderChatId);
    if (!senderRealId) {
      return res.status(400).json({ error: "Invalid senderChatId" });
    }

    let resolvedSenderDevicePublicKey = senderDevicePublicKey
      ? String(senderDevicePublicKey)
      : null;
    if (!resolvedSenderDevicePublicKey && senderDeviceId) {
      const senderForKey = await User.findOne({ chatId: senderRealId }).select("devices");
      const senderDevice = senderForKey?.devices?.find(
        d => String(d.deviceId || "") === String(senderDeviceId)
      );
      resolvedSenderDevicePublicKey =
        senderDevice?.encryptionPublicKey || null;
    }

    const now = new Date();
    if (normalizedReceiver.startsWith(GHOST_PREFIX)) {
      const doc = await GhostId.findOne({
        ghostId: normalizedReceiver,
        isActive: true,
        expiresAt: { $gt: now },
      });
      if (!doc) {
        return res.status(410).json({
          error: "This Ghost ID is no longer active",
          code: "ghost_inactive",
        });
      }
      if (!doc.peerChatId) {
        return res.status(409).json({
          error: "This Ghost ID has not been linked yet",
          code: "ghost_unlinked",
        });
      }
      if (senderRealId !== doc.realChatId && senderRealId !== doc.peerChatId) {
        return res.status(403).json({ error: "Not authorized for this Ghost ID" });
      }

      const resolvedReceiver =
        senderRealId === doc.realChatId ? doc.peerChatId : doc.realChatId;
      const senderPublicId = doc.ghostId;

      const message = new Message({
        messageId,
        clientMessageId: clientMessageId || null,
        senderChatId: senderPublicId,
        receiverChatId: resolvedReceiver,
        senderDeviceId,
        senderDevicePublicKey: resolvedSenderDevicePublicKey,
        payloads,
        groupId: groupId ? normalizeChatId(groupId) : null,
        timestamp: timestamp || now,
        replyToId: replyToId || null,
        replyToContent: replyToContent || null,
        type: typeof type === "number" ? type : 0,
        mediaUrl: mediaUrl || null,
        fileName: fileName || null,
        fileSize: typeof fileSize === "number" ? fileSize : null,
        isViewOnce: Boolean(isViewOnce),
        ghostSessionId: doc.ghostId,
      });

      const recipient = await User.findOne({ chatId: resolvedReceiver });
      if (recipient && recipient.blockedUsers.includes(senderRealId)) {
        return res.status(403).json({ error: "You are blocked by this user" });
      }

      if (recipient && recipient.privacy.messages !== "everyone") {
        const isContact = recipient.savedContacts.includes(senderRealId);
        if (recipient.privacy.messages === "none") {
          return res.status(403).json({ error: "This user does not accept messages" });
        }
        if (recipient.privacy.messages === "contacts" && !isContact) {
        }
      }

      await message.save();

      io.to(resolvedReceiver).emit("newMessage", message.toObject());
      io.to(senderRealId).emit("newMessage", message.toObject());

      if (recipient && recipient.fcmToken) {
        const isOnline = onlineUsers.has(resolvedReceiver) && onlineUsers.get(resolvedReceiver).size > 0;
        if (!isOnline) {
          sendDataOnlyPushNotification({
            token: recipient.fcmToken,
            senderId: senderPublicId,
            senderName: senderPublicId,
            type: typeof type === "number" ? type : 0,
            messageId,
            payloads,
            groupId: groupId ? normalizeChatId(groupId) : null,
            isGroup: Boolean(groupId),
          });
        }
      }

      return res.status(201).json({ message: "Encrypted message sent" });
    }

    const senderResolution = await resolveGhostSenderId(senderChatId);
    if (senderResolution.ghostInvalid) {
      return res.status(410).json({
        error: "This Ghost ID is no longer active",
        code: "ghost_inactive_sender",
      });
    }
    const senderPublicId = senderResolution.senderPublicId;

    const ghostResolution = await resolveGhostReceiverId(receiverChatId);
    if (ghostResolution.ghostInvalid) {
      return res.status(410).json({
        error: "This Ghost ID is no longer active",
        code: "ghost_inactive",
      });
    }

    const resolvedReceiver = ghostResolution.receiverChatId;
    const ghostSessionId = ghostResolution.ghostSessionId;

    const message = new Message({
      messageId,
      clientMessageId: clientMessageId || null,
      senderChatId: senderPublicId,
      receiverChatId: resolvedReceiver,
      senderDeviceId,
      senderDevicePublicKey: resolvedSenderDevicePublicKey,
      payloads,
      groupId: groupId ? normalizeChatId(groupId) : null,
      timestamp: timestamp || now,
      replyToId: replyToId || null,
      replyToContent: replyToContent || null,
      type: typeof type === "number" ? type : 0,
      mediaUrl: mediaUrl || null,
      fileName: fileName || null,
      fileSize: typeof fileSize === "number" ? fileSize : null,
      isViewOnce: Boolean(isViewOnce),
      ghostSessionId: ghostSessionId || null,
    });

    const recipient = await User.findOne({ chatId: resolvedReceiver });
    if (recipient && recipient.blockedUsers.includes(senderRealId)) {
      return res.status(403).json({ error: "You are blocked by this user" });
    }

    if (recipient && recipient.privacy.messages !== "everyone") {
      const isContact = recipient.savedContacts.includes(senderRealId);
      if (recipient.privacy.messages === "contacts" && !isContact) {
      } else if (recipient.privacy.messages === "none") {
        return res.status(403).json({ error: "This user does not accept messages" });
      }
    }

    await message.save();

    io.to(resolvedReceiver).emit("newMessage", message.toObject());
    io.to(senderRealId).emit("newMessage", message.toObject());

    if (recipient && recipient.fcmToken) {
      const isOnline = onlineUsers.has(resolvedReceiver) && onlineUsers.get(resolvedReceiver).size > 0;
      if (!isOnline) {
        sendDataOnlyPushNotification({
          token: recipient.fcmToken,
          senderId: senderPublicId,
          senderName: senderPublicId,
          type: typeof type === "number" ? type : 0,
          messageId,
          payloads,
          groupId: groupId ? normalizeChatId(groupId) : null,
          isGroup: Boolean(groupId),
        });
      }
    }

    res.status(201).json({ message: "Encrypted message sent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Fetch key bundle (for ECDH before sending) ───────────────────────────────
app.get("/keys/:chatId", async (req, res) => {
  try {
    const requestedId = normalizeChatId(req.params.chatId);
    if (requestedId.startsWith(GHOST_PREFIX)) {
      const now = new Date();
      const doc = await GhostId.findOne({
        ghostId: requestedId,
        isActive: true,
        expiresAt: { $gt: now },
      });
      if (!doc) {
        return res.status(410).json({ message: "This Ghost ID is no longer active" });
      }
      if (!doc.peerChatId) {
        return res.status(409).json({ message: "This Ghost ID has not been linked yet" });
      }

      const requesterChatId = normalizeChatId(req.query.requesterChatId);
      if (!requesterChatId) {
        return res.status(400).json({ message: "requesterChatId is required" });
      }

      const lookupChatId =
        requesterChatId === doc.realChatId
          ? doc.peerChatId
          : requesterChatId === doc.peerChatId
            ? doc.realChatId
            : null;
      if (!lookupChatId) {
        return res.status(403).json({ message: "Not authorized for this Ghost ID" });
      }

      const user = await User.findOne({ chatId: lookupChatId });
      if (!user) return res.status(404).json({ message: "User not found" });

      const devices = [];
      for (const device of user.devices) {
        let oneTimePrekey = null;
        if (device.oneTimePrekeys && device.oneTimePrekeys.length > 0) {
          oneTimePrekey = device.oneTimePrekeys.shift();
        }
        devices.push({
          deviceId: device.deviceId,
          encryptionPublicKey: device.encryptionPublicKey,
          signingPublicKey: device.signingPublicKey,
          signedPrekey: device.signedPrekey,
          oneTimePrekey
        });
      }
      await User.updateOne(
        { _id: user._id },
        { $set: { devices: user.devices } },
      );

      return res.json({
        chatId: requestedId,
        identityPublicKey: user.identityPublicKey,
        devices,
      });
    }

    const resolution = await resolveGhostReceiverId(req.params.chatId);
    if (resolution.ghostInvalid && requestedId.startsWith(GHOST_PREFIX)) {
      return res.status(410).json({ message: "This Ghost ID is no longer active" });
    }

    const lookupChatId = resolution.receiverChatId;
    const user = await User.findOne({ chatId: lookupChatId });
    if (!user) return res.status(404).json({ message: "User not found" });

    const devices = [];
    for (const device of user.devices) {
      let oneTimePrekey = null;
      if (device.oneTimePrekeys && device.oneTimePrekeys.length > 0) {
        oneTimePrekey = device.oneTimePrekeys.shift();
      }
      devices.push({
        deviceId: device.deviceId,
        encryptionPublicKey: device.encryptionPublicKey,
        signingPublicKey: device.signingPublicKey,
        signedPrekey: device.signedPrekey,
        oneTimePrekey
      });
    }
    // Avoid full-document validation when only consuming one-time prekeys.
    // Some legacy users may not satisfy all required fields for a full save().
    await User.updateOne(
      { _id: user._id },
      { $set: { devices: user.devices } },
    );

    res.json({
      chatId: requestedId.startsWith(GHOST_PREFIX) ? requestedId : user.chatId,
      identityPublicKey: user.identityPublicKey,
      devices,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Ghost ID (temporary anonymous chat identity) ───────────────────────────

app.post("/ghost/create", async (req, res) => {
  try {
    const realChatId = normalizeChatId(req.body.realChatId);
    if (!realChatId) {
      return res.status(400).json({ error: "realChatId is required" });
    }

    const now = new Date();
    const existing = await GhostId.findOne({
      realChatId,
      isActive: true,
      expiresAt: { $gt: now },
    });
    if (existing) {
      return res.status(409).json({
        error: "You already have an active Ghost ID. Revoke it before creating a new one.",
        ghostId: existing.ghostId,
        expiresAt: existing.expiresAt,
        serverNow: now.toISOString(),
      });
    }

    const ghostId = await generateUniqueGhostId();
    const expiresAt = new Date(Date.now() + GHOST_DEFAULT_TTL_MS);

    await GhostId.create({
      ghostId,
      realChatId,
      createdAt: now,
      expiresAt,
      isActive: true,
    });

    res.status(201).json({
      ghostId,
      expiresAt,
      ttlHours: GHOST_DEFAULT_TTL_MS / (60 * 60 * 1000),
      serverNow: now.toISOString(),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/ghost/consume", async (req, res) => {
  try {
    const ghostId = normalizeChatId(req.body.ghostId);
    const consumerChatId = normalizeChatId(req.body.consumerChatId);
    if (!ghostId || !ghostId.startsWith(GHOST_PREFIX)) {
      return res.status(400).json({ error: "Invalid ghost id" });
    }
    if (!consumerChatId) {
      return res.status(400).json({ error: "consumerChatId is required" });
    }

    const now = new Date();
    const doc = await GhostId.findOne({
      ghostId,
      isActive: true,
      expiresAt: { $gt: now },
    });
    if (!doc) {
      return res.status(410).json({
        error: "This Ghost ID is no longer active",
        ghostId,
        serverNow: now.toISOString(),
      });
    }

    if (doc.realChatId === consumerChatId) {
      return res.status(400).json({
        error: "You cannot link your own Ghost ID",
        ghostId: doc.ghostId,
        expiresAt: doc.expiresAt,
        serverNow: now.toISOString(),
      });
    }

    if (doc.peerChatId) {
      return res.status(409).json({
        error:
          doc.peerChatId === consumerChatId
            ? "This Ghost ID is already linked to your account"
            : "This Ghost ID has already been linked",
        code: doc.peerChatId === consumerChatId ? "ghost_already_linked" : "ghost_taken",
        ghostId: doc.ghostId,
        expiresAt: doc.expiresAt,
        serverNow: now.toISOString(),
      });
    }

    doc.peerChatId = consumerChatId;
    doc.consumedAt = now;
    await doc.save();

    io.to(doc.realChatId).emit("ghost_linked", {
      ghostId: doc.ghostId,
      expiresAt: doc.expiresAt,
      serverNow: now.toISOString(),
    });
    io.to(consumerChatId).emit("ghost_linked", {
      ghostId: doc.ghostId,
      expiresAt: doc.expiresAt,
      serverNow: now.toISOString(),
    });

    res.status(200).json({
      success: true,
      ghostId: doc.ghostId,
      expiresAt: doc.expiresAt,
      serverNow: now.toISOString(),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/ghost/revoke", async (req, res) => {
  try {
    const realChatId = normalizeChatId(req.body.realChatId);
    const ghostIdRaw = (req.body.ghostId || "").toString().trim();
    let doc = null;
    if (ghostIdRaw.startsWith(GHOST_PREFIX)) {
      doc = await GhostId.findOne({ ghostId: ghostIdRaw });
    } else if (realChatId) {
      doc = await GhostId.findOne({
        realChatId,
        isActive: true,
      });
    }
    if (!doc) {
      return res.status(404).json({ error: "No Ghost ID found to revoke" });
    }

    const now = new Date();
    await Message.deleteMany({ ghostSessionId: doc.ghostId });
    await GhostId.updateOne(
      { _id: doc._id },
      {
        $set: {
          isActive: false,
          releasedAt: now,
        },
      },
    );

    res.json({ success: true, ghostId: doc.ghostId, serverNow: now.toISOString() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/ghost/resolve/:ghostId", async (req, res) => {
  try {
    const ghostId = normalizeChatId(req.params.ghostId);
    if (!ghostId.startsWith(GHOST_PREFIX)) {
      return res.status(400).json({ error: "Invalid ghost id" });
    }
    const now = new Date();
    const doc = await GhostId.findOne({
      ghostId,
      isActive: true,
      expiresAt: { $gt: now },
    });
    if (!doc) {
      return res.status(200).json({
        active: false,
        ghostId,
        error: "This Ghost ID is no longer active",
        serverNow: now.toISOString(),
      });
    }
    res.json({
      active: true,
      ghostId: doc.ghostId,
      expiresAt: doc.expiresAt,
      createdAt: doc.createdAt,
      consumed: Boolean(doc.peerChatId),
      serverNow: now.toISOString(),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/ghost/status/:realChatId", async (req, res) => {
  try {
    const realChatId = normalizeChatId(req.params.realChatId);
    if (!realChatId) {
      return res.status(400).json({ error: "realChatId is required" });
    }
    const now = new Date();
    const doc = await GhostId.findOne({
      realChatId,
      isActive: true,
      expiresAt: { $gt: now },
    });
    if (!doc) {
      return res.json({ active: false });
    }
    res.json({
      active: true,
      ghostId: doc.ghostId,
      expiresAt: doc.expiresAt,
      createdAt: doc.createdAt,
      consumed: Boolean(doc.peerChatId),
      serverNow: now.toISOString(),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Auth (mobile + desktop) ────────────────────────────────────────────────

app.post("/auth/mobile/session", async (req, res) => {
  try {
    if (!(await ensureMobileOtpAllowed(req, res))) {
      return;
    }

    const {
      firebaseIdToken,
      name,
      identityPublicKey,
      deviceId,
      deviceName,
      platform,
      profilePhotoUrl,
    } = req.body;

    if (!firebaseIdToken || !name || !identityPublicKey || !deviceId) {
      return res.status(400).json({
        error: "firebaseIdToken, name, identityPublicKey and deviceId are required",
      });
    }
    if (admin.apps.length === 0) {
      return res.status(503).json({ error: "Firebase auth is not configured on backend" });
    }

    const decoded = await admin.auth().verifyIdToken(String(firebaseIdToken));
    console.log(decoded);

    const firebaseUid = String(decoded.uid || "").trim();
    const phoneNumber = normalizePhoneNumber(decoded.phone_number);
    if (!firebaseUid) {
      return res.status(400).json({ error: "Verified Firebase UID missing from token" });
    }

    const userLookupConditions = [{ firebaseUid }];
    if (phoneNumber) {
      userLookupConditions.push({ phoneNumber });
    }

    let user = await User.findOne({
      $or: userLookupConditions,
    });
    let historyCleared = false;
    const trimmedName = String(name || "").trim();
    const normalizedProfilePhoto = String(profilePhotoUrl || "").trim();
    if (user) {
      const activeMobile = await getActiveMobileDevice(user._id, user.activeMobileDeviceId);
      if (activeMobile && activeMobile.deviceId !== String(deviceId)) {
        return res.status(409).json({
          error: "Another mobile device is active for this account",
          code: "MOBILE_DEVICE_ACTIVE",
        });
      }

      if (!user.firebaseUid) {
        user.firebaseUid = firebaseUid;
      }
      if (phoneNumber) {
        user.phoneNumber = phoneNumber;
      }
      user.identityPublicKey = identityPublicKey;
      user.name = trimmedName || user.name;
      user.profilePhoto = normalizedProfilePhoto;
      user.devices = [];
      await clearUserCommunicationHistory(user.chatId);
      user.historyClearedAt = new Date();
      historyCleared = true;
    } else {
      user = new User({
        name: trimmedName,
        chatId: await generateUniqueChatId(),
        firebaseUid,
        phoneNumber,
        identityPublicKey,
        profilePhoto: normalizedProfilePhoto,
      });
    }

    const isNewUser = user.isNew;
    let mobileDevice = await Device.findOne({ deviceId: String(deviceId) });
    if (mobileDevice && String(mobileDevice.userId) !== String(user._id)) {
      return res.status(409).json({ error: "Device is already linked to another account" });
    }

    if (!mobileDevice) {
      mobileDevice = new Device({
        userId: user._id,
        deviceId: String(deviceId),
        deviceName: sanitizeDeviceName(deviceName, "Mobile Device"),
        type: "mobile",
        platform: normalizePlatform(platform),
        isActive: true,
        lastActive: new Date(),
      });
    } else {
      mobileDevice.userId = user._id;
      mobileDevice.deviceName = sanitizeDeviceName(deviceName, mobileDevice.deviceName);
      mobileDevice.platform = normalizePlatform(platform);
      mobileDevice.type = "mobile";
      mobileDevice.isActive = true;
      mobileDevice.lastActive = new Date();
    }

    user.activeMobileDeviceId = mobileDevice.deviceId;
    user.mobileLastHeartbeatAt = new Date();
    await user.save();
    await mobileDevice.save();

    return res
      .status(isNewUser ? 201 : 200)
      .json(buildAuthResponse(user, mobileDevice, { historyCleared }));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to create mobile session" });
  }
});

app.post("/auth/mobile/refresh", async (req, res) => {
  try {
    if (!(await ensureMobileOtpAllowed(req, res))) {
      return;
    }

    const { firebaseIdToken, deviceId, deviceName, platform } = req.body;

    if (!firebaseIdToken || !deviceId) {
      return res.status(400).json({
        error: "firebaseIdToken and deviceId are required",
      });
    }
    if (admin.apps.length === 0) {
      return res.status(503).json({
        error: "Firebase auth is not configured on backend",
      });
    }

    const decoded = await admin.auth().verifyIdToken(String(firebaseIdToken));
    const firebaseUid = String(decoded.uid || "").trim();
    const phoneNumber = normalizePhoneNumber(decoded.phone_number);

    if (!firebaseUid) {
      return res.status(400).json({
        error: "Verified Firebase UID missing from token",
      });
    }

    const userLookupConditions = [{ firebaseUid }];
    if (phoneNumber) {
      userLookupConditions.push({ phoneNumber });
    }

    const user = await User.findOne({
      $or: userLookupConditions,
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const activeMobile = await getActiveMobileDevice(
      user._id,
      user.activeMobileDeviceId,
    );
    if (activeMobile && activeMobile.deviceId !== String(deviceId)) {
      return res.status(409).json({
        error: "Another mobile device is active for this account",
        code: "MOBILE_DEVICE_ACTIVE",
      });
    }

    const mobileDevice = await Device.findOne({
      userId: user._id,
      deviceId: String(deviceId),
      type: "mobile",
    });
    if (!mobileDevice) {
      return res.status(404).json({ error: "Device session not found" });
    }

    if (!user.firebaseUid) {
      user.firebaseUid = firebaseUid;
    }
    if (phoneNumber) {
      user.phoneNumber = phoneNumber;
    }

    mobileDevice.deviceName = sanitizeDeviceName(
      deviceName,
      mobileDevice.deviceName || "Mobile Device",
    );
    mobileDevice.platform = normalizePlatform(platform || mobileDevice.platform);
    mobileDevice.type = "mobile";
    mobileDevice.isActive = true;
    mobileDevice.lastActive = new Date();

    user.activeMobileDeviceId = mobileDevice.deviceId;
    user.mobileLastHeartbeatAt = new Date();

    await Promise.all([user.save(), mobileDevice.save()]);

    return res.json(buildAuthResponse(user, mobileDevice));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to refresh mobile session" });
  }
});

app.post(
  "/auth/mobile/logout",
  requireAuth,
  requireDeviceType("mobile"),
  async (req, res) => {
    try {
      req.device.isActive = false;
      req.device.tokenVersion += 1;
      req.device.socketId = null;
      req.device.lastActive = new Date();
      await req.device.save();

      req.user.activeMobileDeviceId = null;
      req.user.mobileLastHeartbeatAt = null;
      await req.user.save();

      await revokeAllDesktopDevices(req.user._id);
      io.to(`user:${req.user.chatId}`).emit("force_logout", {
        reason: "mobile_logout",
      });

      return res.json({ success: true });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Failed to logout mobile session" });
    }
  },
);

app.post(
  "/auth/mobile/heartbeat",
  requireAuth,
  requireDeviceType("mobile"),
  async (req, res) => {
    try {
      req.device.lastActive = new Date();
      req.device.isActive = true;
      req.user.activeMobileDeviceId = req.device.deviceId;
      req.user.mobileLastHeartbeatAt = new Date();
      await Promise.all([req.device.save(), req.user.save()]);
      return res.json({ success: true, lastActive: req.device.lastActive });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Heartbeat failed" });
    }
  },
);

app.post("/auth/desktop/qr/session", async (req, res) => {
  try {
    const { deviceId, deviceName, platform } = req.body;
    if (!deviceId) {
      return res.status(400).json({ error: "deviceId is required" });
    }
    const session = await createQrSession({
      deviceId: String(deviceId),
      deviceName: sanitizeDeviceName(deviceName, "Desktop Device"),
      platform: normalizePlatform(platform),
    });
    return res.status(201).json({
      sessionId: session.sessionId,
      expiresAt: session.expiresAt,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to create QR session" });
  }
});

app.post(
  "/auth/desktop/qr/approve",
  requireAuth,
  requireDeviceType("mobile"),
  async (req, res) => {
    try {
      const { sessionId } = req.body;
      if (!sessionId) {
        return res.status(400).json({ error: "sessionId is required" });
      }

      const activeMobile = await getActiveMobileDevice(
        req.user._id,
        req.user.activeMobileDeviceId,
      );
      if (!activeMobile || activeMobile.deviceId !== req.device.deviceId) {
        return res.status(403).json({ error: "Active mobile session required" });
      }

      const session = await AuthSession.findOne({ sessionId, type: "qr" });
      if (!session || isExpired(session) || session.status !== "pending") {
        return res.status(410).json({ error: "QR session is no longer active" });
      }
      if (!(await ensureDeviceLimit(req.user._id))) {
        return res.status(409).json({ error: "Maximum linked devices reached" });
      }

      let desktopDevice = await Device.findOne({ deviceId: session.deviceId });
      if (!desktopDevice) {
        desktopDevice = new Device({
          userId: req.user._id,
          deviceId: session.deviceId,
          deviceName: session.deviceName,
          type: "desktop",
          platform: session.platform,
          isActive: true,
          lastActive: new Date(),
        });
      } else if (String(desktopDevice.userId) !== String(req.user._id)) {
        return res.status(409).json({ error: "Desktop device is linked elsewhere" });
      } else {
        desktopDevice.deviceName = session.deviceName;
        desktopDevice.platform = session.platform;
        desktopDevice.type = "desktop";
        desktopDevice.isActive = true;
        desktopDevice.lastActive = new Date();
      }
      await desktopDevice.save();

      const authPayload = buildAuthResponse(req.user, desktopDevice);
      await markApproved(session, authPayload);
      io.to(`auth_session:${sessionId}`).emit("session_approved", authPayload);

      return res.json({ success: true, device: buildLinkedDeviceResponse(desktopDevice) });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Failed to approve QR session" });
    }
  },
);

app.get("/auth/desktop/session-status/:sessionId", async (req, res) => {
  try {
    const authPayload = await consumeApprovedSession(String(req.params.sessionId || ""));
    if (authPayload) {
      return res.json({ status: "approved", ...authPayload });
    }

    const session = await AuthSession.findOne({ sessionId: String(req.params.sessionId || "") });
    if (!session || isExpired(session)) {
      return res.status(410).json({ status: "expired" });
    }
    return res.json({ status: session.status, expiresAt: session.expiresAt });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to read desktop session" });
  }
});

app.post(
  "/auth/desktop/pin/generate",
  requireAuth,
  requireDeviceType("mobile"),
  async (req, res) => {
    try {
      const activeMobile = await getActiveMobileDevice(
        req.user._id,
        req.user.activeMobileDeviceId,
      );
      if (!activeMobile || activeMobile.deviceId !== req.device.deviceId) {
        return res.status(403).json({ error: "Active mobile session required" });
      }

      const payload = await createPinSession({
        userId: req.user._id,
        deviceId: String(req.body.deviceId || `pin_${Date.now()}`),
        deviceName: sanitizeDeviceName(req.body.deviceName, "Desktop Device"),
        platform: normalizePlatform(req.body.platform || "unknown"),
      });

      return res.json({
        sessionId: payload.session.sessionId,
        pin: payload.pin,
        expiresAt: payload.session.expiresAt,
      });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Failed to generate PIN" });
    }
  },
);

app.post("/auth/desktop/pin/login", async (req, res) => {
  try {
    const { phoneNumber, pin, deviceId, deviceName, platform } = req.body;
    if (!phoneNumber || !pin || !deviceId) {
      return res.status(400).json({ error: "phoneNumber, pin and deviceId are required" });
    }

    const user = await User.findOne({ phoneNumber: String(phoneNumber).trim() });
    if (!user) {
      return res.status(404).json({ error: "Phone number not found" });
    }
    const activeMobile = await getActiveMobileDevice(user._id, user.activeMobileDeviceId);
    if (!activeMobile) {
      return res.status(403).json({ error: "Desktop login requires an active mobile session" });
    }
    if (!(await ensureDeviceLimit(user._id))) {
      return res.status(409).json({ error: "Maximum linked devices reached" });
    }

    const pinCheck = await validatePinSession({ phoneUserId: user._id, pin: String(pin) });
    if (!pinCheck.ok) {
      return res.status(400).json({ error: pinCheck.code });
    }

    let desktopDevice = await Device.findOne({ deviceId: String(deviceId) });
    if (!desktopDevice) {
      desktopDevice = new Device({
        userId: user._id,
        deviceId: String(deviceId),
        deviceName: sanitizeDeviceName(deviceName, "Desktop Device"),
        type: "desktop",
        platform: normalizePlatform(platform),
        isActive: true,
        lastActive: new Date(),
      });
    } else if (String(desktopDevice.userId) !== String(user._id)) {
      return res.status(409).json({ error: "Desktop device is linked elsewhere" });
    } else {
      desktopDevice.deviceName = sanitizeDeviceName(deviceName, desktopDevice.deviceName);
      desktopDevice.platform = normalizePlatform(platform);
      desktopDevice.type = "desktop";
      desktopDevice.isActive = true;
      desktopDevice.lastActive = new Date();
    }
    await desktopDevice.save();

    const session = pinCheck.session;
    session.status = "used";
    session.consumedAt = new Date();
    await session.save();

    return res.json(buildAuthResponse(user, desktopDevice));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to login desktop device" });
  }
});

app.get("/auth/devices", requireAuth, async (req, res) => {
  try {
    const devices = await Device.find({
      userId: req.user._id,
      isActive: true,
    }).sort({ lastActive: -1 });
    return res.json(devices.map(buildLinkedDeviceResponse));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to load linked devices" });
  }
});

app.delete(
  "/auth/devices/:deviceId",
  requireAuth,
  requireDeviceType("mobile"),
  async (req, res) => {
    try {
      const target = await Device.findOne({
        userId: req.user._id,
        deviceId: String(req.params.deviceId || ""),
      });
      if (!target) {
        return res.status(404).json({ error: "Device not found" });
      }
      if (target.deviceId === req.device.deviceId) {
        return res.status(400).json({ error: "Use mobile logout for current mobile device" });
      }

      const revoked = await revokeDevice(target.deviceId);
      io.to(`device:${target.deviceId}`).emit("force_logout", {
        reason: "device_revoked",
      });
      return res.json({ success: true, device: buildLinkedDeviceResponse(revoked) });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Failed to revoke device" });
    }
  },
);

// ── Registration ───────────────────────────────────────────────────────────

/**
 * Handles user registration and login via Phone Number.
 * This unifies the auth flow and prevents account duplication.
 */
app.post("/register-phone", async (req, res) => {
  try {
    if (!(await ensureMobileOtpAllowed(req, res))) {
      return;
    }
    const { phoneNumber, name, identityPublicKey, profilePhotoUrl } = req.body;

    if (!phoneNumber || !identityPublicKey) {
      return res.status(400).json({ error: "phoneNumber and identityPublicKey are required" });
    }

    const cleanPhone = phoneNumber.trim();
    
    // 1. Check if user already exists with this phone number
    let user = await User.findOne({ phoneNumber: cleanPhone });

    if (user) {
      // Returning user: Update identity key and return existing chatId
      user.identityPublicKey = identityPublicKey;
      user.devices = []; // Clear devices for new login session (standard E2EE practice)
      await clearUserCommunicationHistory(user.chatId);
      user.historyClearedAt = new Date();
      if (name && !user.name) user.name = name.trim();
      user.profilePhoto = String(profilePhotoUrl || "").trim();
      await user.save();
      
      console.log(`📱 User Login: ${cleanPhone} -> @${user.chatId}`);
      return res.status(200).json({ 
        message: "Account restored", 
        chatId: user.chatId,
        name: user.name,
        profilePhoto: user.profilePhoto 
      });
    }

    // 2. New user: Generate unique 7-digit Chat ID and create account
    const chatId = await generateUniqueChatId();
    user = new User({
      phoneNumber: cleanPhone,
      name: (name || "Convoo User").trim(),
      chatId,
      identityPublicKey,
      profilePhoto: profilePhotoUrl || "",
      devices: []
    });
    
    await user.save();
    console.log(`✨ New User Registered: ${cleanPhone} -> @${chatId}`);

    res.status(201).json({ 
      message: "User created", 
      chatId,
      name: user.name 
    });
  } catch (err) {
    console.error("❌ Register-Phone Error:", err);
    res.status(500).json({ error: "Internal server error during registration" });
  }
});

// ── Register user (requires identityPublicKey for E2EE) ─────────────────────
// If user with same name exists (e.g. reinstall), return existing chatId
app.post("/register", async (req, res) => {
  try {
    const { name, identityPublicKey } = req.body;

    if (!name || !identityPublicKey) {
      return res.status(400).json({ error: "name and identityPublicKey are required" });
    }

    const existing = await User.findOne({ name: name.trim() });
    if (existing) {
      existing.identityPublicKey = identityPublicKey;
      existing.devices = [];
      await existing.save();
      return res.status(201).json({ message: "Account restored", chatId: existing.chatId });
    }

    const chatId = await generateUniqueChatId();
    const newUser = new User({ name: name.trim(), chatId, identityPublicKey, devices: [] });
    await newUser.save();

    res.status(201).json({ message: "User created", chatId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Register device (upload public key bundle) ───────────────────────────────
app.post("/register-device", async (req, res) => {
  try {
    const {
      deviceId,
      encryptionPublicKey,
      signingPublicKey,
      signedPrekey,
      oneTimePrekeys,
    } = req.body;
    const chatId = normalizeChatId(req.body.chatId);

    const user = await User.findOne({ chatId });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Remove any existing device with same deviceId (re-registration)
    user.devices = user.devices.filter(d => d.deviceId !== deviceId);
    user.devices.push({ deviceId, encryptionPublicKey, signingPublicKey, signedPrekey, oneTimePrekeys: oneTimePrekeys || [] });

    await user.save();
    res.json({ message: "Device registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Update FCM Token ──────────────────────────────────────────────────────────
app.post("/update-fcm-token", async (req, res) => {
  try {
    const { chatId, fcmToken, deviceId } = req.body;
    if (!chatId || !fcmToken) return res.status(400).json({ error: "chatId and fcmToken are required" });

    // Update User model (legacy support or global token)
    await User.findOneAndUpdate({ chatId }, { fcmToken });

    // Update Device model if deviceId is provided
    if (deviceId) {
      await Device.findOneAndUpdate({ deviceId }, { fcmToken });
    } else {
      // If no deviceId, try to find the active mobile device for this user
      const user = await User.findOne({ chatId });
      if (user && user.activeMobileDeviceId) {
        await Device.findOneAndUpdate({ deviceId: user.activeMobileDeviceId }, { fcmToken });
      }
    }

    res.json({ message: "FCM token updated ✅" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Sync Saved Contacts (for Mutual Moments) ────────────────────────────────
app.post("/user/sync-contacts", async (req, res) => {
  try {
    const chatId = normalizeChatId(req.body.chatId);
    const savedContacts = Array.isArray(req.body.savedContacts)
      ? req.body.savedContacts.map(normalizeChatId).filter(Boolean)
      : [];
    if (!chatId) return res.status(400).json({ error: "chatId is required" });

    await User.findOneAndUpdate({ chatId }, { savedContacts });
    res.json({ message: "Contacts synced successfully ✅" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/user/:chatId/profile", async (req, res) => {
  try {
    const chatId = normalizeChatId(req.params.chatId);
    const user = await User.findOne({ chatId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const moodExpired =
      user.mood?.expiresAt && new Date(user.mood.expiresAt).getTime() <= Date.now();
    if (moodExpired) {
      user.mood = { label: "", emoji: "", color: "#4A55FF", expiresAt: null };
      await user.save();
    }

    return res.json({
      chatId: user.chatId,
      name: user.name,
      about: user.about || "Available",
      profilePhoto: user.profilePhoto || "",
      email: user.email || "",
      emailVerified: user.emailVerified === true,
      mood: user.mood || {
        label: "",
        emoji: "",
        color: "#4A55FF",
        expiresAt: null,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/user/:chatId/profile", async (req, res) => {
  try {
    const chatId = normalizeChatId(req.params.chatId);
    const user = await User.findOne({ chatId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const {
      name,
      about,
      profilePhoto,
      email,
      mood,
    } = req.body;

    if (typeof name === "string" && name.trim()) {
      user.name = name.trim();
    }
    if (typeof about === "string") {
      user.about = about.trim() || "Available";
    }
    if (typeof profilePhoto === "string") {
      user.profilePhoto = profilePhoto.trim();
    }
    if (typeof email === "string") {
      const nextEmail = email.trim();
      if (nextEmail !== user.email) {
        user.email = nextEmail || undefined;
        user.emailVerified = false;
      }
    }
    if (mood && typeof mood === "object") {
      user.mood = {
        label: String(mood.label || "").trim(),
        emoji: String(mood.emoji || "").trim(),
        color: String(mood.color || "#4A55FF"),
        expiresAt: mood.expiresAt ? new Date(mood.expiresAt) : null,
      };
    }

    await user.save();
    await syncEmailToFirebaseStore({
      chatId: user.chatId,
      email: user.email || "",
      emailVerified: user.emailVerified === true,
    });
    io.to(user.chatId).emit("profile_updated", {
      chatId: user.chatId,
      name: user.name,
      about: user.about,
      profilePhoto: user.profilePhoto,
      mood: user.mood,
    });

    res.json({
      message: "Profile updated successfully",
      profile: {
        chatId: user.chatId,
        name: user.name,
        about: user.about,
        profilePhoto: user.profilePhoto,
        email: user.email || "",
        emailVerified: user.emailVerified === true,
        mood: user.mood,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/user/:chatId/email/verify", async (req, res) => {
  try {
    const chatId = normalizeChatId(req.params.chatId);
    const firebaseIdToken = String(req.body?.firebaseIdToken || "");
    const user = await User.findOne({ chatId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    if (!user.email) {
      return res.status(400).json({ error: "Add an email first" });
    }
    if (!isFirebaseAdminReady()) {
      return res.status(503).json({ error: "Firebase verification is not configured on server" });
    }
    if (!firebaseIdToken) {
      return res.status(400).json({ error: "firebaseIdToken is required" });
    }

    let decoded;
    try {
      decoded = await admin.auth().verifyIdToken(firebaseIdToken, true);
    } catch (error) {
      return res.status(401).json({ error: "Invalid or expired Firebase token" });
    }

    const verifiedEmail = String(decoded.email || "").trim().toLowerCase();
    const profileEmail = String(user.email || "").trim().toLowerCase();
    if (!decoded.email_verified || !verifiedEmail) {
      return res.status(400).json({ error: "Email is not verified in Firebase" });
    }
    if (verifiedEmail !== profileEmail) {
      return res.status(400).json({ error: "Verified Firebase email does not match profile email" });
    }

    user.emailVerified = true;
    await user.save();
    await syncEmailToFirebaseStore({
      chatId: user.chatId,
      email: user.email || "",
      emailVerified: true,
    });
    res.json({
      message: "Email verified successfully",
      email: user.email,
      emailVerified: true,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Get call history ─────────────────────────────────────────────────────────
app.get("/calls/:chatId", async (req, res) => {
  try {
    const calls = await Call.find({
      $or: [{ caller: req.params.chatId }, { receiver: req.params.chatId }]
    }).sort({ timestamp: -1 }).limit(50);
    res.json(calls);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Get user info (Respecting Privacy) ───────────────────────────────────────
app.get("/user/:chatId", async (req, res) => {
  try {
    const requesterId = normalizeChatId(req.query.requesterId);
    const targetChatId = normalizeChatId(req.params.chatId);

    if (targetChatId.startsWith(GHOST_PREFIX)) {
      const doc = await GhostId.findOne({
        ghostId: targetChatId,
        isActive: true,
        expiresAt: { $gt: new Date() },
      });
      if (!doc) {
        return res.status(200).json({
          chatId: targetChatId,
          name: "Ghost Chat",
          isGhostChat: true,
          isGhostInactive: true,
          profilePhoto: "",
          canForward: false,
        });
      }
      return res.status(200).json({
        chatId: targetChatId,
        name: "Ghost Chat (Anonymous)",
        isGhostChat: true,
        isGhostInactive: false,
        profilePhoto: "",
        canForward: false,
      });
    }

    const user = await User.findOne({ chatId: targetChatId });
    if (!user) return res.status(404).json({ message: "User not found" });

    const moodExpired =
      user.mood?.expiresAt && new Date(user.mood.expiresAt).getTime() <= Date.now();
    if (moodExpired) {
      user.mood = { label: "", emoji: "", color: "#4A55FF", expiresAt: null };
      await user.save();
    }

    // Default response (limited)
    const baseResponse = { chatId: user.chatId, name: user.name };

    if (!requesterId || requesterId === user.chatId) {
      return res.json({
        ...baseResponse,
        privacy: user.privacy,
        about: user.about || "Available",
        profilePhoto: user.profilePhoto || "",
        email: user.email || "",
        emailVerified: user.emailVerified === true,
        mood: user.mood || {
          label: "",
          emoji: "",
          color: "#4A55FF",
          expiresAt: null,
        },
      });
    }

    // Check Block Status
    if (user.blockedUsers.includes(requesterId)) {
      return res.json({ ...baseResponse, isBlocked: true });
    }

    const requester = await User.findOne({ chatId: requesterId }).select("privacy");
    const response = { ...baseResponse };

    // Helper functions for common lists
    const isContact = user.savedContacts.includes(requesterId);

    // Online Status Visibility
    const showOS =
      canViewerSeePresence(user, requesterId, "onlineStatus") &&
      hasReciprocalPresencePermission(requester, "onlineStatus");

    if (showOS) response.isOnline = onlineUsers.has(user.chatId) && onlineUsers.get(user.chatId).size > 0;

    // Profile Photo Visibility
    const ppSetting = user.privacy.profilePhoto;
    const ppExc = user.privacy.profilePhotoExceptions || [];
    let showPP = false;
    if (ppSetting === "everyone") showPP = true;
    else if (ppSetting === "contacts") showPP = isContact;
    else if (ppSetting === "except") showPP = isContact && !ppExc.includes(requesterId);

    if (showPP) response.profilePhoto = user.profilePhoto;

    // Last Seen Visibility
    const showLS =
      canViewerSeePresence(user, requesterId, "lastSeen") &&
      hasReciprocalPresencePermission(requester, "lastSeen");

    if (showLS) response.lastSeen = user.lastSeen;

    // About Visibility
    const abSetting = user.privacy.about;
    const abExc = user.privacy.aboutExceptions || [];
    let showAB = false;
    if (abSetting === "everyone") showAB = true;
    else if (abSetting === "contacts") showAB = isContact;
    else if (abSetting === "except") showAB = isContact && !abExc.includes(requesterId);
    if (showAB) response.about = user.about;

    if (showAB && user.mood?.label) {
      response.mood = user.mood;
    }

    // Forwarding Privacy
    const fwdSetting = user.privacy.forwarding;
    let canForward = true;
    if (fwdSetting === "disable") canForward = false;
    else if (fwdSetting === "contacts") canForward = isContact;
    response.canForward = canForward;

    res.json(response);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Privacy Settings management ──────────────────────────────────────────────
app.get("/user/:chatId/privacy", async (req, res) => {
  try {
    const user = await User.findOne({ chatId: req.params.chatId });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user.privacy || {});
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/user/:chatId/privacy", async (req, res) => {
  try {
    const { privacy } = req.body;
    const user = await User.findOneAndUpdate(
      { chatId: req.params.chatId },
      { $set: { privacy } },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user.privacy);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ── Blocking System ─────────────────────────────────────────────────────────
app.get("/user/:chatId/blocked", async (req, res) => {
  try {
    const user = await User.findOne({ chatId: req.params.chatId });
    if (!user) return res.status(404).json({ error: "User not found" });

    // Return basic info for each blocked user
    const blockedDetails = await User.find(
      { chatId: { $in: user.blockedUsers || [] } },
      "name chatId profilePhoto about mood",
    );
    res.json(blockedDetails);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/user/block", async (req, res) => {
  try {
    const { chatId, targetChatId } = req.body;
    const resolution = await resolveGhostReceiverId(targetChatId);
    const normalizedTarget = normalizeChatId(targetChatId);
    if (resolution.ghostInvalid && normalizedTarget.startsWith(GHOST_PREFIX)) {
      return res.status(410).json({ error: "This Ghost ID is no longer active" });
    }
    const resolvedTarget = resolution.receiverChatId;
    await User.findOneAndUpdate(
      { chatId },
      { $addToSet: { blockedUsers: resolvedTarget } },
    );
    res.json({ message: "User blocked successfully" });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/user/unblock", async (req, res) => {
  try {
    const { chatId, targetChatId } = req.body;
    const resolution = await resolveGhostReceiverId(targetChatId);
    const resolvedTarget = resolution.ghostInvalid
      ? normalizeChatId(targetChatId)
      : resolution.receiverChatId;
    await User.findOneAndUpdate(
      { chatId },
      { $pull: { blockedUsers: resolvedTarget } },
    );
    res.json({ message: "User unblocked successfully" });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ── Account Management ───────────────────────────────────────────────────────
function ensureRazorpayReady(res) {
  if (razorpayClient) {
    return true;
  }
  res.status(503).json({
    error: "Payment provider is not configured on server",
  });
  return false;
}

function validatePaymentConfigAtStartup() {
  if (!razorpayKeyId || !razorpayKeySecret) {
    console.warn(
      "Razorpay configuration is missing. Payment endpoints will return 503 until RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are set.",
    );
  }
  if (!razorpayWebhookSecret) {
    console.warn(
      "RAZORPAY_WEBHOOK_SECRET is missing. Webhook verification is disabled until configured.",
    );
  }
  if (allowedOrigins.length === 0) {
    throw new Error(
      "Missing CORS_ORIGINS configuration. Set allowed app origins as comma-separated list.",
    );
  }
}

function isSubscriptionActive(user) {
  const sub = user?.subscription;
  if (!sub || sub.status !== "active" || !sub.endsAt) {
    return false;
  }
  return new Date(sub.endsAt).getTime() > Date.now();
}

function getChangeChatIdPrice({ isSubscriber, optionType }) {
  const base = CHANGE_CHAT_ID_PRICES[optionType] ?? CHANGE_CHAT_ID_PRICES.random;
  return Math.max(1, base - (isSubscriber ? CHANGE_CHAT_ID_SUBSCRIBER_DISCOUNT : 0));
}

function computePaymentAmount({ purpose, plan, optionType, user }) {
  if (purpose === "subscription") {
    return SUBSCRIPTION_PRICES[plan] ?? 0;
  }
  if (purpose === "change_chat_id") {
    return getChangeChatIdPrice({
      isSubscriber: isSubscriptionActive(user),
      optionType,
    });
  }
  return 0;
}

function verifyRazorpaySignature({ orderId, paymentId, signature }) {
  const hmac = crypto.createHmac("sha256", razorpayKeySecret);
  hmac.update(`${orderId}|${paymentId}`);
  const digest = hmac.digest("hex");
  return digest === signature;
}

async function getPaymentFailureCooldown({ chatId, purpose }) {
  const windowStart = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const failedTxs = await PaymentTransaction.find({
    chatId,
    purpose,
    status: "failed",
    updatedAt: { $gte: windowStart },
  })
    .sort({ updatedAt: -1 })
    .limit(3)
    .select("updatedAt");

  if (failedTxs.length < 3) {
    return null;
  }
  const thirdRecentFailureAt = failedTxs[2]?.updatedAt;
  if (!thirdRecentFailureAt) {
    return null;
  }
  const blockedUntil = new Date(
    new Date(thirdRecentFailureAt).getTime() + 24 * 60 * 60 * 1000,
  );
  if (Date.now() >= blockedUntil.getTime()) {
    return null;
  }
  return blockedUntil;
}

async function activateSubscriptionForUser({ chatId, plan, paymentAt = new Date() }) {
  const user = await User.findOne({ chatId });
  if (!user) return null;
  const now = new Date();
  const baseStart = isSubscriptionActive(user) && user.subscription?.endsAt
    ? new Date(user.subscription.endsAt)
    : now;
  const nextEnd = new Date(baseStart);
  if (plan === "yearly") {
    nextEnd.setFullYear(nextEnd.getFullYear() + 1);
  } else {
    nextEnd.setMonth(nextEnd.getMonth() + 1);
  }
  user.subscription = {
    plan,
    status: "active",
    startsAt: baseStart,
    endsAt: nextEnd,
    lastPaymentAt: paymentAt,
  };
  await user.save();
  return user.subscription;
}

app.get("/billing/subscription-status/:chatId", requireAuth, async (req, res) => {
  try {
    const chatId = normalizeChatId(req.params.chatId);
    if (chatId !== req.auth.chatId) {
      return res.status(403).json({ error: "Forbidden" });
    }
    const user = await User.findOne({ chatId }).select("chatId subscription");
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const active = isSubscriptionActive(user);
    if (!active && user.subscription?.status === "active") {
      await User.updateOne(
        { chatId },
        {
          $set: {
            "subscription.status": "expired",
          },
        },
      );
      user.subscription.status = "expired";
    }
    return res.json({
      chatId,
      active,
      subscription: user.subscription || {
        plan: "none",
        status: "inactive",
        startsAt: null,
        endsAt: null,
        lastPaymentAt: null,
      },
    });
  } catch (error) {
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/payments/create-order", requireAuth, createOrderRateLimiter, async (req, res) => {
  try {
    if (!ensureRazorpayReady(res)) return;
    const {
      purpose,
      plan,
      optionType = "random",
      desiredChatId = null,
    } = req.body || {};
    const chatId = normalizeChatId(req.auth.chatId);
    if (!chatId || !["subscription", "change_chat_id"].includes(purpose)) {
      return res.status(400).json({ error: "Invalid payment request" });
    }
    if (purpose === "subscription" && !["monthly", "yearly"].includes(plan)) {
      return res.status(400).json({ error: "Invalid subscription plan" });
    }

    const user = await User.findOne({ chatId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const blockedUntil = await getPaymentFailureCooldown({ chatId, purpose });
    if (blockedUntil) {
      return res.status(429).json({
        error: "Payment retries are temporarily blocked due to multiple failed attempts",
        blockedUntil,
        retryAfterSeconds: Math.max(
          1,
          Math.floor((blockedUntil.getTime() - Date.now()) / 1000),
        ),
      });
    }

    const amountInr = computePaymentAmount({ purpose, plan, optionType, user });
    if (!amountInr || amountInr <= 0) {
      return res.status(400).json({ error: "Unable to compute payment amount" });
    }

    const existingPending = await PaymentTransaction.findOne({
      chatId,
      purpose,
      status: { $in: ["created", "pending"] },
      ...(purpose === "subscription"
        ? { plan }
        : { "metadata.optionType": optionType }),
    }).sort({ createdAt: -1 });
    if (existingPending) {
      return res.status(200).json({
        success: true,
        reusedPending: true,
        message: "Reusing existing pending payment order",
        transactionId: existingPending._id.toString(),
        orderId: existingPending.razorpayOrderId,
        amount: existingPending.amount,
        currency: existingPending.currency,
        razorpayKeyId,
        purpose: existingPending.purpose,
        plan: existingPending.plan,
      });
    }

    const order = await razorpayClient.orders.create({
      amount: amountInr * 100,
      currency: "INR",
      receipt: `rcpt_${chatId}_${Date.now()}`,
      notes: {
        chatId,
        purpose,
        plan: plan || "",
        optionType,
        desiredChatId: desiredChatId || "",
      },
    });

    const tx = await PaymentTransaction.create({
      chatId,
      purpose,
      plan: purpose === "subscription" ? plan : null,
      amount: amountInr,
      currency: "INR",
      status: "created",
      razorpayOrderId: order.id,
      metadata: {
        optionType,
        desiredChatId,
      },
    });
    console.log(
      `[PAYMENT] Created order tx=${tx._id.toString()} chatId=${chatId} purpose=${purpose} amount=${amountInr}`,
    );

    return res.json({
      transactionId: tx._id.toString(),
      orderId: order.id,
      amount: amountInr,
      currency: "INR",
      razorpayKeyId,
      purpose,
      plan: tx.plan,
      discountApplied:
        purpose === "change_chat_id" &&
        isSubscriptionActive(user),
    });
  } catch (error) {
    console.error("Create payment order error:", error);
    const providerMessage =
      error?.error?.description ||
      error?.description ||
      error?.message ||
      "";
    return res.status(500).json({
      error: providerMessage
        ? `Unable to create payment order: ${providerMessage}`
        : "Unable to create payment order",
    });
  }
});

app.post("/payments/verify", requireAuth, verifyPaymentRateLimiter, async (req, res) => {
  try {
    if (!ensureRazorpayReady(res)) return;
    const {
      transactionId,
      razorpayOrderId,
      razorpayPaymentId,
      razorpaySignature,
    } = req.body || {};
    if (!transactionId || !razorpayOrderId || !razorpayPaymentId || !razorpaySignature) {
      return res.status(400).json({ error: "Missing payment verification fields" });
    }

    const tx = await PaymentTransaction.findById(transactionId);
    if (!tx) {
      return res.status(404).json({ error: "Payment transaction not found" });
    }
    if (tx.chatId !== req.auth.chatId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    if (tx.status === "confirmed" || tx.status === "consumed") {
      return res.json({
        success: true,
        alreadyConfirmed: true,
        transactionId: tx._id.toString(),
        purpose: tx.purpose,
      });
    }

    if (tx.razorpayOrderId !== razorpayOrderId) {
      tx.status = "failed";
      await tx.save();
      return res.status(400).json({ error: "Order mismatch" });
    }

    const duplicatePayment = await PaymentTransaction.findOne({
      razorpayPaymentId,
      _id: { $ne: tx._id },
    }).select("_id");
    if (duplicatePayment) {
      tx.status = "failed";
      await tx.save();
      return res.status(409).json({ error: "Payment ID already used" });
    }

    const isValidSignature = verifyRazorpaySignature({
      orderId: razorpayOrderId,
      paymentId: razorpayPaymentId,
      signature: razorpaySignature,
    });

    if (!isValidSignature) {
      tx.status = "failed";
      tx.razorpayPaymentId = razorpayPaymentId;
      tx.razorpaySignature = razorpaySignature;
      await tx.save();
      return res.status(400).json({ error: "Invalid payment signature" });
    }

    const remotePayment = await razorpayClient.payments.fetch(razorpayPaymentId);
    if (!remotePayment || remotePayment.status !== "captured") {
      tx.status = "failed";
      await tx.save();
      return res.status(400).json({ error: "Payment is not captured on provider" });
    }
    if (String(remotePayment.order_id || "") !== razorpayOrderId) {
      tx.status = "failed";
      await tx.save();
      return res.status(400).json({ error: "Provider order mismatch" });
    }
    const providerAmount = Number(remotePayment.amount || 0);
    const expectedAmountPaise = Math.round(Number(tx.amount) * 100);
    if (providerAmount !== expectedAmountPaise) {
      tx.status = "failed";
      await tx.save();
      return res.status(400).json({ error: "Provider amount mismatch" });
    }

    tx.status = "confirmed";
    tx.razorpayPaymentId = razorpayPaymentId;
    tx.razorpaySignature = razorpaySignature;
    await tx.save();
    console.log(
      `[PAYMENT] Verified payment tx=${tx._id.toString()} chatId=${tx.chatId} purpose=${tx.purpose} amount=${tx.amount}`,
    );

    let subscription = null;
    if (tx.purpose === "subscription") {
      subscription = await activateSubscriptionForUser({
        chatId: tx.chatId,
        plan: tx.plan || "monthly",
        paymentAt: new Date(),
      });
    }

    return res.json({
      success: true,
      transactionId: tx._id.toString(),
      purpose: tx.purpose,
      subscription,
    });
  } catch (error) {
    console.error("Payment verify error:", error);
    return res.status(500).json({ error: "Unable to verify payment" });
  }
});

app.post("/payments/:transactionId/fail", requireAuth, async (req, res) => {
  try {
    const requestedStatus = String(req.body?.status || "pending");
    const nextStatus = requestedStatus === "failed" ? "failed" : "pending";
    const tx = await PaymentTransaction.findById(req.params.transactionId);
    if (!tx) {
      return res.status(404).json({ error: "Payment transaction not found" });
    }
    if (tx.chatId !== req.auth.chatId) {
      return res.status(403).json({ error: "Forbidden" });
    }
    if (tx.status === "confirmed" || tx.status === "consumed") {
      return res.status(409).json({ error: "Payment already completed" });
    }
    tx.status = nextStatus;
    await tx.save();
    return res.json({ success: true, status: tx.status });
  } catch (error) {
    return res.status(500).json({ error: "Unable to update transaction state" });
  }
});

app.get("/payments/pending/:chatId", requireAuth, async (req, res) => {
  try {
    const chatId = normalizeChatId(req.params.chatId);
    if (chatId !== req.auth.chatId) {
      return res.status(403).json({ error: "Forbidden" });
    }
    const pending = await PaymentTransaction.find({
      chatId,
      status: { $in: ["created", "pending"] },
    })
      .sort({ createdAt: -1 })
      .limit(25);
    return res.json(
      pending.map((tx) => ({
        transactionId: tx._id.toString(),
        purpose: tx.purpose,
        plan: tx.plan,
        amount: tx.amount,
        currency: tx.currency,
        status: tx.status,
        orderId: tx.razorpayOrderId,
        createdAt: tx.createdAt,
      })),
    );
  } catch (error) {
    return res.status(500).json({ error: "Unable to fetch pending payments" });
  }
});

app.post("/payments/refund", requireAuth, async (req, res) => {
  try {
    if (!ensureRazorpayReady(res)) return;
    const { transactionId, amount, reason = "" } = req.body || {};
    if (!transactionId) {
      return res.status(400).json({ error: "transactionId is required" });
    }
    const tx = await PaymentTransaction.findById(transactionId);
    if (!tx) {
      return res.status(404).json({ error: "Payment transaction not found" });
    }
    if (tx.chatId !== req.auth.chatId) {
      return res.status(403).json({ error: "Forbidden" });
    }
    if (tx.status === "consumed") {
      return res.status(409).json({ error: "Refund is not allowed after usage" });
    }
    if (tx.status !== "confirmed") {
      return res.status(409).json({ error: "Only confirmed payments can be refunded" });
    }
    if (!tx.razorpayPaymentId) {
      return res.status(400).json({ error: "Missing payment reference for refund" });
    }

    const refundAmount = Math.min(
      Number(tx.amount),
      Math.max(1, Number(amount || tx.amount)),
    );
    const refund = await razorpayClient.payments.refund(tx.razorpayPaymentId, {
      amount: Math.round(refundAmount * 100),
      speed: "normal",
      notes: {
        reason: String(reason || ""),
        transactionId: tx._id.toString(),
      },
    });

    const savedRefund = await PaymentRefund.create({
      chatId: tx.chatId,
      transactionId: tx._id,
      razorpayPaymentId: tx.razorpayPaymentId,
      razorpayRefundId: refund.id,
      amount: refundAmount,
      currency: tx.currency || "INR",
      status: refund.status || "processed",
      reason: String(reason || ""),
      metadata: refund,
    });

    console.log(
      `[REFUND] Created refund tx=${tx._id.toString()} refundId=${savedRefund.razorpayRefundId} amount=${savedRefund.amount}`,
    );
    return res.json({
      success: true,
      refundId: savedRefund.razorpayRefundId,
      amount: savedRefund.amount,
      status: savedRefund.status,
    });
  } catch (error) {
    console.error("Refund error:", error);
    return res.status(500).json({ error: "Unable to process refund" });
  }
});

app.get("/payments/refunds/:chatId", requireAuth, async (req, res) => {
  try {
    const chatId = normalizeChatId(req.params.chatId);
    if (chatId !== req.auth.chatId) {
      return res.status(403).json({ error: "Forbidden" });
    }
    const refunds = await PaymentRefund.find({ chatId })
      .sort({ createdAt: -1 })
      .limit(25);
    return res.json(
      refunds.map((refund) => ({
        refundId: refund.razorpayRefundId,
        transactionId: refund.transactionId?.toString(),
        paymentId: refund.razorpayPaymentId,
        amount: refund.amount,
        currency: refund.currency,
        status: refund.status,
        reason: refund.reason,
        createdAt: refund.createdAt,
      })),
    );
  } catch (error) {
    return res.status(500).json({ error: "Unable to fetch refunds" });
  }
});

app.get("/payments/history/:chatId", requireAuth, async (req, res) => {
  try {
    const chatId = normalizeChatId(req.params.chatId);
    if (chatId !== req.auth.chatId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const [transactions, refunds] = await Promise.all([
      PaymentTransaction.find({ chatId })
        .sort({ createdAt: -1 })
        .limit(100),
      PaymentRefund.find({ chatId })
        .sort({ createdAt: -1 })
        .limit(100),
    ]);

    return res.json({
      transactions: transactions.map((tx) => ({
        id: tx._id.toString(),
        kind: "payment",
        purpose: tx.purpose,
        plan: tx.plan,
        amount: tx.amount,
        currency: tx.currency,
        status: tx.status,
        orderId: tx.razorpayOrderId,
        paymentId: tx.razorpayPaymentId,
        createdAt: tx.createdAt,
        updatedAt: tx.updatedAt,
        metadata: tx.metadata || {},
      })),
      refunds: refunds.map((refund) => ({
        id: refund._id.toString(),
        kind: "refund",
        transactionId: refund.transactionId?.toString(),
        amount: refund.amount,
        currency: refund.currency,
        status: refund.status,
        reason: refund.reason,
        paymentId: refund.razorpayPaymentId,
        refundId: refund.razorpayRefundId,
        createdAt: refund.createdAt,
      })),
    });
  } catch (error) {
    return res.status(500).json({ error: "Unable to fetch payment history" });
  }
});

app.get("/chat-id/availability/:chatId", chatIdAvailabilityRateLimiter, async (req, res) => {
  try {
    const requestedChatId = normalizeChatId(req.params.chatId);
    if (!isValidSevenDigitChatId(requestedChatId)) {
      return res.status(200).json({
        available: false,
        message: "Chat ID must be exactly 7 digits",
      });
    }

    const existing = await User.findOne({ chatId: requestedChatId });
    if (existing) {
      return res.status(200).json({
        available: false,
        message: "Already taken",
      });
    }

    return res.status(200).json({
      available: true,
      message: "Available",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/user/change-chat-id", requireAuth, async (req, res) => {
  try {
    const {
      oldChatId,
      desiredChatId,
      optionType = "random",
      paymentTransactionId,
      notifyMode = "none",
      notifyChatIds = [],
    } = req.body;

    if (!oldChatId || !paymentTransactionId) {
      return res.status(400).json({ error: "Missing parameters" });
    }
    if (normalizeChatId(oldChatId) !== req.auth.chatId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const user = await User.findOne({ chatId: oldChatId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const paymentTx = await PaymentTransaction.findById(paymentTransactionId);
    if (!paymentTx || paymentTx.chatId !== oldChatId) {
      return res.status(404).json({ error: "Payment transaction not found" });
    }
    if (paymentTx.purpose !== "change_chat_id") {
      return res.status(400).json({ error: "Invalid payment purpose" });
    }
    if (paymentTx.status !== "confirmed") {
      return res.status(402).json({
        error: "Payment is not confirmed yet. Please retry verification.",
      });
    }
    const expectedAmount = computePaymentAmount({
      purpose: "change_chat_id",
      optionType,
      user,
    });
    if (Number(paymentTx.amount) !== Number(expectedAmount)) {
      return res.status(400).json({
        error: "Payment amount mismatch for selected Chat ID option",
      });
    }
    const paidOptionType = String(paymentTx.metadata?.optionType || "random");
    if (paidOptionType !== String(optionType || "random")) {
      return res.status(400).json({
        error: "Paid option does not match requested Chat ID option",
      });
    }

    if (user.lastChatIdChangeAt) {
      const cooldownEndsAt = new Date(user.lastChatIdChangeAt.getTime() + 7 * 24 * 60 * 60 * 1000);
      if (Date.now() < cooldownEndsAt.getTime()) {
        return res.status(429).json({
          error: "You can change your Chat ID again after the cooldown ends",
          cooldownEndsAt,
        });
      }
    }

    let newChatId = "";
    if (optionType === "custom") {
      if (!isValidSevenDigitChatId(desiredChatId)) {
        return res.status(400).json({
          error: "Custom Chat ID must be exactly 7 digits",
        });
      }
      const paidDesired = String(paymentTx.metadata?.desiredChatId || "").trim();
      const requestedDesired = String(desiredChatId || "").trim();
      if (!paidDesired || paidDesired !== requestedDesired) {
        return res.status(400).json({
          error: "Paid custom Chat ID does not match requested Chat ID",
        });
      }
      newChatId = String(desiredChatId).trim();
    } else {
      newChatId = await generateUniqueChatId();
    }

    if (newChatId === oldChatId) {
      return res.status(400).json({
        error: "Choose a different Chat ID",
      });
    }

    const existing = await User.findOne({ chatId: newChatId });
    if (existing) {
      return res.status(409).json({
        error: "Chat ID is already taken",
      });
    }

    const allowedNotifyChatIds = Array.isArray(notifyChatIds)
      ? notifyChatIds
          .map((id) => String(id || "").trim())
          .filter((id) => id && user.savedContacts.includes(id))
      : [];

    const notifyRecipientIds = notifyMode === "all"
      ? [...user.savedContacts]
      : notifyMode === "selected"
        ? [...new Set(allowedNotifyChatIds)]
        : [];

    const oldId = user.chatId;
    const consumedTx = await PaymentTransaction.findOneAndUpdate(
      {
        _id: paymentTransactionId,
        chatId: oldChatId,
        status: "confirmed",
      },
      {
        $set: {
          status: "consumed",
          consumedAt: new Date(),
        },
      },
      { new: true },
    );
    if (!consumedTx) {
      return res.status(409).json({
        error: "Payment already used or no longer valid",
      });
    }
    user.previousChatIds = [...new Set([...(user.previousChatIds || []), oldId])];
    user.chatId = newChatId;
    user.lastChatIdChangeAt = new Date();
    await user.save();
    console.log(
      `[CHAT_ID_CHANGE] Consumed payment tx=${consumedTx._id.toString()} old=${oldId} new=${newChatId}`,
    );

    await Message.updateMany(
      { senderChatId: oldId },
      { $set: { senderChatId: newChatId } },
    );
    await Message.updateMany(
      { receiverChatId: oldId },
      { $set: { receiverChatId: newChatId } },
    );
    await updateCallReferences(oldId, newChatId);
    await updateMomentReferences(oldId, newChatId);
    await updateUserReferenceArrays(oldId, newChatId);
    migrateOnlinePresence(oldId, newChatId);

    const updatedRecipients = await User.find({
      chatId: { $in: notifyRecipientIds },
    });
    const systemMessageText = `${user.name} has updated their Chat ID from @${oldId} to @${newChatId}.`;

    for (const recipient of updatedRecipients) {
      const systemMessage = new Message({
        messageId: `chat_id_change_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        senderChatId: newChatId,
        receiverChatId: recipient.chatId,
        senderDeviceId: "system",
        content: systemMessageText,
        type: 0,
        status: "delivered",
        payloads: [
          {
            deviceId: "all",
            ciphertext: systemMessageText,
            header: { iv: "" },
          },
        ],
      });
      await systemMessage.save();

      io.to(recipient.chatId).emit("chat_id_changed", {
        oldChatId: oldId,
        newChatId,
        userName: user.name,
        notifyMessage: systemMessageText,
      });

      io.to(recipient.chatId).emit("newMessage", systemMessage.toObject());
    }

    io.to(oldId).emit("chat_id_changed", {
      oldChatId: oldId,
      newChatId,
      userName: user.name,
      isSelf: true,
    });

    res.json({
      message: "Chat ID changed successfully",
      oldChatId: oldId,
      newChatId,
      cooldownEndsAt: user.lastChatIdChangeAt,
      notifiedCount: updatedRecipients.length,
      paymentTransactionId: consumedTx._id.toString(),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/user/change-number", async (req, res) => {
  try {
    const { oldChatId, newChatId } = req.body;
    if (!oldChatId || !newChatId) {
      return res.status(400).json({ error: "Missing parameters" });
    }
    if (!isValidSevenDigitChatId(newChatId)) {
      return res.status(400).json({ error: "Chat ID must be exactly 7 digits" });
    }
    const existing = await User.findOne({ chatId: newChatId });
    if (existing) {
      return res.status(409).json({ error: "Chat ID is already taken" });
    }
    const user = await User.findOne({ chatId: oldChatId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.previousChatIds = [...new Set([...(user.previousChatIds || []), oldChatId])];
    user.chatId = newChatId;
    user.lastChatIdChangeAt = new Date();
    await user.save();

    await Message.updateMany(
      { senderChatId: oldChatId },
      { $set: { senderChatId: newChatId } },
    );
    await Message.updateMany(
      { receiverChatId: oldChatId },
      { $set: { receiverChatId: newChatId } },
    );
    await updateCallReferences(oldChatId, newChatId);
    await updateMomentReferences(oldChatId, newChatId);
    await updateUserReferenceArrays(oldChatId, newChatId);
    migrateOnlinePresence(oldChatId, newChatId);

    return res.json({
      message: "Number changed successfully",
      oldChatId,
      newChatId,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.delete("/user/delete", async (req, res) => {
  try {
    const { chatId } = req.body;
    if (!chatId) return res.status(400).json({ error: "Missing parameters" });

    const user = await User.findOneAndDelete({ chatId });
    if (!user) return res.status(404).json({ error: "User not found" });

    await Message.deleteMany({
      $or: [{ receiverChatId: chatId }, { senderChatId: chatId }]
    });

    await Call.deleteMany({ $or: [{ caller: chatId }, { receiver: chatId }] });
    await Moment.deleteMany({ userId: chatId });

    res.json({ message: "Account deleted securely" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Moments ─────────────────────────────────────────────────────────────
function sanitizeMomentForViewer(moment, requesterId, isOwner = false) {
  const json = moment.toObject ? moment.toObject() : { ...moment };
  const viewEntry = (json.views || []).find(v => v.viewerId === requesterId);

  return {
    ...json,
    likes: json.likes || [],
    comments: json.comments || [],
    viewerState: {
      hasViewed: !!viewEntry,
      hasLiked: !!viewEntry?.liked,
      viewedAt: viewEntry?.viewedAt || null,
    },
    views: isOwner ? (json.views || []) : undefined,
    viewCount: Array.isArray(json.views) ? json.views.length : 0,
    likeCount: Array.isArray(json.likes) ? json.likes.length : 0,
    commentCount: Array.isArray(json.comments) ? json.comments.length : 0,
  };
}

async function canRequesterViewMoments(requesterId, targetId) {
  const requester = await User.findOne({ chatId: requesterId });
  const target = await User.findOne({ chatId: targetId });

  if (!requester || !target) {
    return false;
  }
  if (requester.blockedUsers.includes(targetId) || target.blockedUsers.includes(requesterId)) {
    return false;
  }

  const isTargetContact = target.savedContacts.includes(requesterId);
  const isMutual = isTargetContact && requester.savedContacts.includes(targetId);
  const setting = target.privacy?.moments || "contacts";
  const exceptions = target.privacy?.momentsExceptions || [];

  if (setting === "contacts") {
    return isMutual;
  }
  if (setting === "except") {
    return isMutual && !exceptions.includes(requesterId);
  }
  if (setting === "only") {
    return exceptions.includes(requesterId);
  }
  return false;
}

app.post("/moments", async (req, res) => {
  try {
    const {
      id,
      userId,
      userName,
      userAvatar,
      type,
      content,
      localMediaPath,
      mediaUrl,
      timestamp,
      expiresAt,
      backgroundColor,
      fontFamily,
    } = req.body;

    if (!id || !userId || !userName || type === undefined) {
      return res.status(400).json({ error: "Missing required moment fields" });
    }

    let moment = await Moment.findOne({ id });
    if (moment) {
      return res.status(200).json({
        message: "Moment already exists",
        moment: sanitizeMomentForViewer(moment, userId, true),
      });
    }

    moment = await Moment.create({
      id,
      userId,
      userName,
      userAvatar: userAvatar || "",
      type,
      content: content || "",
      localMediaPath: localMediaPath || "",
      mediaUrl: mediaUrl || "",
      timestamp: timestamp || new Date(),
      expiresAt: expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000),
      backgroundColor,
      fontFamily,
      likes: [],
      views: [],
      comments: [],
    });

    io.to(userId).emit("moment_updated", {
      type: "moment_created",
      ownerChatId: userId,
      momentId: moment.id,
    });

    res.status(201).json({
      message: "Moment created successfully",
      moment: sanitizeMomentForViewer(moment, userId, true),
    });
  } catch (err) {
    console.error("ERROR in POST /moments:", err.message);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

app.get("/moments/owner/:ownerChatId", async (req, res) => {
  try {
    const { ownerChatId } = req.params;
    const requesterId = req.query.requesterId || ownerChatId;
    if (requesterId !== ownerChatId) {
      return res.status(403).json({ error: "Only the owner can access this feed" });
    }

    const moments = await Moment.find({
      userId: ownerChatId,
      expiresAt: { $gt: new Date() },
    }).sort({ timestamp: -1 });

    res.json(moments.map(moment => sanitizeMomentForViewer(moment, ownerChatId, true)));
  } catch (err) {
    console.error("Owner moments fetch error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/moments/:requesterId/:chatIds", async (req, res) => {
  try {
    const { requesterId, chatIds: requestedIdsStr } = req.params;
    const requestedIds = requestedIdsStr.split(",").filter(id => id.trim() !== "");

    const requester = await User.findOne({ chatId: requesterId });
    if (!requester) {
      return res.status(404).json({ error: "Requester not found" });
    }

    const permittedIds = [];
    for (const targetId of requestedIds) {
      if (await canRequesterViewMoments(requesterId, targetId)) {
        permittedIds.push(targetId);
      }
    }

    const moments = await Moment.find({
      userId: { $in: permittedIds },
      expiresAt: { $gt: new Date() },
    }).sort({ timestamp: -1 });

    res.json(moments.map(moment => sanitizeMomentForViewer(moment, requesterId, false)));
  } catch (err) {
    console.error("Fetch moments error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/moments/:momentId/view", async (req, res) => {
  try {
    const { viewerId, viewerName = "" } = req.body;
    if (!viewerId) {
      return res.status(400).json({ error: "viewerId is required" });
    }

    const moment = await Moment.findOne({ id: req.params.momentId });
    if (!moment) {
      return res.status(404).json({ error: "Moment not found" });
    }
    if (!(await canRequesterViewMoments(viewerId, moment.userId))) {
      return res.status(403).json({ error: "Not allowed to view this moment" });
    }

    const existingIndex = moment.views.findIndex(view => view.viewerId === viewerId);
    if (existingIndex === -1) {
      moment.views.push({
        viewerId,
        viewerName,
        viewedAt: new Date(),
        liked: false,
      });
      await moment.save();
      io.to(moment.userId).emit("moment_updated", {
        type: "moment_viewed",
        ownerChatId: moment.userId,
        momentId: moment.id,
        viewerId,
        viewerName,
      });
    }

    res.json({
      message: "Moment view recorded",
      moment: sanitizeMomentForViewer(moment, viewerId, viewerId === moment.userId),
    });
  } catch (err) {
    console.error("Moment view error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/moments/:momentId/like", async (req, res) => {
  try {
    const { userId, userName = "" } = req.body;
    if (!userId) {
      return res.status(400).json({ error: "userId is required" });
    }

    const moment = await Moment.findOne({ id: req.params.momentId });
    if (!moment) {
      return res.status(404).json({ error: "Moment not found" });
    }
    if (!(await canRequesterViewMoments(userId, moment.userId))) {
      return res.status(403).json({ error: "Not allowed to like this moment" });
    }

    const likeIndex = moment.likes.indexOf(userId);
    if (likeIndex === -1) {
      moment.likes.push(userId);
    } else {
      moment.likes.splice(likeIndex, 1);
    }

    const existingView = moment.views.find(view => view.viewerId === userId);
    if (existingView) {
      existingView.liked = likeIndex === -1;
      existingView.viewerName = userName || existingView.viewerName;
    } else {
      moment.views.push({
        viewerId: userId,
        viewerName: userName,
        viewedAt: new Date(),
        liked: likeIndex === -1,
      });
    }

    await moment.save();
    io.to(moment.userId).emit("moment_updated", {
      type: "moment_liked",
      ownerChatId: moment.userId,
      momentId: moment.id,
      userId,
      userName,
      liked: likeIndex === -1,
    });

    res.json({
      message: likeIndex === -1 ? "Moment liked" : "Moment unliked",
      moment: sanitizeMomentForViewer(moment, userId, userId === moment.userId),
    });
  } catch (err) {
    console.error("Moment like error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/moments/:momentId/comment", async (req, res) => {
  try {
    const { userId, userName = "", content } = req.body;
    if (!userId || !content || !content.trim()) {
      return res.status(400).json({ error: "userId and content are required" });
    }

    const moment = await Moment.findOne({ id: req.params.momentId });
    if (!moment) {
      return res.status(404).json({ error: "Moment not found" });
    }
    if (!(await canRequesterViewMoments(userId, moment.userId))) {
      return res.status(403).json({ error: "Not allowed to comment on this moment" });
    }

    const comment = {
      id: new mongoose.Types.ObjectId().toString(),
      userId,
      userName,
      content: content.trim(),
      createdAt: new Date(),
    };
    moment.comments.push(comment);

    const existingView = moment.views.find(view => view.viewerId === userId);
    if (!existingView) {
      moment.views.push({
        viewerId: userId,
        viewerName: userName,
        viewedAt: new Date(),
        liked: false,
      });
    }

    await moment.save();
    io.to(moment.userId).emit("moment_updated", {
      type: "moment_commented",
      ownerChatId: moment.userId,
      momentId: moment.id,
      userId,
      userName,
      commentId: comment.id,
    });

    res.status(201).json({
      message: "Moment comment added",
      comment,
      moment: sanitizeMomentForViewer(moment, userId, userId === moment.userId),
    });
  } catch (err) {
    console.error("Moment comment error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.delete("/moments/:momentId", async (req, res) => {
  try {
    const ownerChatId = req.query.ownerChatId;
    if (!ownerChatId) {
      return res.status(400).json({ error: "ownerChatId is required" });
    }

    const deleted = await Moment.findOneAndDelete({
      id: req.params.momentId,
      userId: ownerChatId,
    });
    if (!deleted) {
      return res.status(404).json({ error: "Moment not found" });
    }

    io.to(ownerChatId).emit("moment_updated", {
      type: "moment_deleted",
      ownerChatId,
      momentId: req.params.momentId,
    });

    res.json({ message: "Moment deleted" });
  } catch (err) {
    console.error("Moment delete error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.delete("/moments/user/:ownerChatId", async (req, res) => {
  try {
    const { ownerChatId } = req.params;
    const result = await Moment.deleteMany({ userId: ownerChatId });
    io.to(ownerChatId).emit("moment_updated", {
      type: "all_moments_deleted",
      ownerChatId,
    });
    res.json({ message: "All owner moments deleted", deletedCount: result.deletedCount });
  } catch (err) {
    console.error("Delete owner moments error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/moments/report", async (req, res) => {
  try {
    const {
      reporterId,
      ownerChatId,
      momentId,
      preview = "",
      targetOwnerChatId = "6076322",
    } = req.body;

    if (!reporterId || !ownerChatId || !momentId) {
      return res.status(400).json({ error: "reporterId, ownerChatId and momentId are required" });
    }

    const report = await MomentReport.findOneAndUpdate(
      { momentId, reporterId },
      {
        $set: {
          ownerChatId,
          targetOwnerChatId,
          preview,
          status: "open",
          reportedAt: new Date(),
        },
      },
      {
        upsert: true,
        new: true,
        setDefaultsOnInsert: true,
      },
    );

    io.to(targetOwnerChatId).emit("moment_reported", {
      momentId,
      ownerChatId,
      reporterId,
      preview,
      reportId: report._id.toString(),
    });

    res.json({
      message: "Moment report received",
      reportId: report._id.toString(),
    });
  } catch (err) {
    console.error("Moment report error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ── Upload Media ────────────────────────────────────────────────────────────
app.post("/upload-media", requireAuth, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const fileUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
  res.json({ url: fileUrl });
});

// ── Socket.IO ────────────────────────────────────────────────────────────────
io.use(async (socket, next) => {
  try {
    const token =
      socket.handshake.auth?.token ||
      socket.handshake.headers?.authorization?.replace(/^Bearer\s+/i, "") ||
      "";
    const sessionId = String(socket.handshake.auth?.sessionId || "");

    if (token) {
      let payload;
      try {
        payload = verifyAccessToken(token);
      } catch (error) {
        if (!isTokenExpiredError(error)) {
          throw error;
        }
        payload = verifyAccessTokenAllowExpired(token);
      }
      const device = await Device.findOne({ deviceId: payload.deviceId });
      if (!device || !device.isActive || Number(device.tokenVersion || 0) !== Number(payload.tokenVersion || 0)) {
        return next(new Error("Unauthorized"));
      }
      socket.data.auth = payload;
      socket.data.deviceId = payload.deviceId;
      socket.data.chatId = payload.chatId;
      return next();
    }

    if (sessionId) {
      socket.data.sessionId = sessionId;
      return next();
    }

    return next(new Error("Unauthorized"));
  } catch (error) {
    return next(new Error("Unauthorized"));
  }
});

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  if (socket.data.auth?.chatId) {
    attachAuthenticatedSocket(socket).catch((error) => {
      console.error("Socket attach failed:", error);
    });
  }

  if (socket.data.sessionId) {
    socket.join(`auth_session:${socket.data.sessionId}`);
  }

  socket.on("register", async () => {
    if (socket.data.auth?.chatId) {
      await attachAuthenticatedSocket(socket);
      return;
    }
    if (socket.data.sessionId) {
      socket.join(`auth_session:${socket.data.sessionId}`);
    }
  });

  socket.on("watch_presence", (data) => {
    try {
      if (!socket.data.auth?.chatId) {
        return;
      }
      const raw = Array.isArray(data?.chatIds) ? data.chatIds : [];
      const chatIds = [...new Set(raw.map((c) => normalizeChatId(String(c || ""))).filter(Boolean))].slice(
        0,
        200,
      );
      for (const chatId of chatIds) {
        socket.join(presenceRoom(chatId));
      }
      socket.emit("watch_presence_ok", { count: chatIds.length });
    } catch (_) {}
  });

  socket.on("unwatch_presence", (data) => {
    try {
      if (!socket.data.auth?.chatId) {
        return;
      }
      const raw = Array.isArray(data?.chatIds) ? data.chatIds : [];
      const chatIds = [...new Set(raw.map((c) => normalizeChatId(String(c || ""))).filter(Boolean))].slice(
        0,
        200,
      );
      for (const chatId of chatIds) {
        socket.leave(presenceRoom(chatId));
      }
      socket.emit("unwatch_presence_ok", { count: chatIds.length });
    } catch (_) {}
  });

  socket.on("message_delivered", async (data) => {
    if (!socket.data.auth?.chatId) return;
    if (!data?.messageId || !data?.to) return;
    data.from = socket.data.auth.chatId;
    const to = await resolveGhostReceiverId(data.to);
    const room = to.ghostInvalid ? data.to : to.receiverChatId;
    io.to(room).emit("message_delivered", data);
  });

  socket.on("message_read", async (data) => {
    if (!socket.data.auth?.chatId) return;
    if (!data?.messageId || !data?.to) return;
    data.from = socket.data.auth.chatId;
    const to = await resolveGhostReceiverId(data.to);
    const room = to.ghostInvalid ? data.to : to.receiverChatId;
    io.to(room).emit("message_read", data);
  });

  socket.on("send_group_message", async (data) => {
    try {
      // Disabled: plaintext group messaging must not hit the server.
      // Group chat uses E2EE fan-out via /send with encrypted payloads + groupId.
      socket.emit("group_message_error", {
        error: "Group plaintext messaging disabled (E2EE only)",
        code: "group_plaintext_disabled",
      });
    } catch (e) {
      socket.emit("group_message_error", { error: "Failed to send group message" });
    }
  });

  socket.on("group_call_invite", async (data) => {
    const from = normalizeActorChatId(socket, data.from);
    const roomId =
      data.roomId || `room_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const rawParticipants = Array.isArray(data.participants) ? data.participants : [];
    const targetIds = [...new Set(rawParticipants.map((item) => item.toString()).filter((id) => id && id !== from))];
    const groupId = String(data.groupId || "").trim();
    const groupNameOverride = String(data.groupName || "").trim();

    if (!from || targetIds.length === 0) {
      socket.emit("group_call_error", {
        roomId,
        message: "At least one valid participant is required",
      });
      return;
    }

    const caller = await User.findOne({ chatId: from });
    if (!caller) {
      socket.emit("group_call_error", {
        roomId,
        message: "Caller not registered",
      });
      return;
    }

    const room = ensureCallRoom(roomId, {
      hostId: from,
      hostName: data.fromName || from,
      callType: data.type || "voice",
    });
    room.groupId = groupId || null;
    room.groupName = groupNameOverride || null;
    room.hasEverConnected = room.hasEverConnected === true;
    if (room.disconnectTimers.has(from)) {
      clearCallTimer(room.disconnectTimers.get(from));
      room.disconnectTimers.delete(from);
    }
    room.disconnectedParticipants.delete(from);
    if (room.participants.has(from)) {
      room.participants.get(from).connected = true;
      room.participants.get(from).reconnectDeadline = null;
    }
    socket.join(roomId);
    rememberSocketRoom(socket, roomId);

    const invitedPayload = [];

    let group = null;
    if (groupId) {
      group = await Group.findOne({ groupId });
      if (!group) {
        socket.emit("group_call_error", { roomId, message: "Group not found" });
        return;
      }
      if (!group.members.includes(from)) {
        socket.emit("group_call_error", { roomId, message: "Not a group member" });
        return;
      }
      const resolvedGroupName = groupNameOverride || group.name || groupId;
      activeGroupCallsByGroupId.set(groupId, {
        roomId,
        groupName: resolvedGroupName,
        callType: data.type || "voice",
        hostId: from,
        hostName: data.fromName || caller.name || from,
        startedAt: room.createdAt,
      });
      // Make call joinable: mark non-invited members as "available" so they receive state updates.
      for (const memberId of group.members) {
        if (!memberId || memberId === from) continue;
        if (!room.invited.has(memberId) && !room.participants.has(memberId)) {
          room.invited.set(memberId, {
            chatId: memberId,
            name: memberId,
            status: "available",
          });
        }
      }
      notifyGroupCallStartedToMembers({
        group,
        room,
        hostId: from,
        hostName: data.fromName || caller.name || from,
        groupName: resolvedGroupName,
        callType: data.type || "voice",
      });
    }

    const recipients = await Promise.all(
      targetIds.map(async (targetId) => ({
        targetId,
        recipient: await User.findOne({ chatId: targetId }),
      })),
    );

    for (const { targetId, recipient } of recipients) {
      if (!recipient) {
        invitedPayload.push({ chatId: targetId, status: "invalid" });
        continue;
      }

      const allowed = await isCallAllowed({
        caller,
        recipient,
        recipientChatId: targetId,
      });
      if (!allowed) {
        invitedPayload.push({ chatId: targetId, status: "blocked" });
        continue;
      }

      const targetName = recipient.name || targetId;
      room.invited.set(targetId, {
        chatId: targetId,
        name: targetName,
        status: "ringing",
      });
      invitedPayload.push({ chatId: targetId, status: "ringing" });

      await Call.create({
        caller: from,
        receiver: targetId,
        roomId,
        participants: [from, targetId],
        isGroup: true,
        type: data.type || "voice",
        status: "ringing",
        metadata: {
          ...(groupId ? { groupId } : {}),
          ...(group ? { groupName: groupNameOverride || group.name || groupId } : {}),
        },
      });

      io.to(targetId).emit("group_call_invite", {
        roomId,
        from,
        fromName: data.fromName || caller.name || from,
        callType: data.type || "voice",
        invitedParticipants: targetIds,
        participants: createRoomSnapshot(room).participants,
      });

      const isOnline = onlineUsers.has(targetId) && onlineUsers.get(targetId).size > 0;
      if (!isOnline) {
        const tokens = await getUserMobileCallTokens(recipient);
        for (const token of tokens) {
          sendCallPushNotification({
            token,
            callerId: from,
            callerName: data.fromName || caller.name || from,
            callType: data.type || "voice",
            callId: roomId,
            channelId: roomId,
            groupId,
            groupName: group ? (groupNameOverride || group.name || groupId) : "",
            participantIds: targetIds,
            participantNames: Object.fromEntries(
              createRoomSnapshot(room).participants.map((participant) => [
                participant.chatId,
                participant.name,
              ])
            ),
            addedBy: data.fromName || caller.name || from,
            isGroup: true,
          }).catch((error) => {
            console.error("FCM Error (Group Call):", error);
          });
        }
      }
    }

    socket.emit("group_call_invite_sent", {
      roomId,
      invited: invitedPayload,
    });
    emitRoomState(room);
  });

  socket.on("group_call_accept", async (data) => {
    const room = activeCallRooms.get(data.roomId);
    const from = normalizeActorChatId(socket, data.from);
    if (!room) {
      socket.emit("group_call_error", {
        roomId: data.roomId,
        message: "This call is no longer active",
      });
      return;
    }

    socket.join(data.roomId);
    rememberSocketRoom(socket, data.roomId);
    room.invited.delete(from);
    room.disconnectedParticipants.delete(from);
    if (room.disconnectTimers.has(from)) {
      clearCallTimer(room.disconnectTimers.get(from));
      room.disconnectTimers.delete(from);
    }
    room.participants.set(from, {
      chatId: from,
      name: data.fromName || from,
      joinedAt: new Date(),
      connected: true,
      reconnectDeadline: null,
    });
    if (room.participants.size > 1) {
      room.hasEverConnected = true;
    }

    await Call.updateMany(
      { roomId: data.roomId, receiver: from },
      { status: "accepted", startTime: new Date(), answeredBy: from, reconnectGraceUntil: null }
    );

    socket.emit("group_call_state", createRoomSnapshot(room));
    socket.to(data.roomId).emit("group_participant_joined", {
      roomId: data.roomId,
      participant: {
        chatId: from,
        name: data.fromName || from,
      },
    });
    flushRealtimeSignals(room, from);
    emitRoomState(room);
  });

  socket.on("group_call_join", async (data) => {
    try {
      const from = normalizeActorChatId(socket, data.from);
      const groupId = String(data.groupId || "").trim();
      if (!from || !groupId) {
        socket.emit("group_call_error", { message: "Invalid join request" });
        return;
      }
      const active = activeGroupCallsByGroupId.get(groupId);
      if (!active) {
        socket.emit("group_call_error", { message: "No active group call" });
        return;
      }
      socket.emit("group_call_join_info", {
        groupId,
        groupName: active.groupName,
        roomId: active.roomId,
        callType: active.callType,
        hostId: active.hostId,
        hostName: active.hostName,
        startedAt: active.startedAt,
      });
    } catch (_) {}
  });

  socket.on("group_call_decline", async (data) => {
    const room = activeCallRooms.get(data.roomId);
    const from = normalizeActorChatId(socket, data.from);
    if (room?.invited.has(from)) {
      room.invited.set(from, {
        chatId: from,
        name: data.fromName || from,
        status: "declined",
      });
      emitRoomState(room);
    }

    await Call.updateMany(
      { roomId: data.roomId, receiver: from },
      { status: "rejected", endTime: new Date(), endedBy: from, endReason: "declined" }
    );

    io.to(data.roomId).emit("group_call_declined", {
      roomId: data.roomId,
      participant: {
        chatId: from,
        name: data.fromName || from,
      },
    });
  });

  socket.on("group_webrtc_offer", (data) => {
    const payload = { ...data, from: normalizeActorChatId(socket, data.from) };
    const room = activeCallRooms.get(data.roomId);
    if (room && !isUserOnline(data.to)) {
      queueRealtimeSignal(room, data.to, "group_webrtc_offer", payload);
    }
    io.to(data.to).emit("group_webrtc_offer", payload);
  });

  socket.on("group_webrtc_answer", (data) => {
    const payload = { ...data, from: normalizeActorChatId(socket, data.from) };
    const room = activeCallRooms.get(data.roomId);
    if (room && !isUserOnline(data.to)) {
      queueRealtimeSignal(room, data.to, "group_webrtc_answer", payload);
    }
    io.to(data.to).emit("group_webrtc_answer", payload);
  });

  socket.on("group_ice_candidate", (data) => {
    const payload = { ...data, from: normalizeActorChatId(socket, data.from) };
    const room = activeCallRooms.get(data.roomId);
    if (room && !isUserOnline(data.to)) {
      queueRealtimeSignal(room, data.to, "group_ice_candidate", payload);
    }
    io.to(data.to).emit("group_ice_candidate", payload);
  });

  socket.on("group_call_reconnect", (data) => {
    const room = activeCallRooms.get(data.roomId);
    const from = normalizeActorChatId(socket, data.from);
    if (!room || !room.participants.has(from)) {
      socket.emit("group_call_error", {
        roomId: data.roomId,
        message: "Call session not found",
      });
      return;
    }
    socket.join(data.roomId);
    rememberSocketRoom(socket, data.roomId);
    room.disconnectedParticipants.delete(from);
    if (room.disconnectTimers.has(from)) {
      clearCallTimer(room.disconnectTimers.get(from));
      room.disconnectTimers.delete(from);
    }
    room.participants.get(from).connected = true;
    room.participants.get(from).reconnectDeadline = null;
    flushRealtimeSignals(room, from);
    socket.emit("group_call_state", createRoomSnapshot(room));
    emitRoomState(room);
  });

  socket.on("group_call_leave", async (data) => {
    const room = activeCallRooms.get(data.roomId);
    const from = normalizeActorChatId(socket, data.from);
    if (!room) {
      return;
    }

    room.participants.delete(from);
    room.invited.delete(from);
    room.disconnectedParticipants.delete(from);
    if (room.disconnectTimers.has(from)) {
      clearCallTimer(room.disconnectTimers.get(from));
      room.disconnectTimers.delete(from);
    }
    socket.leave(data.roomId);
    if (socket.data.callRooms) {
      socket.data.callRooms.delete(data.roomId);
    }

    await Call.updateMany(
      { roomId: data.roomId, $or: [{ receiver: from }, { caller: from }] },
      { status: "ended", endTime: new Date(), duration: data.duration || 0, endedBy: from, endReason: "left" }
    );

    socket.to(data.roomId).emit("group_participant_left", {
      roomId: data.roomId,
      participantId: from,
    });
    if (!closeRoomIfNeeded(room, "participant_left")) {
      emitRoomState(room);
    }
    if (room.groupId && closeRoomIfNeeded(room, "participant_left")) {
      activeGroupCallsByGroupId.delete(room.groupId);
      io.to(room.groupId).emit("group_call_ended", {
        roomId: room.roomId,
        groupId: room.groupId,
        reason: "ended",
        message: "Call ended",
      });
    }

    if (activeCallRooms.has(data.roomId) &&
        room.participants.size === 0 &&
        room.invited.size === 0) {
      activeCallRooms.delete(data.roomId);
    }
  });

  // Signaling
  socket.on("call_offer", async (data) => {
    const from = normalizeActorChatId(socket, data.from);
    const to = normalizeChatId(data.to);
    if (!from || !to || from === to) {
      return;
    }
    console.log(`Call offer from ${from} to ${to}`);

    const recipient = await User.findOne({ chatId: to });
    const caller = await User.findOne({ chatId: from });
    if (caller && caller.blockedUsers.includes(to)) {
      return;
    }
    if (recipient) {
      if (recipient.blockedUsers.includes(from)) {
        return;
      }

      const isContact = recipient.savedContacts.includes(from);
      if (recipient.privacy.calls === "none") return;
      if (recipient.privacy.calls === "contacts" && !isContact) {
        if (recipient.privacy.unknownCallersReject) return;
      }
    }

    const call = new Call({
      caller: from,
      receiver: to,
      participants: [from, to],
      type: data.type,
      status: 'ringing',
      metadata: {
        initiatorDeviceId: socket.data.deviceId || null,
        callerNetwork: data.networkQuality || null,
      },
    });
    await call.save();
    const callId = call._id.toString();
    const callState = ensurePeerCall(callId, {
      callerId: from,
      callerName: data.fromName || caller?.name || from,
      calleeId: to,
      calleeName: recipient?.name || to,
      callType: data.type || "voice",
    });
    socket.join(peerCallRoom(callId));
    rememberSocketRoom(socket, peerCallRoom(callId));
    const offerPayload = { ...data, from, to, callId };
    if (!isUserOnline(to)) {
      queueRealtimeSignal(callState, to, "call_offer", offerPayload);
    }
    io.to(to).emit("call_offer", offerPayload);
    emitPeerCallState(callState);

    if (recipient && !isUserOnline(to)) {
      const tokens = await getUserMobileCallTokens(recipient);
      for (const token of tokens) {
        sendCallPushNotification({
          token,
          callerId: from,
          callerName: data.fromName || from,
          callType: data.type,
          callId,
          channelId: callId,
          participantIds: [to],
          participantNames: {
            [from]: data.fromName || from,
          },
        }).catch(e => console.error("FCM Error (Call):", e));
      }
    }
  });

  socket.on("call_answer", async (data) => {
    const from = normalizeActorChatId(socket, data.from);
    const call = activePeerCalls.get(String(data.callId || ""));
    const to = normalizeChatId(data.to);
    console.log(`Call answer from ${from} to ${to}`);
    if (call) {
      call.status = "accepted";
      call.startedAt = new Date();
      clearCallTimer(call.ringTimer);
      socket.join(peerCallRoom(call.callId));
      rememberSocketRoom(socket, peerCallRoom(call.callId));
      const participant = call.participants.get(from);
      if (participant) {
        participant.connected = true;
        participant.reconnectDeadline = null;
      }
      clearPeerDisconnectTimer(call, from);
      flushRealtimeSignals(call, from);
      emitPeerCallState(call);
    }
    await Call.findByIdAndUpdate(data.callId, {
      status: 'accepted',
      startTime: new Date(),
      answeredBy: from,
      reconnectGraceUntil: null,
    });
    const payload = { ...data, from, to };
    if (call && !isUserOnline(to)) {
      queueRealtimeSignal(call, to, "call_answer", payload);
    }
    io.to(to).emit("call_answer", payload);
  });

  socket.on("ice_candidate", (data) => {
    const payload = { ...data, from: normalizeActorChatId(socket, data.from) };
    const call = activePeerCalls.get(String(data.callId || ""));
    if (call && !isUserOnline(data.to)) {
      queueRealtimeSignal(call, data.to, "ice_candidate", payload);
    }
    io.to(data.to).emit("ice_candidate", payload);
  });

  socket.on("call_reconnect", (data) => {
    const call = activePeerCalls.get(String(data.callId || ""));
    const from = normalizeActorChatId(socket, data.from);
    if (!call) {
      socket.emit("call_error", {
        callId: data.callId,
        message: "Call session not found",
      });
      return;
    }
    socket.join(peerCallRoom(call.callId));
    rememberSocketRoom(socket, peerCallRoom(call.callId));
    const participant = call.participants.get(from);
    if (participant) {
      participant.connected = true;
      participant.reconnectDeadline = null;
    }
    clearPeerDisconnectTimer(call, from);
    flushRealtimeSignals(call, from);
    socket.emit("call_reconnected", createPeerCallSnapshot(call));
    emitPeerCallState(call);
  });

  socket.on("call_keepalive", (data) => {
    const call = activePeerCalls.get(String(data.callId || ""));
    const from = normalizeActorChatId(socket, data.from);
    if (!call?.participants?.has(from)) {
      return;
    }
    const participant = call.participants.get(from);
    participant.connected = true;
    participant.reconnectDeadline = null;
    if (data.networkQuality) {
      participant.networkQuality = String(data.networkQuality);
    }
    clearPeerDisconnectTimer(call, from);
  });

  socket.on("call_quality_report", (data) => {
    const call = activePeerCalls.get(String(data.callId || ""));
    const from = normalizeActorChatId(socket, data.from);
    if (!call?.participants?.has(from)) {
      return;
    }
    call.participants.get(from).networkQuality = String(data.networkQuality || "good");
    emitPeerCallState(call);
  });

  socket.on("call_toggle_media", (data) => {
    const call = activePeerCalls.get(String(data.callId || ""));
    const from = normalizeActorChatId(socket, data.from);
    if (!call?.participants?.has(from)) {
      return;
    }
    const participant = call.participants.get(from);
    participant.media = {
      audio: data.audio !== false,
      video: Boolean(data.video),
    };
    const payload = {
      callId: call.callId,
      participantId: from,
      media: participant.media,
    };
    io.to(peerCallRoom(call.callId)).emit("call_media_changed", payload);
    io.to(call.callerId).emit("call_media_changed", payload);
    io.to(call.calleeId).emit("call_media_changed", payload);
  });

  socket.on("call_renegotiate_offer", (data) => {
    const payload = { ...data, from: normalizeActorChatId(socket, data.from) };
    const call = activePeerCalls.get(String(data.callId || ""));
    if (call && !isUserOnline(data.to)) {
      queueRealtimeSignal(call, data.to, "call_renegotiate_offer", payload);
    }
    io.to(data.to).emit("call_renegotiate_offer", payload);
  });

  socket.on("call_renegotiate_answer", (data) => {
    const payload = { ...data, from: normalizeActorChatId(socket, data.from) };
    const call = activePeerCalls.get(String(data.callId || ""));
    if (call && !isUserOnline(data.to)) {
      queueRealtimeSignal(call, data.to, "call_renegotiate_answer", payload);
    }
    io.to(data.to).emit("call_renegotiate_answer", payload);
  });

  socket.on("typing", async (data) => {
    if (!socket.data.auth?.chatId) {
      return;
    }
    if (!data?.to) {
      return;
    }
    data.from = socket.data.auth.chatId;
    const senderUser = await User.findOne({ chatId: data.from }).select("privacy");
    const recipientUser = await User.findOne({ chatId: data.to }).select("privacy");
    const senderAllows = senderUser?.privacy?.typingIndicator === true;
    const recipientAllows = recipientUser?.privacy?.typingIndicator === true;
    if (!senderAllows || !recipientAllows) {
      return;
    }
    const throttleKey = `${data.from}->${data.to}`;
    const nowMs = Date.now();
    const last = typingThrottle.get(throttleKey) || 0;
    if (nowMs - last < 700) {
      return;
    }
    typingThrottle.set(throttleKey, nowMs);
    const to = await resolveGhostReceiverId(data.to);
    const room = to.ghostInvalid ? data.to : to.receiverChatId;
    io.to(room).emit("typing", data);
  });

  socket.on("stop_typing", async (data) => {
    if (!socket.data.auth?.chatId) {
      return;
    }
    if (!data?.to) {
      return;
    }
    data.from = socket.data.auth.chatId;
    const senderUser = await User.findOne({ chatId: data.from }).select("privacy");
    const recipientUser = await User.findOne({ chatId: data.to }).select("privacy");
    const senderAllows = senderUser?.privacy?.typingIndicator === true;
    const recipientAllows = recipientUser?.privacy?.typingIndicator === true;
    if (!senderAllows || !recipientAllows) {
      return;
    }
    typingThrottle.delete(`${data.from}->${data.to}`);
    const to = await resolveGhostReceiverId(data.to);
    const room = to.ghostInvalid ? data.to : to.receiverChatId;
    io.to(room).emit("stop_typing", data);
  });

  socket.on("reject_call", async (data) => {
    const from = normalizeActorChatId(socket, data.from);
    const to = normalizeChatId(data.to);
    const call = activePeerCalls.get(String(data.callId || ""));
    if (call) {
      clearCallTimer(call.ringTimer);
      activePeerCalls.delete(call.callId);
    }
    await Call.findByIdAndUpdate(data.callId, {
      status: 'rejected',
      endTime: new Date(),
      endedBy: from,
      endReason: "declined",
    });
    io.to(to).emit("call_rejected", { ...data, from, to });

    const msg = new Message({
      messageId: `call_${Date.now()}`,
      senderChatId: from,
      receiverChatId: to,
      senderDeviceId: "system",
      payloads: [{ deviceId: "all", ciphertext: `Missed ${data.callType || 'voice'} call`, header: { iv: "" } }],
      timestamp: new Date()
    });
    await msg.save();
    io.to(to).emit("newMessage", msg.toObject());
    io.to(from).emit("newMessage", msg.toObject());
  });

  socket.on("missed_call", async (data) => {
    if (!data.callId) {
      return;
    }
    const from = normalizeActorChatId(socket, data.from);
    const to = normalizeChatId(data.to);
    const call = activePeerCalls.get(String(data.callId || ""));
    if (call) {
      finalizePeerCall(call, {
        status: "missed",
        reason: "missed",
        endedBy: from,
      });
    } else {
      await Call.findByIdAndUpdate(data.callId, {
        status: 'missed',
        endTime: new Date(),
        endedBy: from,
        endReason: "missed",
      });
      io.to(to).emit("call_missed", { ...data, from, to });
    }

    const msg = new Message({
      messageId: `call_${Date.now()}`,
      senderChatId: from,
      receiverChatId: to,
      senderDeviceId: "system",
      payloads: [{ deviceId: "all", ciphertext: `Missed ${data.callType || 'voice'} call`, header: { iv: "" } }],
      timestamp: new Date()
    });
    await msg.save();
    io.to(to).emit("newMessage", msg.toObject());
    io.to(from).emit("newMessage", msg.toObject());

    const receiver = await User.findOne({ chatId: to });
    const sender = await User.findOne({ chatId: from });
    if (receiver) {
      const mobileDevices = await Device.find({
        userId: receiver._id,
        type: "mobile",
        fcmToken: { $ne: null }
      });
      for (const device of mobileDevices) {
        await sendDataOnlyPushNotification({
          token: device.fcmToken,
          senderId: from,
          senderName: sender?.name || from,
          senderAvatar: sender?.profilePhoto || "",
          type: 0,
          messageId: msg.messageId,
          content: `Missed ${data.callType || 'voice'} call`
        });
      }
    }
  });

  socket.on("end_call", async (data) => {
    const from = normalizeActorChatId(socket, data.from);
    const to = normalizeChatId(data.to);
    const duration = Number(data.duration || 0);
    const call = activePeerCalls.get(String(data.callId || ""));
    if (call) {
      finalizePeerCall(call, {
        status: "ended",
        reason: "hangup",
        endedBy: from,
        duration,
      });
    } else {
      await Call.findByIdAndUpdate(data.callId, {
        status: 'ended',
        endTime: new Date(),
        duration,
        endedBy: from,
        endReason: "hangup",
      });
      io.to(to).emit("call_ended", { ...data, from, to, duration });
    }

    const mins = Math.floor(duration / 60);
    const secs = duration % 60;
    const msg = new Message({
      messageId: `call_${Date.now()}`,
      senderChatId: from,
      receiverChatId: to,
      senderDeviceId: "system",
      payloads: [{ deviceId: "all", ciphertext: `${data.callType == 'video' ? 'Video' : 'Voice'} call – ${mins}:${secs.toString().padStart(2, '0')}`, header: { iv: "" } }],
      timestamp: new Date()
    });
    await msg.save();
    io.to(to).emit("newMessage", msg.toObject());
    io.to(from).emit("newMessage", msg.toObject());

    // Send FCM for call log
    const receiver = await User.findOne({ chatId: to });
    const sender = await User.findOne({ chatId: from });
    if (receiver) {
      const mobileDevices = await Device.find({
        userId: receiver._id,
        type: "mobile",
        fcmToken: { $ne: null }
      });
      for (const device of mobileDevices) {
        await sendDataOnlyPushNotification({
          token: device.fcmToken,
          senderId: from,
          senderName: sender?.name || from,
          senderAvatar: sender?.profilePhoto || "",
          type: 0,
          messageId: msg.messageId,
          content: `${data.callType == 'video' ? 'Video' : 'Voice'} call – ${mins}:${secs.toString().padStart(2, '0')}`
        });
      }
    }
  });

  socket.on("send_message", async (data) => {
    const { senderId, receiverId, content, messageId, type, payloads } = data;

    console.log("📨 Sending from:", senderId, "to:", receiverId);

    // 1️⃣ Save message
    const message = await Message.create({
      messageId: messageId || Date.now().toString(),
      senderChatId: senderId,
      receiverChatId: receiverId,
      senderDeviceId: socket.data.deviceId || "socket",
      content,
      type: type || 0,
      payloads: payloads || [],
      status: "sent",
      timestamp: new Date()
    });

    // 2️⃣ Find receiver and sender info
    const [receiver, sender] = await Promise.all([
      User.findOne({ chatId: receiverId }),
      User.findOne({ chatId: senderId })
    ]);

    // 3️⃣ Emit to receiver's online sockets
    const receiverSockets = onlineUsers.get(receiverId);
    let delivered = false;

    if (receiverSockets && receiverSockets.size > 0) {
      for (const sId of receiverSockets) {
        io.to(sId).emit("receive_message", message.toObject());
      }
      delivered = true;
      console.log("✅ Message delivered via socket");
    }

    // 4️⃣ Send FCM to receiver's mobile devices
    if (receiver) {
      const mobileDevices = await Device.find({
        userId: receiver._id,
        type: "mobile",
        fcmToken: { $ne: null }
      });

      for (const device of mobileDevices) {
        // Skip FCM if the device is already connected via socket (optional, but sometimes safer to send anyway)
        // For "DATA-only" payloads, it's often good to send to ensure consistency.
        await sendDataOnlyPushNotification({
          token: device.fcmToken,
          senderId,
          senderName: sender?.name || senderId,
          senderAvatar: sender?.profilePhoto || "",
          type: type || 0,
          messageId: message.messageId,
          payloads: message.payloads,
          content: message.content
        });
      }
    }

    // 5️⃣ Update status if delivered via socket
    if (delivered) {
      message.status = "delivered";
      await message.save();
      socket.emit("message_delivered", {
        messageId: message.messageId,
        status: "delivered"
      });
    }

    socket.emit("message_sent", message.toObject());
  });

  socket.on("disconnect", async () => {
    const chatId = socket.data.chatId;
    const deviceId = socket.data.deviceId;
    removeOnlineSocket(socket.id);
    console.log("Socket disconnected:", socket.id);

    if (chatId) {
      const stillOnline = onlineUsers.has(chatId) && onlineUsers.get(chatId).size > 0;
      if (!stillOnline) {
        removeParticipantFromRooms(chatId, socket, { temporary: true });
        for (const call of activePeerCalls.values()) {
          if (call.callerId === chatId || call.calleeId === chatId) {
            schedulePeerDisconnectGrace(call, chatId);
          }
        }
      }
      const nowIso = new Date().toISOString();
      const presencePayload = {
        chatId,
        isOnline: stillOnline,
        lastSeen: stillOnline ? null : nowIso,
        serverNow: nowIso,
      };
      io.to(`user:${chatId}`).emit("presence_changed", presencePayload);
      io.to(presenceRoom(chatId)).emit("presence_changed", presencePayload);
      try {
        await User.updateOne(
          { chatId, socketId: socket.id },
          { $set: { socketId: null, lastSeen: new Date() } },
        );
        if (deviceId) {
          await Device.updateOne(
            { deviceId, socketId: socket.id },
            { $set: { socketId: null, lastActive: new Date() } },
          );
        }
      } catch (e) {
        console.error("Socket disconnect DB update failed:", e);
      }
    }
  });
});

async function purgeInactiveMobileSessions() {
  // Keep mobile sessions stable across normal background periods.
  // We mark stale sessions as inactive after a long idle window,
  // but do not revoke tokenVersion here.
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const staleUsers = await User.find({
    activeMobileDeviceId: { $ne: null },
    mobileLastHeartbeatAt: { $lt: cutoff },
  }).select("_id chatId activeMobileDeviceId");

  for (const user of staleUsers) {
    await Device.updateOne(
      { userId: user._id, deviceId: user.activeMobileDeviceId },
      {
        $set: {
          isActive: false,
          socketId: null,
          lastActive: new Date(),
        },
      },
    );
  }
}



const PORT = process.env.PORT || 3000;

async function bootstrapServer() {
  validatePaymentConfigAtStartup();
  initializeFirebaseAdmin();
  ensureUpdateConfig();
  await connectMongo();

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Convoo E2EE Server running on port ${PORT}`);
  });

  setInterval(() => {
    purgeExpiredGhostSessions().catch((e) =>
      console.error("Ghost expiry sweep failed:", e),
    );
    purgeInactiveMobileSessions().catch((e) =>
      console.error("Inactive mobile sweep failed:", e),
    );
  }, 5 * 60 * 1000);
}

bootstrapServer().catch((error) => {
  console.error("Failed to start Convoo backend:", error);
  process.exit(1);
});
