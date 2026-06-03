const crypto = require("crypto");
const { promisify } = require("util");
const { v4: uuidv4 } = require("uuid");
const AuthSession = require("../models/AuthSession");

let bcrypt = null;
try {
  bcrypt = require("bcryptjs");
} catch (_) {
  bcrypt = null;
}

const scryptAsync = promisify(crypto.scrypt);

const SESSION_TTL_MS = 60 * 1000;
const MAX_PIN_ATTEMPTS = 5;

function buildExpiryDate() {
  return new Date(Date.now() + SESSION_TTL_MS);
}

function generatePin() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function hashPin(pin) {
  if (bcrypt) {
    return bcrypt.hash(pin, 10);
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scryptAsync(pin, salt, 64);
  return `scrypt:${salt}:${Buffer.from(derivedKey).toString("hex")}`;
}

async function verifyPin(pin, storedHash) {
  if (!storedHash) {
    return false;
  }

  if (!storedHash.startsWith("scrypt:")) {
    if (!bcrypt) {
      return false;
    }
    return bcrypt.compare(pin, storedHash);
  }

  const [, salt, expectedHex] = storedHash.split(":");
  if (!salt || !expectedHex) {
    return false;
  }

  const derivedKey = await scryptAsync(pin, salt, 64);
  const derivedBuffer = Buffer.from(derivedKey);
  const expectedBuffer = Buffer.from(expectedHex, "hex");
  if (derivedBuffer.length !== expectedBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(derivedBuffer, expectedBuffer);
}

async function createQrSession({ deviceId, deviceName, platform }) {
  return AuthSession.create({
    sessionId: uuidv4(),
    deviceId,
    deviceName,
    platform,
    type: "qr",
    expiresAt: buildExpiryDate(),
    status: "pending",
  });
}

async function createPinSession({ userId, deviceId, deviceName, platform }) {
  const pin = generatePin();
  const pinHash = await hashPin(pin);
  const session = await AuthSession.create({
    sessionId: uuidv4(),
    userId,
    deviceId,
    deviceName,
    platform,
    type: "pin",
    pinHash,
    expiresAt: buildExpiryDate(),
    status: "pending",
  });
  return { pin, session };
}

function isExpired(session) {
  return !session || new Date(session.expiresAt).getTime() <= Date.now();
}

async function markApproved(session, authPayload) {
  session.status = "approved";
  session.approvedAt = new Date();
  session.authPayload = authPayload;
  await session.save();
  return session;
}

async function consumeApprovedSession(sessionId) {
  const session = await AuthSession.findOne({ sessionId });
  if (!session || isExpired(session)) {
    return null;
  }
  if (session.status !== "approved" || session.consumedAt) {
    return null;
  }
  session.status = "used";
  session.consumedAt = new Date();
  await session.save();
  return session.authPayload;
}

async function validatePinSession({ phoneUserId, pin }) {
  const session = await AuthSession.findOne({
    userId: phoneUserId,
    type: "pin",
    status: "pending",
  }).sort({ createdAt: -1 });

  if (!session || isExpired(session)) {
    return { ok: false, code: "PIN_EXPIRED" };
  }
  if (session.attemptCount >= MAX_PIN_ATTEMPTS) {
    session.status = "revoked";
    await session.save();
    return { ok: false, code: "PIN_RATE_LIMITED" };
  }

  const match = await verifyPin(pin, session.pinHash || "");
  if (!match) {
    session.attemptCount += 1;
    if (session.attemptCount >= MAX_PIN_ATTEMPTS) {
      session.status = "revoked";
    }
    await session.save();
    return { ok: false, code: "PIN_INVALID" };
  }

  return { ok: true, session };
}

module.exports = {
  SESSION_TTL_MS,
  createQrSession,
  createPinSession,
  isExpired,
  markApproved,
  consumeApprovedSession,
  validatePinSession,
};
