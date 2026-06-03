const User = require("../models/User");
const Device = require("../models/Device");
const {
  verifyAccessToken,
  isTokenExpiredError,
} = require("../services/auth-token");

function readBearerToken(req) {
  const header = req.header("authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : "";
}

async function requireAuth(req, res, next) {
  try {
    const token = readBearerToken(req);
    if (!token) {
      return res.status(401).json({ error: "Missing auth token" });
    }

    let payload;
    try {
      payload = verifyAccessToken(token);
    } catch (error) {
      if (isTokenExpiredError(error)) {
        return res.status(401).json({
          error: "Access token expired",
          code: "TOKEN_EXPIRED",
        });
      }
      return res.status(401).json({ error: "Unauthorized" });
    }

    const userId = String(payload?.sub || "").trim();
    const chatId = String(payload?.chatId || "").trim();
    const deviceId = String(payload?.deviceId || "").trim();
    const tokenVersion = Number(payload?.tokenVersion || 0);

    if (!userId || !chatId || !deviceId) {
      return res.status(401).json({ error: "Invalid auth token" });
    }

    const [user, device] = await Promise.all([
      User.findById(userId),
      Device.findOne({ userId, deviceId }),
    ]);

    if (!user || !device) {
      return res.status(401).json({ error: "Session not found" });
    }

    if (String(user.chatId) !== chatId) {
      return res.status(401).json({ error: "Session chat ID mismatch" });
    }

    if (!device.isActive) {
      return res.status(401).json({ error: "Device session is inactive" });
    }

    if (Number(device.tokenVersion || 0) !== tokenVersion) {
      return res.status(401).json({ error: "Session has been revoked" });
    }

    req.auth = payload;
    req.user = user;
    req.device = device;
    next();
  } catch (error) {
    console.error("Auth error:", error.message);
    return res.status(401).json({ error: "Unauthorized" });
  }
}

function requireDeviceType(type) {
  return (req, res, next) => {
    if (!req.user || !req.device) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (req.device.type !== type) {
      return res.status(403).json({ error: `${type} device required` });
    }

    next();
  };
}

module.exports = {
  requireAuth,
  requireDeviceType,
};
