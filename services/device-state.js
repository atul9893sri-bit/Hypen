const Device = require("../models/Device");

const MOBILE_INACTIVE_MS = 5 * 60 * 1000;
const MAX_LINKED_DEVICES = 4;

function isRecentlyActive(dateValue) {
  if (!dateValue) {
    return false;
  }
  return Date.now() - new Date(dateValue).getTime() <= MOBILE_INACTIVE_MS;
}

async function getActiveMobileDevice(userId, activeMobileDeviceId) {
  if (!activeMobileDeviceId) {
    return null;
  }
  const device = await Device.findOne({
    userId,
    deviceId: activeMobileDeviceId,
    type: "mobile",
  });
  if (!device || !device.isActive || !isRecentlyActive(device.lastActive)) {
    return null;
  }
  return device;
}

async function ensureDeviceLimit(userId) {
  const count = await Device.countDocuments({
    userId,
    isActive: true,
  });
  return count < MAX_LINKED_DEVICES;
}

async function revokeDevice(deviceId) {
  const device = await Device.findOne({ deviceId });
  if (!device) {
    return null;
  }
  device.isActive = false;
  device.tokenVersion += 1;
  device.socketId = null;
  device.lastActive = new Date();
  await device.save();
  return device;
}

async function revokeAllDesktopDevices(userId) {
  await Device.updateMany(
    { userId, type: "desktop", isActive: true },
    {
      $set: {
        isActive: false,
        socketId: null,
        lastActive: new Date(),
      },
      $inc: {
        tokenVersion: 1,
      },
    },
  );
}

module.exports = {
  MOBILE_INACTIVE_MS,
  MAX_LINKED_DEVICES,
  isRecentlyActive,
  getActiveMobileDevice,
  ensureDeviceLimit,
  revokeDevice,
  revokeAllDesktopDevices,
};
