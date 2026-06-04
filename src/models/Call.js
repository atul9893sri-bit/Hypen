const mongoose = require('mongoose');

const CallSchema = new mongoose.Schema({
    caller: { type: String, required: true },
    receiver: { type: String, required: true },
    roomId: { type: String, default: null, index: true },
    participants: { type: [String], default: [] },
    isGroup: { type: Boolean, default: false },
    type: { type: String, enum: ['voice', 'video'], required: true },
    status: { type: String, enum: ['ringing', 'accepted', 'rejected', 'ended', 'missed'], default: 'ringing' },
    answeredBy: { type: String, default: null },
    endedBy: { type: String, default: null },
    endReason: { type: String, default: null },
    reconnectGraceUntil: { type: Date, default: null },
    metadata: {
        initiatorDeviceId: { type: String, default: null },
        callerNetwork: { type: String, default: null },
        receiverNetwork: { type: String, default: null },
    },
    startTime: { type: Date },
    endTime: { type: Date },
    duration: { type: Number, default: 0 }, // in seconds
    timestamp: { type: Date, default: Date.now }
});

CallSchema.index({ caller: 1, timestamp: -1 });
CallSchema.index({ receiver: 1, timestamp: -1 });
CallSchema.index({ participants: 1, status: 1, timestamp: -1 });
CallSchema.index({ roomId: 1, status: 1, timestamp: -1 });

module.exports = mongoose.model('Call', CallSchema);
