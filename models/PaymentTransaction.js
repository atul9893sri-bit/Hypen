const mongoose = require("mongoose");

const paymentTransactionSchema = new mongoose.Schema(
  {
    chatId: {
      type: String,
      required: true,
      index: true,
    },
    purpose: {
      type: String,
      enum: ["subscription", "change_chat_id"],
      required: true,
      index: true,
    },
    plan: {
      type: String,
      enum: ["monthly", "yearly", null],
      default: null,
    },
    amount: {
      type: Number,
      required: true,
    },
    currency: {
      type: String,
      default: "INR",
    },
    status: {
      type: String,
      enum: ["created", "pending", "confirmed", "failed", "consumed"],
      default: "created",
      index: true,
    },
    razorpayOrderId: {
      type: String,
      required: true,
      unique: true,
    },
    razorpayPaymentId: {
      type: String,
      default: null,
      unique: true,
      sparse: true,
    },
    razorpaySignature: {
      type: String,
      default: null,
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    consumedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

module.exports = mongoose.model("PaymentTransaction", paymentTransactionSchema);
