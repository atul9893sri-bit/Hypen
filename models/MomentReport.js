const mongoose = require("mongoose");

const momentReportSchema = new mongoose.Schema(
  {
    momentId: {
      type: String,
      required: true,
      index: true,
    },
    ownerChatId: {
      type: String,
      required: true,
      index: true,
    },
    reporterId: {
      type: String,
      required: true,
      index: true,
    },
    targetOwnerChatId: {
      type: String,
      required: true,
      default: "6076322",
      index: true,
    },
    preview: {
      type: String,
      default: "",
      maxlength: 2000,
    },
    status: {
      type: String,
      enum: ["open", "reviewing", "closed"],
      default: "open",
    },
    reportedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: true,
  },
);

momentReportSchema.index(
  { momentId: 1, reporterId: 1 },
  { unique: true, name: "unique_moment_report_per_user" },
);

module.exports = mongoose.model("MomentReport", momentReportSchema);
