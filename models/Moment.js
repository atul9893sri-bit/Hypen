const mongoose = require("mongoose");

const momentViewSchema = new mongoose.Schema(
  {
    viewerId: {
      type: String,
      required: true,
      index: true,
    },
    viewerName: {
      type: String,
      default: "",
    },
    viewedAt: {
      type: Date,
      default: Date.now,
    },
    liked: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false },
);

const momentCommentSchema = new mongoose.Schema(
  {
    id: {
      type: String,
      required: true,
    },
    userId: {
      type: String,
      required: true,
      index: true,
    },
    userName: {
      type: String,
      default: "",
    },
    content: {
      type: String,
      required: true,
      trim: true,
      maxlength: 1000,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { _id: false },
);

const momentSchema = new mongoose.Schema(
  {
    id: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userId: {
      type: String,
      required: true,
      index: true,
    },
    userName: {
      type: String,
      required: true,
      trim: true,
    },
    userAvatar: {
      type: String,
      default: "",
    },
    type: {
      type: Number,
      required: true,
      min: 0,
    },
    content: {
      type: String,
      default: "",
      trim: true,
    },
    localMediaPath: {
      type: String,
      default: "",
    },
    mediaUrl: {
      type: String,
      default: "",
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expireAfterSeconds: 0 },
    },
    backgroundColor: Number,
    fontFamily: String,
    likes: {
      type: [String],
      default: [],
    },
    views: {
      type: [momentViewSchema],
      default: [],
    },
    comments: {
      type: [momentCommentSchema],
      default: [],
    },
  },
  {
    timestamps: true,
  },
);

module.exports = mongoose.model("Moment", momentSchema);
