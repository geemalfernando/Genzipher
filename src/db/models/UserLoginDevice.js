import mongoose from "mongoose";

const UserLoginDeviceSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    deviceId: { type: String, required: true, index: true },
    firstSeenAt: { type: Date, required: true, index: true },
    lastSeenAt: { type: Date, required: true, index: true },
    firstIp: { type: String, default: null, index: true },
    lastIp: { type: String, default: null, index: true },
    lastUserAgent: { type: String, default: null },
    verifiedAt: { type: Date, default: null, index: true },
    blockedAt: { type: Date, default: null, index: true },
  },
  { timestamps: true }
);

UserLoginDeviceSchema.index({ userId: 1, deviceId: 1 }, { unique: true });

export const UserLoginDevice =
  mongoose.models.UserLoginDevice ||
  mongoose.model("UserLoginDevice", UserLoginDeviceSchema);
