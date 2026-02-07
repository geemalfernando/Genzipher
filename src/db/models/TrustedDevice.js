import mongoose from "mongoose";

const TrustedDeviceSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    deviceId: { type: String, required: true, index: true },
    tokenHash: { type: String, required: true },
    expiresAt: { type: Date, required: true, index: true },
    lastUsedAt: { type: Date, default: null, index: true },
    revokedAt: { type: Date, default: null, index: true },
  },
  { timestamps: true }
);

TrustedDeviceSchema.index({ userId: 1, deviceId: 1 }, { unique: true });

export const TrustedDevice =
  mongoose.models.TrustedDevice || mongoose.model("TrustedDevice", TrustedDeviceSchema);

