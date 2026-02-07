import mongoose from "mongoose";

const DeviceSchema = new mongoose.Schema(
  {
    deviceId: { type: String, required: true, unique: true, index: true },
    patientToken: { type: String, required: true, index: true },
    publicKeyPem: { type: String, required: true },
    fingerprintHash: { type: String, default: null, index: true },
    firstSeenAt: { type: Date, default: null, index: true },
    lastSeenAt: { type: Date, default: null, index: true },
    riskLevel: { type: String, required: true, enum: ["low", "medium", "high"], default: "low", index: true },
    status: {
      type: String,
      required: true,
      enum: ["pending", "active", "blocked"],
      default: "pending",
      index: true,
    },
    challengeNonce: { type: String, default: null, index: true },
    challengeIssuedAt: { type: Date, default: null, index: true },
  },
  { timestamps: true }
);

export const Device = mongoose.models.Device || mongoose.model("Device", DeviceSchema);
