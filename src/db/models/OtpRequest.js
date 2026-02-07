import mongoose from "mongoose";

const OtpRequestSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    purpose: { type: String, required: true, enum: ["LOGIN", "STEP_UP", "RESET", "DEVICE_REMOVE", "MFA_DISABLE"], index: true },
    otpHash: { type: String, required: true },
    expiresAt: { type: Date, required: true, index: true },
    attempts: { type: Number, required: true, default: 0 },
    used: { type: Boolean, required: true, default: false, index: true },
    sentTo: { type: String, required: true },
    lastSentAt: { type: Date, required: true, index: true },
    context: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { timestamps: true }
);

OtpRequestSchema.index({ userId: 1, purpose: 1, createdAt: -1 });

export const OtpRequest =
  mongoose.models.OtpRequest || mongoose.model("OtpRequest", OtpRequestSchema);
