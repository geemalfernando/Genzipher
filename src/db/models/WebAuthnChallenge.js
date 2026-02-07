import mongoose from "mongoose";

const WebAuthnChallengeSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    purpose: { type: String, required: true, enum: ["ENROLL", "VERIFY"], index: true },
    challenge: { type: String, required: true }, // base64url
    expiresAt: { type: Date, required: true, index: true },
  },
  { timestamps: true }
);

WebAuthnChallengeSchema.index({ userId: 1, purpose: 1, expiresAt: -1 });

export const WebAuthnChallenge =
  mongoose.models.WebAuthnChallenge || mongoose.model("WebAuthnChallenge", WebAuthnChallengeSchema);

