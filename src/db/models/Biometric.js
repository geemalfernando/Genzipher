import mongoose from "mongoose";

// WebAuthn credential storage for MVP.
// NOTE: This MVP stores the credential response JSON for demo purposes.
// For production-grade verification, use a dedicated WebAuthn server library.
const BiometricSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    role: { type: String, required: true, enum: ["pharmacy", "doctor", "admin", "manufacturer"], index: true },
    credentialIdB64u: { type: String, required: true, unique: true, index: true },
    publicKeyJson: { type: String, required: true },
    counter: { type: Number, default: 0 },
    deviceName: { type: String, default: null },
    enrolledAt: { type: Date, required: true, default: Date.now, index: true },
    lastUsedAt: { type: Date, default: null, index: true },
    isActive: { type: Boolean, default: true, index: true },
  },
  { timestamps: true }
);

BiometricSchema.index({ userId: 1, isActive: 1 });
BiometricSchema.index({ role: 1, isActive: 1 });

export const Biometric = mongoose.models.Biometric || mongoose.model("Biometric", BiometricSchema);
