import mongoose from "mongoose";

const UserSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    username: { type: String, required: true, unique: true, index: true },
    email: { type: String, default: null, unique: true, sparse: true, index: true },
    role: {
      type: String,
      required: true,
      enum: ["doctor", "patient", "pharmacy", "manufacturer", "admin"],
      index: true,
    },
    password: { type: String, required: true },
    mfaEnabled: { type: Boolean, required: true, default: false, index: true },
    mfaMethod: {
      type: String,
      required: true,
      enum: ["NONE", "EMAIL_OTP", "TOTP"],
      default: "NONE",
      index: true,
    },
    // Encrypted TOTP secret (base32) for authenticator-app MFA.
    // Stored as { ivB64, tagB64, ciphertextB64 }.
    mfaTotpSecretEnc: { type: mongoose.Schema.Types.Mixed, default: null },
    mfaTotpEnabledAt: { type: Date, default: null, index: true },
    biometricEnrolled: { type: Boolean, required: true, default: false, index: true },
    biometricEnrolledAt: { type: Date, default: null, index: true },
    createdFromDeviceId: { type: String, default: null, index: true },
    lastLoginDeviceId: { type: String, default: null, index: true },
    lastLoginAt: { type: Date, default: null, index: true },
    passwordResetLockedUntil: { type: Date, default: null, index: true },
    passwordResetLockedAt: { type: Date, default: null, index: true },
    passwordResetLockedReason: { type: String, default: null },
    passwordResetLockedBy: { type: String, default: null },
    status: { type: String, required: true, enum: ["pending", "active", "blocked", "deleted"], default: "active", index: true },
    publicKeyPem: { type: String, default: null },
    privateKeyPem: { type: String, default: null },
  },
  { timestamps: true }
);

export const User = mongoose.models.User || mongoose.model("User", UserSchema);
