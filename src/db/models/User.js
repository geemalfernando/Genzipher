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
    status: { type: String, required: true, enum: ["active", "blocked"], default: "active", index: true },
    publicKeyPem: { type: String, default: null },
    privateKeyPem: { type: String, default: null },
  },
  { timestamps: true }
);

export const User = mongoose.models.User || mongoose.model("User", UserSchema);
