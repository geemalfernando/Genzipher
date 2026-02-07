import mongoose from "mongoose";

const StaffSessionSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    role: { type: String, required: true, enum: ["pharmacy", "doctor", "admin", "manufacturer"], index: true },
    deviceId: { type: String, required: true, index: true },
    ipAddress: { type: String, required: true, index: true },
    userAgent: { type: String, default: null },
    firstSeenAt: { type: Date, required: true, index: true },
    lastSeenAt: { type: Date, required: true, index: true },
    isActive: { type: Boolean, default: true, index: true },
    biometricVerified: { type: Boolean, default: false, index: true },
    biometricVerifiedAt: { type: Date, default: null, index: true },
  },
  { timestamps: true }
);

StaffSessionSchema.index({ userId: 1, deviceId: 1, isActive: 1 });
StaffSessionSchema.index({ role: 1, isActive: 1, lastSeenAt: -1 });

export const StaffSession =
  mongoose.models.StaffSession || mongoose.model("StaffSession", StaffSessionSchema);
