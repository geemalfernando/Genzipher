import mongoose from "mongoose";

const AccountRequestSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    type: { type: String, required: true, enum: ["ACTIVATE", "DELETE"], index: true },
    userId: { type: String, required: true, index: true },
    role: { type: String, required: true, enum: ["doctor", "patient"], index: true },
    status: { type: String, required: true, enum: ["PENDING", "APPROVED", "REJECTED"], default: "PENDING", index: true },
    createdAtIso: { type: String, required: true },
    decidedAtIso: { type: String, default: null },
    decidedBy: { type: String, default: null },
    note: { type: String, default: null },
    // Snapshot for notifications/audit (email can change later)
    email: { type: String, default: null },
    username: { type: String, default: null },
  },
  { timestamps: true }
);

AccountRequestSchema.index({ userId: 1, type: 1, status: 1 });
AccountRequestSchema.index({ type: 1, status: 1, createdAtIso: -1 });

export const AccountRequest =
  mongoose.models.AccountRequest || mongoose.model("AccountRequest", AccountRequestSchema);

