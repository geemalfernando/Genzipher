import mongoose from "mongoose";

const AuditEntrySchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    ts: { type: String, required: true, index: true },
    actor: { type: mongoose.Schema.Types.Mixed, required: true },
    action: { type: String, required: true, index: true },
    details: { type: mongoose.Schema.Types.Mixed, required: true },
    prevHash: { type: String, required: true, index: true },
    hash: { type: String, required: true, index: true },
  },
  { timestamps: true }
);

export const AuditEntry =
  mongoose.models.AuditEntry || mongoose.model("AuditEntry", AuditEntrySchema);

