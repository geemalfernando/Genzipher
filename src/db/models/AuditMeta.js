import mongoose from "mongoose";

const AuditMetaSchema = new mongoose.Schema(
  {
    key: { type: String, required: true, unique: true, index: true },
    headHash: { type: String, required: true },
  },
  { timestamps: true }
);

export const AuditMeta =
  mongoose.models.AuditMeta || mongoose.model("AuditMeta", AuditMetaSchema);

