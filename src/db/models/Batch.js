import mongoose from "mongoose";

const BatchSchema = new mongoose.Schema(
  {
    batchId: { type: String, required: true, unique: true, index: true },
    manufacturerId: { type: String, required: true, index: true },
    lot: { type: String, required: true },
    expiry: { type: String, required: true, index: true },
    certificateHash: { type: String, required: true },
    issuedAt: { type: String, required: true },
    signatureB64url: { type: String, required: true },
    status: { type: String, required: true, enum: ["valid", "recalled", "quarantined"], default: "valid", index: true },
  },
  { timestamps: true }
);

export const Batch = mongoose.models.Batch || mongoose.model("Batch", BatchSchema);

