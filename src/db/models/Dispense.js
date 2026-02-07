import mongoose from "mongoose";

const DispenseSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    ts: { type: String, required: true, index: true },
    pharmacyId: { type: String, required: true, index: true },
    allowed: { type: Boolean, required: true, index: true },
    rxId: { type: String, default: null, index: true },
    batchId: { type: String, default: null, index: true },
    checks: { type: mongoose.Schema.Types.Mixed, required: true },
  },
  { timestamps: true }
);

export const Dispense =
  mongoose.models.Dispense || mongoose.model("Dispense", DispenseSchema);

