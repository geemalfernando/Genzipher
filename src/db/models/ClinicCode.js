import mongoose from "mongoose";

const ClinicCodeSchema = new mongoose.Schema(
  {
    codeHash: { type: String, required: true, unique: true, index: true },
    patientId: { type: String, default: null, index: true }, // optional binding to a specific patient (User.id)
    expiresAt: { type: Date, required: true, index: true },
    usedAt: { type: Date, default: null, index: true },
    usedByPatientId: { type: String, default: null, index: true },
  },
  { timestamps: true }
);

export const ClinicCode =
  mongoose.models.ClinicCode || mongoose.model("ClinicCode", ClinicCodeSchema);

