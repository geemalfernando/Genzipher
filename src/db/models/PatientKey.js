import mongoose from "mongoose";

const PatientKeySchema = new mongoose.Schema(
  {
    patientToken: { type: String, required: true, unique: true, index: true },
    keyB64: { type: String, required: true },
  },
  { timestamps: true }
);

export const PatientKey =
  mongoose.models.PatientKey || mongoose.model("PatientKey", PatientKeySchema);

