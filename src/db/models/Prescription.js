import mongoose from "mongoose";

const PrescriptionSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    doctorId: { type: String, required: true, index: true },
    patientIdToken: { type: String, required: true, index: true },
    medicineId: { type: String, required: true, index: true },
    dosage: { type: String, required: true },
    durationDays: { type: Number, required: true },
    issuedAt: { type: String, required: true },
    expiry: { type: String, required: true, index: true },
    nonce: { type: String, required: true, unique: true, index: true },
    signatureB64url: { type: String, required: true },
    status: { type: String, required: true, enum: ["active", "revoked"], default: "active", index: true },
  },
  { timestamps: true }
);

export const Prescription =
  mongoose.models.Prescription || mongoose.model("Prescription", PrescriptionSchema);

