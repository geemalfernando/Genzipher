import mongoose from "mongoose";

const VitalsSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    patientToken: { type: String, required: true, index: true },
    deviceId: { type: String, required: true, index: true },
    ts: { type: String, required: true, index: true },
    encrypted: {
      ivB64: { type: String, required: true },
      tagB64: { type: String, required: true },
      ciphertextB64: { type: String, required: true },
    },
  },
  { timestamps: true }
);

export const Vitals =
  mongoose.models.Vitals || mongoose.model("Vitals", VitalsSchema);

