import mongoose from "mongoose";

const PatientProfileSchema = new mongoose.Schema(
  {
    patientId: { type: String, required: true, unique: true, index: true }, // maps to User.id
    did: { type: String, default: null, index: true },
    status: {
      type: String,
      required: true,
      enum: ["PENDING", "VERIFIED", "ACTIVE", "QUARANTINED"],
      default: "PENDING",
      index: true,
    },
    piiRef: { type: String, default: null },
    trustScore: { type: Number, required: true, default: 0, index: true },
    trustExplainTop3: { type: [String], required: true, default: [] },
    lastKnownGeo: { type: String, default: null },
  },
  { timestamps: true }
);

export const PatientProfile =
  mongoose.models.PatientProfile ||
  mongoose.model("PatientProfile", PatientProfileSchema);

