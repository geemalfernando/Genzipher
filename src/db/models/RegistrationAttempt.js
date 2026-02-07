import mongoose from "mongoose";

const RegistrationAttemptSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true, index: true },
    patientId: { type: String, default: null, index: true },
    ts: { type: Date, required: true, index: true },
  },
  { timestamps: true }
);

RegistrationAttemptSchema.index({ ip: 1, ts: -1 });

export const RegistrationAttempt =
  mongoose.models.RegistrationAttempt ||
  mongoose.model("RegistrationAttempt", RegistrationAttemptSchema);

