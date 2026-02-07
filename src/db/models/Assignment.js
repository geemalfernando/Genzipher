import mongoose from "mongoose";

const AssignmentSchema = new mongoose.Schema(
  {
    doctorId: { type: String, required: true, unique: true, index: true },
    patientTokens: { type: [String], required: true, default: [] },
  },
  { timestamps: true }
);

export const Assignment =
  mongoose.models.Assignment || mongoose.model("Assignment", AssignmentSchema);

