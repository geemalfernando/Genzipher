import mongoose from "mongoose";

const QualityVerificationSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    medicineId: { type: String, required: true, index: true },
    batchId: { type: String, default: null, index: true },
    stockId: { type: String, default: null, index: true },
    verifiedBy: { type: String, required: true, index: true },
    verificationDate: { type: String, required: true, index: true },
    standard: { type: String, required: true, index: true },
    checks: { type: mongoose.Schema.Types.Mixed, default: {} },
    overallStatus: { type: String, enum: ["pending", "approved", "rejected"], default: "pending", index: true },
    notes: { type: String, default: null },
    testResults: { type: mongoose.Schema.Types.Mixed, default: null },
    createdAt: { type: String, required: true, index: true },
  },
  { timestamps: true }
);

QualityVerificationSchema.index({ medicineId: 1, verificationDate: -1 });
QualityVerificationSchema.index({ overallStatus: 1, verificationDate: -1 });

export const QualityVerification =
  mongoose.models.QualityVerification || mongoose.model("QualityVerification", QualityVerificationSchema);

