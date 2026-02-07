import mongoose from "mongoose";

const MedicineSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    name: { type: String, required: true, index: true },
    genericName: { type: String, default: null, index: true },
    manufacturer: { type: String, required: true, index: true },
    category: { type: String, required: true, index: true },
    dosageForms: { type: [String], default: [] },
    strengths: { type: [String], default: [] },
    description: { type: String, default: null },
    activeIngredients: { type: [String], default: [] },
    storageConditions: { type: String, default: null },
    expiryPeriod: { type: Number, default: null },
    requiresPrescription: { type: Boolean, default: true, index: true },
    status: { type: String, enum: ["active", "inactive"], default: "active", index: true },
    createdBy: { type: String, required: true, index: true },
    createdAt: { type: String, required: true, index: true },
  },
  { timestamps: true }
);

MedicineSchema.index({ name: 1, manufacturer: 1 });
MedicineSchema.index({ category: 1, status: 1 });

export const Medicine = mongoose.models.Medicine || mongoose.model("Medicine", MedicineSchema);

