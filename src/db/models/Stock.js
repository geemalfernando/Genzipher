import mongoose from "mongoose";

const StockSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    medicineId: { type: String, required: true, index: true },
    quantity: { type: Number, required: true, index: true },
    unit: { type: String, default: "units" },
    expiryDate: { type: String, required: true, index: true }, // ISO date (YYYY-MM-DD)
    batchId: { type: String, default: null, index: true },
    status: {
      type: String,
      enum: ["available", "low_stock", "out_of_stock", "expired", "quarantined"],
      default: "available",
      index: true,
    },
    location: { type: String, default: null },
    minStockLevel: { type: Number, default: 10 },
    costPerUnit: { type: Number, default: null },
    sellingPricePerUnit: { type: Number, default: null },
    notes: { type: String, default: null },
    createdBy: { type: String, required: true, index: true },
    createdAt: { type: String, required: true, index: true },
    lastRestockedAt: { type: String, default: null, index: true },
    lastRestockedBy: { type: String, default: null, index: true },
  },
  { timestamps: true }
);

StockSchema.index({ medicineId: 1, status: 1 });
StockSchema.index({ expiryDate: 1, status: 1 });

export const Stock = mongoose.models.Stock || mongoose.model("Stock", StockSchema);

