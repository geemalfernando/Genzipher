import mongoose from "mongoose";

const MagicLinkRequestSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    purpose: { type: String, required: true, enum: ["NEW_DEVICE"], index: true },
    tokenHash: { type: String, required: true, index: true },
    expiresAt: { type: Date, required: true, index: true },
    usedAt: { type: Date, default: null, index: true },
    sentTo: { type: String, required: true },
    context: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { timestamps: true }
);

MagicLinkRequestSchema.index({ userId: 1, purpose: 1, createdAt: -1 });

export const MagicLinkRequest =
  mongoose.models.MagicLinkRequest ||
  mongoose.model("MagicLinkRequest", MagicLinkRequestSchema);

