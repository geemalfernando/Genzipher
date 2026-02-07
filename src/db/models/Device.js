import mongoose from "mongoose";

const DeviceSchema = new mongoose.Schema(
  {
    deviceId: { type: String, required: true, unique: true, index: true },
    patientToken: { type: String, required: true, index: true },
    publicKeyPem: { type: String, required: true },
    status: { type: String, required: true, enum: ["active", "blocked"], default: "active", index: true },
  },
  { timestamps: true }
);

export const Device = mongoose.models.Device || mongoose.model("Device", DeviceSchema);

