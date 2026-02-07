import mongoose from "mongoose";

const AppointmentSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    patientId: { type: String, required: true, index: true },
    patientToken: { type: String, required: true, index: true },
    doctorId: { type: String, required: true, index: true },
    appointmentDate: { type: String, required: true, index: true }, // YYYY-MM-DD
    appointmentTime: { type: String, required: true, index: true }, // HH:MM (24h)
    notes: { type: String, default: null },
    status: { type: String, required: true, enum: ["scheduled", "completed", "cancelled"], default: "scheduled", index: true },
    requestedDeviceId: { type: String, default: null, index: true },
    requestedIp: { type: String, default: null },
    integrityHash: { type: String, required: true, index: true },
    createdAt: { type: String, required: true, index: true },
  },
  { timestamps: true }
);

AppointmentSchema.index({ patientId: 1, appointmentDate: -1, appointmentTime: -1 });
AppointmentSchema.index({ doctorId: 1, appointmentDate: -1, appointmentTime: -1 });

export const Appointment = mongoose.models.Appointment || mongoose.model("Appointment", AppointmentSchema);

