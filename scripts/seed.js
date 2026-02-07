import "dotenv/config";
import crypto from "node:crypto";

import { connectMongo } from "../src/db/connect.js";
import { User } from "../src/db/models/User.js";
import { Assignment } from "../src/db/models/Assignment.js";
import { Device } from "../src/db/models/Device.js";
import { PatientKey } from "../src/db/models/PatientKey.js";
import { PatientProfile } from "../src/db/models/PatientProfile.js";
import { Prescription } from "../src/db/models/Prescription.js";
import { Batch } from "../src/db/models/Batch.js";
import { Dispense } from "../src/db/models/Dispense.js";
import { Vitals } from "../src/db/models/Vitals.js";
import { AuditMeta } from "../src/db/models/AuditMeta.js";
import { AuditEntry } from "../src/db/models/AuditEntry.js";
import { ClinicCode } from "../src/db/models/ClinicCode.js";
import { RegistrationAttempt } from "../src/db/models/RegistrationAttempt.js";
import { OtpRequest } from "../src/db/models/OtpRequest.js";

import { generateEd25519KeyPairPem } from "../src/lib/crypto.js";

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

function hmacTokenizePatientId(patientUserId) {
  const h = crypto.createHmac("sha256", JWT_SECRET);
  h.update(`patient:${patientUserId}`);
  return h.digest("hex").slice(0, 32);
}

function mkUser({ id, username, role, password, withSigningKeys }) {
  const base = { id, username, role, password, status: "active" };
  if (!withSigningKeys) return base;
  const { publicKeyPem, privateKeyPem } = generateEd25519KeyPairPem();
  return { ...base, publicKeyPem, privateKeyPem };
}

async function main() {
  await connectMongo();

  await Promise.all([
    User.deleteMany({}),
    Assignment.deleteMany({}),
    Device.deleteMany({}),
    PatientKey.deleteMany({}),
    PatientProfile.deleteMany({}),
    Prescription.deleteMany({}),
    Batch.deleteMany({}),
    Dispense.deleteMany({}),
    Vitals.deleteMany({}),
    AuditMeta.deleteMany({}),
    AuditEntry.deleteMany({}),
    ClinicCode.deleteMany({}),
    RegistrationAttempt.deleteMany({}),
    OtpRequest.deleteMany({}),
  ]);

  const users = [
    { ...mkUser({ id: "u_doctor1", username: "doctor1", role: "doctor", password: "password123", withSigningKeys: true }), email: "doctor1@demo.local", mfaEnabled: false, mfaMethod: "NONE" },
    { ...mkUser({ id: "u_patient1", username: "patient1", role: "patient", password: "password123", withSigningKeys: false }), email: "patient1@demo.local", mfaEnabled: false, mfaMethod: "NONE" },
    { ...mkUser({ id: "u_pharmacy1", username: "pharmacy1", role: "pharmacy", password: "password123", withSigningKeys: false }), email: "pharmacy1@demo.local", mfaEnabled: false, mfaMethod: "NONE" },
    { ...mkUser({ id: "u_mfg1", username: "mfg1", role: "manufacturer", password: "password123", withSigningKeys: true }), email: "mfg1@demo.local", mfaEnabled: false, mfaMethod: "NONE" },
    { ...mkUser({ id: "u_admin1", username: "admin1", role: "admin", password: "password123", withSigningKeys: false }), email: "admin1@demo.local", mfaEnabled: false, mfaMethod: "NONE" },
  ];

  await User.insertMany(users);

  const patientToken = hmacTokenizePatientId("u_patient1");
  await Assignment.create({ doctorId: "u_doctor1", patientTokens: [patientToken] });
  await PatientKey.create({ patientToken, keyB64: crypto.randomBytes(32).toString("base64") });
  await PatientProfile.create({
    patientId: "u_patient1",
    status: "ACTIVE",
    trustScore: 95,
    trustExplainTop3: ["clinic_code_used:+35", "ip_reuse_count:0", "new_device:0"],
    lastKnownGeo: "DEMO",
  });
  await AuditMeta.create({ key: "audit_meta", headHash: "GENESIS" });

  console.log("MongoDB seed complete.");
  console.log(`MONGODB_URI: ${process.env.MONGODB_URI || "mongodb://localhost:27017/genzipher_mvp"}`);
  console.log("Demo users: doctor1 / patient1 / pharmacy1 / mfg1 / admin1 (password123)");
  console.log("Demo MFA code for doctor/pharmacy/mfg/admin: 123456");
  console.log(`Patient token for u_patient1: ${patientToken}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
