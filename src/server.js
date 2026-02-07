import "dotenv/config";
import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { connectMongo } from "./db/connect.js";
import { User } from "./db/models/User.js";
import { Assignment } from "./db/models/Assignment.js";
import { Device } from "./db/models/Device.js";
import { PatientKey } from "./db/models/PatientKey.js";
import { Prescription } from "./db/models/Prescription.js";
import { Batch } from "./db/models/Batch.js";
import { Dispense } from "./db/models/Dispense.js";
import { Vitals } from "./db/models/Vitals.js";
import { AuditMeta } from "./db/models/AuditMeta.js";
import { AuditEntry } from "./db/models/AuditEntry.js";

import {
  aes256gcmDecrypt,
  aes256gcmEncrypt,
  nowIso,
  randomId,
  signObjectEd25519,
  verifyObjectEd25519,
} from "./lib/crypto.js";
import { jwtSignHs256, jwtVerifyHs256 } from "./lib/jwt.js";
import { computeAuditHash } from "./lib/audit.js";

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const DEMO_MFA_CODE = process.env.DEMO_MFA_CODE || "123456";
const MFA_REQUIRED_ROLES = new Set(["doctor", "pharmacy", "manufacturer", "admin"]);

function hmacTokenizePatientId(patientUserId) {
  const h = crypto.createHmac("sha256", JWT_SECRET);
  h.update(`patient:${patientUserId}`);
  return h.digest("hex").slice(0, 32);
}

function getBearer(req) {
  const header = req.header("authorization") || "";
  const [kind, token] = header.split(" ");
  if (kind !== "Bearer" || !token) return null;
  return token;
}

function requireAuth(req, res, next) {
  const token = getBearer(req);
  if (!token) return res.status(401).json({ error: "missing_bearer_token" });
  const result = jwtVerifyHs256({ token, secret: JWT_SECRET });
  if (!result.ok) return res.status(401).json({ error: "invalid_token", detail: result.error });
  req.auth = result.payload;
  return next();
}

function requireRole(roles) {
  return (req, res, next) => {
    if (!req.auth || !roles.includes(req.auth.role)) {
      return res.status(403).json({ error: "forbidden", required: roles });
    }
    return next();
  };
}

async function auditAppend({ actor, action, details }) {
  const metaKey = "audit_meta";
  const existingMeta = await AuditMeta.findOne({ key: metaKey }).lean();
  const prevHash = existingMeta?.headHash || "GENESIS";

  const entryWithoutHash = {
    id: randomId("audit"),
    ts: nowIso(),
    actor,
    action,
    details,
    prevHash,
  };
  const hash = computeAuditHash({ prevHash, entryWithoutHash });
  const entry = { ...entryWithoutHash, hash };

  await AuditEntry.create(entry);
  await AuditMeta.updateOne({ key: metaKey }, { $set: { headHash: hash } }, { upsert: true });
  return entry;
}

async function ensureIndexes() {
  await Promise.all([
    User.init(),
    Assignment.init(),
    Device.init(),
    PatientKey.init(),
    Prescription.init(),
    Batch.init(),
    Dispense.init(),
    Vitals.init(),
    AuditMeta.init(),
    AuditEntry.init(),
  ]);
}

async function start() {
  await connectMongo();
  await ensureIndexes();

  const app = express();
  app.disable("x-powered-by");
  app.use(cors());
  app.use(express.json({ limit: "1mb" }));

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const publicDir = path.resolve(__dirname, "../public");
  app.use("/", express.static(publicDir));

  // Friendly aliases / SPA-style paths
  app.get(["/home", "/home/"], (req, res) => res.redirect(302, "/"));

  app.get("/health", async (req, res) => {
    res.json({ ok: true, ts: nowIso() });
  });

  // --- Auth ---
  app.post("/auth/login", async (req, res) => {
    const { username, password, mfaCode } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "bad_request", message: "username/password required" });

    const user = await User.findOne({ username }).lean();
    if (!user || user.password !== password || user.status !== "active") {
      await auditAppend({
        actor: { username },
        action: "auth.login_failed",
        details: { reason: "bad_credentials_or_inactive" },
      });
      return res.status(401).json({ error: "invalid_credentials" });
    }

    if (MFA_REQUIRED_ROLES.has(user.role) && mfaCode !== DEMO_MFA_CODE) {
      return res.status(401).json({ error: "mfa_required_or_invalid" });
    }

    const token = jwtSignHs256({
      payload: { sub: user.id, role: user.role, username: user.username },
      secret: JWT_SECRET,
      expiresInSeconds: 15 * 60,
    });

    await auditAppend({
      actor: { userId: user.id, role: user.role, username: user.username },
      action: "auth.login_success",
      details: {},
    });

    return res.json({ token, role: user.role, userId: user.id });
  });

  // --- Devices (device binding) ---
  app.post("/devices/register", requireAuth, requireRole(["patient"]), async (req, res) => {
    const { deviceId, publicKeyPem } = req.body || {};
    if (!deviceId || !publicKeyPem) return res.status(400).json({ error: "bad_request", message: "deviceId/publicKeyPem required" });
    const patientToken = hmacTokenizePatientId(req.auth.sub);

    const exists = await Device.findOne({ deviceId }).lean();
    if (exists) return res.status(409).json({ error: "device_exists" });

    await Device.create({ deviceId, patientToken, publicKeyPem, status: "active" });
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "device.register",
      details: { deviceId, patientToken },
    });
    return res.status(201).json({ ok: true, deviceId, patientToken });
  });

  // --- Vitals upload ---
  app.post("/vitals/upload", requireAuth, requireRole(["patient"]), async (req, res) => {
    const { deviceId, payload, signatureB64url } = req.body || {};
    if (!deviceId || !payload || !signatureB64url) {
      return res.status(400).json({ error: "bad_request", message: "deviceId/payload/signatureB64url required" });
    }

    const patientToken = hmacTokenizePatientId(req.auth.sub);
    const device = await Device.findOne({ deviceId, patientToken, status: "active" }).lean();
    if (!device) return res.status(403).json({ error: "device_not_bound" });

    const ok = verifyObjectEd25519({ obj: payload, signatureB64url, publicKeyPem: device.publicKeyPem });
    if (!ok) {
      await auditAppend({
        actor: { userId: req.auth.sub, role: req.auth.role },
        action: "vitals.upload_rejected",
        details: { deviceId, reason: "bad_signature" },
      });
      return res.status(400).json({ error: "invalid_payload_signature" });
    }

    const patientKey = await PatientKey.findOne({ patientToken }).lean();
    if (!patientKey) return res.status(500).json({ error: "patient_key_missing", patientToken });

    const encrypted = aes256gcmEncrypt({ plaintext: JSON.stringify(payload), keyB64: patientKey.keyB64 });
    const record = {
      id: randomId("vitals"),
      patientToken,
      deviceId,
      ts: nowIso(),
      encrypted,
    };
    await Vitals.create(record);

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "vitals.upload",
      details: { deviceId, recordId: record.id, patientToken },
    });

    return res.status(201).json({ ok: true, recordId: record.id });
  });

  // --- Vitals read (doctor; ABAC + break-glass) ---
  app.get("/vitals/:patientToken", requireAuth, requireRole(["doctor"]), async (req, res) => {
    const patientToken = req.params.patientToken;
    const breakGlass = req.header("x-break-glass") === "true";

    const assignment = await Assignment.findOne({ doctorId: req.auth.sub }).lean();
    const assigned = assignment?.patientTokens?.includes(patientToken);
    if (!assigned && !breakGlass) return res.status(403).json({ error: "not_assigned_to_patient" });

    const patientKey = await PatientKey.findOne({ patientToken }).lean();
    if (!patientKey) return res.status(404).json({ error: "patient_key_missing" });

    const records = await Vitals.find({ patientToken }).sort({ ts: -1 }).limit(25).lean();
    const decrypted = records.map((r) => ({
      id: r.id,
      ts: r.ts,
      deviceId: r.deviceId,
      payload: JSON.parse(aes256gcmDecrypt({ ...r.encrypted, keyB64: patientKey.keyB64 })),
    }));

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: breakGlass ? "vitals.read_break_glass" : "vitals.read",
      details: { patientToken, returned: decrypted.length },
    });

    return res.json({ patientToken, records: decrypted });
  });

  // --- Prescriptions ---
  app.post("/prescriptions", requireAuth, requireRole(["doctor"]), async (req, res) => {
    const { patientUserId, medicineId, dosage, durationDays } = req.body || {};
    if (!patientUserId || !medicineId || !dosage || !durationDays) {
      return res.status(400).json({ error: "bad_request", message: "patientUserId/medicineId/dosage/durationDays required" });
    }

    const doctor = await User.findOne({ id: req.auth.sub, role: "doctor" }).lean();
    const patient = await User.findOne({ id: patientUserId, role: "patient" }).lean();
    if (!doctor || !doctor.privateKeyPem) return res.status(500).json({ error: "doctor_key_missing" });
    if (!patient) return res.status(404).json({ error: "patient_not_found" });

    const patientToken = hmacTokenizePatientId(patient.id);
    const assignment = await Assignment.findOne({ doctorId: doctor.id }).lean();
    const assigned = assignment?.patientTokens?.includes(patientToken);
    if (!assigned) return res.status(403).json({ error: "not_assigned_to_patient" });

    const issuedAt = nowIso();
    const expiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const nonce = randomId("nonce");

    const rxCore = {
      patientIdToken: patientToken,
      medicineId,
      dosage,
      durationDays: Number(durationDays),
      issuedAt,
      expiry,
      nonce,
    };
    const signatureB64url = signObjectEd25519({ obj: rxCore, privateKeyPem: doctor.privateKeyPem });
    const rx = {
      id: randomId("rx"),
      doctorId: doctor.id,
      ...rxCore,
      signatureB64url,
      status: "active",
    };

    await Prescription.create(rx);
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "rx.create",
      details: { rxId: rx.id, patientToken, medicineId },
    });

    return res.status(201).json(rx);
  });

  app.post("/prescriptions/verify", async (req, res) => {
    const rx = req.body?.prescription;
    if (!rx) return res.status(400).json({ error: "bad_request", message: "prescription required" });

    const doctor = await User.findOne({ id: rx.doctorId, role: "doctor" }).lean();
    if (!doctor) return res.status(400).json({ ok: false, error: "unknown_doctor" });

    const rxCore = {
      patientIdToken: rx.patientIdToken,
      medicineId: rx.medicineId,
      dosage: rx.dosage,
      durationDays: rx.durationDays,
      issuedAt: rx.issuedAt,
      expiry: rx.expiry,
      nonce: rx.nonce,
    };

    const signatureOk = verifyObjectEd25519({ obj: rxCore, signatureB64url: rx.signatureB64url, publicKeyPem: doctor.publicKeyPem });
    const expired = Date.parse(rx.expiry) < Date.now();

    const nonceDoc = await Prescription.findOne({ nonce: rx.nonce }).lean();
    const nonceReused = Boolean(nonceDoc && nonceDoc.id !== rx.id);

    return res.json({ ok: signatureOk && !expired && !nonceReused, checks: { signatureOk, expired, nonceReused } });
  });

  // --- Batches ---
  app.post("/batches", requireAuth, requireRole(["manufacturer"]), async (req, res) => {
    const { batchId, lot, expiry, certificateHash } = req.body || {};
    if (!batchId || !lot || !expiry || !certificateHash) {
      return res.status(400).json({ error: "bad_request", message: "batchId/lot/expiry/certificateHash required" });
    }

    const mfg = await User.findOne({ id: req.auth.sub, role: "manufacturer" }).lean();
    if (!mfg || !mfg.privateKeyPem) return res.status(500).json({ error: "manufacturer_key_missing" });

    const exists = await Batch.findOne({ batchId }).lean();
    if (exists) return res.status(409).json({ error: "batch_exists" });

    const batchCore = {
      batchId,
      manufacturerId: mfg.id,
      lot,
      expiry,
      certificateHash,
      issuedAt: nowIso(),
    };
    const signatureB64url = signObjectEd25519({ obj: batchCore, privateKeyPem: mfg.privateKeyPem });
    const batch = { ...batchCore, signatureB64url, status: "valid" };

    await Batch.create(batch);
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "batch.register",
      details: { batchId, lot },
    });

    return res.status(201).json(batch);
  });

  app.post("/batches/verify", async (req, res) => {
    const batch = req.body?.batch;
    if (!batch) return res.status(400).json({ error: "bad_request", message: "batch required" });

    const mfg = await User.findOne({ id: batch.manufacturerId, role: "manufacturer" }).lean();
    if (!mfg) return res.status(400).json({ ok: false, error: "unknown_manufacturer" });

    const batchCore = {
      batchId: batch.batchId,
      manufacturerId: batch.manufacturerId,
      lot: batch.lot,
      expiry: batch.expiry,
      certificateHash: batch.certificateHash,
      issuedAt: batch.issuedAt,
    };
    const signatureOk = verifyObjectEd25519({ obj: batchCore, signatureB64url: batch.signatureB64url, publicKeyPem: mfg.publicKeyPem });
    const expired = Date.parse(batch.expiry) < Date.now();
    const ok = signatureOk && !expired && batch.status === "valid";
    return res.json({ ok, checks: { signatureOk, expired, status: batch.status } });
  });

  // --- Dispense ---
  app.post("/dispense", requireAuth, requireRole(["pharmacy"]), async (req, res) => {
    const { prescription: rx, batch } = req.body || {};
    if (!rx || !batch) return res.status(400).json({ error: "bad_request", message: "prescription and batch required" });

    const doctor = await User.findOne({ id: rx.doctorId, role: "doctor" }).lean();
    if (!doctor) return res.status(400).json({ error: "rx_unknown_doctor" });
    const rxCore = {
      patientIdToken: rx.patientIdToken,
      medicineId: rx.medicineId,
      dosage: rx.dosage,
      durationDays: rx.durationDays,
      issuedAt: rx.issuedAt,
      expiry: rx.expiry,
      nonce: rx.nonce,
    };
    const rxSigOk = verifyObjectEd25519({ obj: rxCore, signatureB64url: rx.signatureB64url, publicKeyPem: doctor.publicKeyPem });
    const rxExpired = Date.parse(rx.expiry) < Date.now();
    const nonceDoc = await Prescription.findOne({ nonce: rx.nonce }).lean();
    const rxNonceReused = Boolean(nonceDoc && nonceDoc.id !== rx.id);

    const mfg = await User.findOne({ id: batch.manufacturerId, role: "manufacturer" }).lean();
    if (!mfg) return res.status(400).json({ error: "batch_unknown_manufacturer" });
    const batchCore = {
      batchId: batch.batchId,
      manufacturerId: batch.manufacturerId,
      lot: batch.lot,
      expiry: batch.expiry,
      certificateHash: batch.certificateHash,
      issuedAt: batch.issuedAt,
    };
    const batchSigOk = verifyObjectEd25519({ obj: batchCore, signatureB64url: batch.signatureB64url, publicKeyPem: mfg.publicKeyPem });
    const batchExpired = Date.parse(batch.expiry) < Date.now();
    const batchOk = batchSigOk && !batchExpired && batch.status === "valid";

    const allowed = rxSigOk && !rxExpired && !rxNonceReused && batchOk;
    const record = {
      id: randomId("dispense"),
      ts: nowIso(),
      pharmacyId: req.auth.sub,
      allowed,
      rxId: rx.id || null,
      batchId: batch.batchId || null,
      checks: {
        rxSigOk,
        rxExpired,
        rxNonceReused,
        batchSigOk,
        batchExpired,
        batchStatus: batch.status,
      },
    };

    await Dispense.create(record);
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: allowed ? "dispense.allowed" : "dispense.blocked",
      details: { recordId: record.id, rxId: record.rxId, batchId: record.batchId, checks: record.checks },
    });

    return res.status(allowed ? 200 : 409).json(record);
  });

  // --- Audit viewer ---
  app.get("/audit/logs", requireAuth, requireRole(["admin"]), async (req, res) => {
    const entries = await AuditEntry.find({}).sort({ ts: -1 }).limit(200).lean();
    res.json({ count: entries.length, entries });
  });

  // --- Helpful demo data endpoints (read-only, authenticated) ---
  app.get("/demo/whoami", requireAuth, async (req, res) => {
    res.json({ auth: req.auth });
  });

  app.get("/demo/users", requireAuth, async (req, res) => {
    // Minimal exposure for demo UI
    const users = await User.find({}, { _id: 0, id: 1, username: 1, role: 1, status: 1 }).lean();
    res.json({ users });
  });

  // SPA fallback: serve the UI for unknown GET routes (e.g. /home/)
  app.get("*", (req, res, next) => {
    if (req.method !== "GET") return next();
    if (req.path.includes(".")) return next(); // likely a file
    return res.sendFile(path.join(publicDir, "index.html"));
  });

  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`MVP listening on http://localhost:${PORT}`);
  });
}

start().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
