import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import mongoSanitize from "express-mongo-sanitize";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { connectMongo } from "./db/connect.js";
import { User } from "./db/models/User.js";
import { Assignment } from "./db/models/Assignment.js";
import { Device } from "./db/models/Device.js";
import { PatientKey } from "./db/models/PatientKey.js";
import { PatientProfile } from "./db/models/PatientProfile.js";
import { ClinicCode } from "./db/models/ClinicCode.js";
import { RegistrationAttempt } from "./db/models/RegistrationAttempt.js";
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
  sha256Base64url,
  signObjectEd25519,
  verifyObjectEd25519,
} from "./lib/crypto.js";
import { jwtSignHs256, jwtVerifyHs256 } from "./lib/jwt.js";
import { computeAuditHash } from "./lib/audit.js";

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const DEMO_MFA_CODE = process.env.DEMO_MFA_CODE || "123456";
const MFA_REQUIRED_ROLES = new Set(["doctor", "pharmacy", "manufacturer", "admin"]);
const CORS_ORIGIN = process.env.CORS_ORIGIN || "";

function hmacTokenizePatientId(patientUserId) {
  const h = crypto.createHmac("sha256", JWT_SECRET);
  h.update(`patient:${patientUserId}`);
  return h.digest("hex").slice(0, 32);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function safeNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function getClientIp(req) {
  const xf = req.header("x-forwarded-for");
  if (xf) return xf.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "unknown";
}

function buildTrustScore({
  newDevice,
  ipReuseCount,
  failedOtpAttempts,
  clinicCodeUsed,
  geoAnomaly,
}) {
  const impacts = [];
  let score = 60;

  if (clinicCodeUsed) {
    score += 35;
    impacts.push({ factor: "clinic_code_used", impact: +35 });
  }
  if (newDevice) {
    score -= 20;
    impacts.push({ factor: "new_device", impact: -20 });
  }
  if (typeof ipReuseCount === "number" && ipReuseCount > 0) {
    const penalty = Math.min(20, ipReuseCount * 3);
    score -= penalty;
    impacts.push({ factor: "ip_reuse_count", impact: -penalty });
  }
  if (typeof failedOtpAttempts === "number" && failedOtpAttempts > 0) {
    const penalty = Math.min(25, failedOtpAttempts * 5);
    score -= penalty;
    impacts.push({ factor: "failed_otp_attempts", impact: -penalty });
  }
  if (geoAnomaly) {
    score -= 20;
    impacts.push({ factor: "geo_anomaly", impact: -20 });
  }

  score = Math.max(0, Math.min(100, score));
  const top3 = impacts
    .sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact))
    .slice(0, 3)
    .map((x) => `${x.factor}:${x.impact}`);

  return { score, top3 };
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
    PatientProfile.init(),
    ClinicCode.init(),
    RegistrationAttempt.init(),
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

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          "default-src": ["'self'"],
          "script-src": ["'self'"],
          "style-src": ["'self'", "https://unpkg.com", "'unsafe-inline'"],
          "img-src": ["'self'"],
          "connect-src": ["'self'"],
          "object-src": ["'none'"],
          "base-uri": ["'self'"],
          "frame-ancestors": ["'none'"],
          "upgrade-insecure-requests": [],
        },
      },
      crossOriginEmbedderPolicy: false,
    })
  );

  app.use(
    cors(
      CORS_ORIGIN
        ? {
            origin: CORS_ORIGIN.split(",").map((s) => s.trim()).filter(Boolean),
          }
        : {
            origin: false,
          }
    )
  );

  app.use(express.json({ limit: "1mb", type: ["application/json", "application/*+json"] }));
  app.use(mongoSanitize({ replaceWith: "_" }));

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
    if (!isNonEmptyString(username) || !isNonEmptyString(password)) {
      return res.status(400).json({ error: "bad_request", message: "username/password required" });
    }

    const user = await User.findOne({ username }).lean();
    if (!user || user.password !== password || user.status !== "active") {
      await auditAppend({
        actor: { username },
        action: "auth.login_failed",
        details: { reason: "bad_credentials_or_inactive" },
      });
      return res.status(401).json({ error: "invalid_credentials" });
    }

    if (user.role === "patient") {
      const profile = await PatientProfile.findOne({ patientId: user.id }).lean();
      if (!profile || (profile.status !== "ACTIVE" && profile.status !== "VERIFIED")) {
        await auditAppend({
          actor: { userId: user.id, role: user.role, username: user.username },
          action: "auth.login_blocked",
          details: { reason: "patient_not_verified", status: profile?.status || "missing_profile" },
        });
        return res.status(403).json({ error: "patient_not_verified", status: profile?.status || "missing_profile" });
      }
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

  // --- Patient registration + strong verification (clinic code) ---
  app.post("/patients/pre-register", async (req, res) => {
    const { username, password, geo, deviceId } = req.body || {};
    if (!isNonEmptyString(username) || !isNonEmptyString(password)) {
      return res.status(400).json({ error: "bad_request", message: "username/password required" });
    }

    const ip = getClientIp(req);
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const ipReuseCount = await RegistrationAttempt.countDocuments({ ip, ts: { $gte: since } });

    const existing = await User.findOne({ username }).lean();
    if (existing) return res.status(409).json({ error: "username_taken" });

    const patientId = randomId("u_patient");
    await RegistrationAttempt.create({ ip, patientId, ts: new Date() });

    const { score, top3 } = buildTrustScore({
      newDevice: Boolean(deviceId),
      ipReuseCount,
      failedOtpAttempts: 0,
      clinicCodeUsed: false,
      geoAnomaly: false,
    });

    await User.create({
      id: patientId,
      username,
      role: "patient",
      password,
      status: "active",
    });
    await PatientProfile.create({
      patientId,
      status: score >= 80 ? "VERIFIED" : "PENDING",
      trustScore: score,
      trustExplainTop3: top3,
      lastKnownGeo: isNonEmptyString(geo) ? geo : null,
    });

    await auditAppend({
      actor: { username, role: "patient" },
      action: "patient.pre_register",
      details: { patientId, ipReuseCount, trustScore: score, trustExplainTop3: top3, decidedStatus: score >= 80 ? "VERIFIED" : "PENDING" },
    });

    return res.status(201).json({
      patientId,
      status: score >= 80 ? "VERIFIED" : "PENDING",
      trustScore: score,
      trustExplainTop3: top3,
      next: score >= 80 ? "login" : "verify_clinic_code",
    });
  });

  app.get("/patients/me/profile", requireAuth, requireRole(["patient"]), async (req, res) => {
    const profile = await PatientProfile.findOne({ patientId: req.auth.sub }, { _id: 0, __v: 0 }).lean();
    if (!profile) return res.status(404).json({ error: "patient_profile_missing" });
    const patientToken = hmacTokenizePatientId(req.auth.sub);
    res.json({ profile, patientToken });
  });

  // Admin generates 1-time clinic code (expires in 10 minutes by default)
  app.post("/clinic/codes", requireAuth, requireRole(["admin"]), async (req, res) => {
    const { patientId, expiresMinutes } = req.body || {};
    const mins = safeNumber(expiresMinutes) ?? 10;
    const code = crypto.randomBytes(4).toString("hex").toUpperCase(); // 8 chars
    const codeHash = sha256Base64url(`clinic:${code}:${JWT_SECRET}`);
    const expiresAt = new Date(Date.now() + mins * 60 * 1000);
    await ClinicCode.create({
      codeHash,
      patientId: isNonEmptyString(patientId) ? patientId : null,
      expiresAt,
      usedAt: null,
      usedByPatientId: null,
    });
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "clinic.code_issued",
      details: { patientId: isNonEmptyString(patientId) ? patientId : null, expiresAt: expiresAt.toISOString() },
    });
    return res.status(201).json({ code, expiresAt: expiresAt.toISOString(), boundPatientId: isNonEmptyString(patientId) ? patientId : null });
  });

  app.post("/patients/verify-clinic-code", async (req, res) => {
    const { username, patientId, code } = req.body || {};
    if (!isNonEmptyString(code) || (!isNonEmptyString(username) && !isNonEmptyString(patientId))) {
      return res.status(400).json({ error: "bad_request", message: "code + (username or patientId) required" });
    }

    const user = isNonEmptyString(patientId)
      ? await User.findOne({ id: patientId, role: "patient" }).lean()
      : await User.findOne({ username, role: "patient" }).lean();
    if (!user) return res.status(404).json({ error: "patient_not_found" });

    const codeHash = sha256Base64url(`clinic:${code}:${JWT_SECRET}`);
    const record = await ClinicCode.findOne({ codeHash }).lean();
    if (!record) return res.status(401).json({ error: "invalid_code" });
    if (record.usedAt) return res.status(409).json({ error: "code_already_used" });
    if (record.expiresAt.getTime() < Date.now()) return res.status(401).json({ error: "code_expired" });
    if (record.patientId && record.patientId !== user.id) return res.status(403).json({ error: "code_not_for_patient" });

    const profile = await PatientProfile.findOne({ patientId: user.id }).lean();
    if (!profile) return res.status(500).json({ error: "patient_profile_missing" });

    const { score, top3 } = buildTrustScore({
      newDevice: false,
      ipReuseCount: 0,
      failedOtpAttempts: 0,
      clinicCodeUsed: true,
      geoAnomaly: false,
    });

    await Promise.all([
      ClinicCode.updateOne({ codeHash }, { $set: { usedAt: new Date(), usedByPatientId: user.id } }),
      PatientProfile.updateOne(
        { patientId: user.id },
        { $set: { status: "VERIFIED", trustScore: Math.max(profile.trustScore, score), trustExplainTop3: top3 } }
      ),
    ]);

    await auditAppend({
      actor: { patientId: user.id, username: user.username, role: "patient" },
      action: "patient.verified",
      details: { method: "clinic_code", trustScore: Math.max(profile.trustScore, score), trustExplainTop3: top3 },
    });

    return res.json({ ok: true, patientId: user.id, status: "VERIFIED", trustScore: Math.max(profile.trustScore, score), trustExplainTop3: top3, next: "login" });
  });

  // After verification, patient can provision DID + data key
  app.post("/patients/issue-did", requireAuth, requireRole(["patient"]), async (req, res) => {
    const profile = await PatientProfile.findOne({ patientId: req.auth.sub }).lean();
    if (!profile) return res.status(500).json({ error: "patient_profile_missing" });
    if (profile.did) return res.json({ did: profile.did });
    const did = `did:genzipher:${randomId("p")}`;
    await PatientProfile.updateOne({ patientId: req.auth.sub }, { $set: { did } });
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "patient.did_issued",
      details: { did },
    });
    return res.status(201).json({ did });
  });

  app.post("/patients/provision-data-key", requireAuth, requireRole(["patient"]), async (req, res) => {
    const patientToken = hmacTokenizePatientId(req.auth.sub);
    const existing = await PatientKey.findOne({ patientToken }).lean();
    if (existing) return res.json({ ok: true, patientToken });
    const keyB64 = crypto.randomBytes(32).toString("base64");
    await PatientKey.create({ patientToken, keyB64 });
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "patient.data_key_provisioned",
      details: { patientToken },
    });
    return res.status(201).json({ ok: true, patientToken });
  });

  // --- Devices (device binding) ---
  const bindDeviceHandler = async (req, res) => {
    const { deviceId, publicKeyPem, fingerprintHash } = req.body || {};
    if (!isNonEmptyString(deviceId) || !isNonEmptyString(publicKeyPem)) {
      return res.status(400).json({ error: "bad_request", message: "deviceId/publicKeyPem required" });
    }
    const patientToken = hmacTokenizePatientId(req.auth.sub);

    const exists = await Device.findOne({ deviceId }).lean();
    if (exists) return res.status(409).json({ error: "device_exists" });

    const nonce = randomId("chal");
    await Device.create({
      deviceId,
      patientToken,
      publicKeyPem,
      fingerprintHash: isNonEmptyString(fingerprintHash) ? fingerprintHash : null,
      status: "pending",
      challengeNonce: nonce,
      challengeIssuedAt: new Date(),
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
      riskLevel: "low",
    });
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "patient.device_bind_requested",
      details: { deviceId, patientToken },
    });
    return res.status(201).json({
      ok: true,
      deviceId,
      patientToken,
      challenge: { deviceId, nonce },
      next: "auth/device-verify",
    });
  };

  app.post("/patients/bind-device", requireAuth, requireRole(["patient"]), bindDeviceHandler);
  app.post("/devices/register", requireAuth, requireRole(["patient"]), bindDeviceHandler);

  app.post("/auth/device-challenge", requireAuth, requireRole(["patient"]), async (req, res) => {
    const { deviceId } = req.body || {};
    if (!isNonEmptyString(deviceId)) return res.status(400).json({ error: "bad_request", message: "deviceId required" });
    const patientToken = hmacTokenizePatientId(req.auth.sub);
    const device = await Device.findOne({ deviceId, patientToken }).lean();
    if (!device) return res.status(404).json({ error: "device_not_found" });
    if (device.status === "active") return res.json({ ok: true, deviceId, status: "active" });
    const nonce = randomId("chal");
    await Device.updateOne({ deviceId }, { $set: { challengeNonce: nonce, challengeIssuedAt: new Date() } });
    return res.json({ ok: true, challenge: { deviceId, nonce } });
  });

  app.post("/auth/device-verify", requireAuth, requireRole(["patient"]), async (req, res) => {
    const { deviceId, signatureB64url } = req.body || {};
    if (!isNonEmptyString(deviceId) || !isNonEmptyString(signatureB64url)) {
      return res.status(400).json({ error: "bad_request", message: "deviceId/signatureB64url required" });
    }
    const patientToken = hmacTokenizePatientId(req.auth.sub);
    const device = await Device.findOne({ deviceId, patientToken }).lean();
    if (!device) return res.status(404).json({ error: "device_not_found" });
    if (device.status === "blocked") return res.status(403).json({ error: "device_blocked" });
    if (!device.challengeNonce) return res.status(409).json({ error: "no_active_challenge" });

    const challengePayload = { deviceId, nonce: device.challengeNonce };
    const ok = verifyObjectEd25519({
      obj: challengePayload,
      signatureB64url,
      publicKeyPem: device.publicKeyPem,
    });
    if (!ok) {
      await auditAppend({
        actor: { userId: req.auth.sub, role: req.auth.role },
        action: "patient.device_bind_failed",
        details: { deviceId, reason: "bad_signature" },
      });
      return res.status(401).json({ error: "invalid_device_signature" });
    }

    await Device.updateOne(
      { deviceId },
      { $set: { status: "active", lastSeenAt: new Date() }, $unset: { challengeNonce: 1, challengeIssuedAt: 1 } }
    );
    await PatientProfile.updateOne({ patientId: req.auth.sub }, { $set: { status: "ACTIVE" } });

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "patient.device_bound",
      details: { deviceId },
    });
    return res.json({ ok: true, deviceId, status: "active", patientStatus: "ACTIVE" });
  });

  // --- Vitals upload ---
  app.post("/vitals/upload", requireAuth, requireRole(["patient"]), async (req, res) => {
    const { deviceId, payload, signatureB64url } = req.body || {};
    if (!isNonEmptyString(deviceId) || !payload || !isNonEmptyString(signatureB64url)) {
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
    const duration = safeNumber(durationDays);
    if (!isNonEmptyString(patientUserId) || !isNonEmptyString(medicineId) || !isNonEmptyString(dosage) || duration === null) {
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
      durationDays: duration,
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
    if (!isNonEmptyString(batchId) || !isNonEmptyString(lot) || !isNonEmptyString(expiry) || !isNonEmptyString(certificateHash)) {
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
    const { patientId, patientToken, action } = req.query || {};
    const filter = {};
    if (isNonEmptyString(action)) filter.action = String(action);
    if (isNonEmptyString(patientId)) {
      // best-effort filter by patient token inside audit details
      const token = hmacTokenizePatientId(String(patientId));
      filter.$or = [
        { "actor.userId": String(patientId) },
        { "actor.patientId": String(patientId) },
        { "details.patientToken": token },
      ];
    } else if (isNonEmptyString(patientToken)) {
      filter["details.patientToken"] = String(patientToken);
    }

    const entries = await AuditEntry.find(filter).sort({ ts: -1 }).limit(200).lean();
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
