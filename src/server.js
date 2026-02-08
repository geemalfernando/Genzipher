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
import { OtpRequest } from "./db/models/OtpRequest.js";
import { TrustedDevice } from "./db/models/TrustedDevice.js";
import { UserLoginDevice } from "./db/models/UserLoginDevice.js";
import { MagicLinkRequest } from "./db/models/MagicLinkRequest.js";
import { StaffSession } from "./db/models/StaffSession.js";
import { Biometric } from "./db/models/Biometric.js";
import { WebAuthnChallenge } from "./db/models/WebAuthnChallenge.js";
import { Medicine } from "./db/models/Medicine.js";
import { Stock } from "./db/models/Stock.js";
import { QualityVerification } from "./db/models/QualityVerification.js";
import { Appointment } from "./db/models/Appointment.js";
import { Prescription } from "./db/models/Prescription.js";
import { Batch } from "./db/models/Batch.js";
import { Dispense } from "./db/models/Dispense.js";
import { Vitals } from "./db/models/Vitals.js";
import { AuditMeta } from "./db/models/AuditMeta.js";
import { AuditEntry } from "./db/models/AuditEntry.js";
import { AccountRequest } from "./db/models/AccountRequest.js";

import {
  aes256gcmDecrypt,
  aes256gcmEncrypt,
  nowIso,
  randomId,
  sha256Base64url,
  signObjectEd25519,
  verifyObjectEd25519,
  verifyObjectEs256,
} from "./lib/crypto.js";
import { jwtSignHs256, jwtVerifyHs256 } from "./lib/jwt.js";
import { computeAuditHash } from "./lib/audit.js";
import {
  isSmtpEnabled,
  sendClinicCodeEmail,
  sendMagicLinkEmail,
  sendOtpEmail,
  sendAccountActivatedEmail,
  sendAccountDeletedEmail,
  sendPrescriptionIssuedEmail,
  verifySmtpConnection,
} from "./lib/mailer.js";

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const DEMO_MFA_CODE = process.env.DEMO_MFA_CODE || "123456";
// Signup gate for pharmacy staff (NOT MFA). Defaults to DEMO_MFA_CODE for backward compatibility.
const PHARMACIST_REGISTRATION_CODE = process.env.PHARMACIST_REGISTRATION_CODE || DEMO_MFA_CODE;
const MFA_REQUIRED_ROLES = new Set(["doctor", "pharmacy", "manufacturer", "admin"]);
const CORS_ORIGIN = (process.env.CORS_ORIGIN || process.env.PUBLIC_BASE_URL || "").trim();
const DEVICE_STEP_UP_ROLES = new Set(
  (process.env.DEVICE_STEP_UP_ROLES || "patient,doctor")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
);
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`).trim();
const CSRF_ENABLED = String(process.env.CSRF_ENABLED || "true").toLowerCase() !== "false";
const RX_EMAIL_NOTIFICATIONS = ["1", "true", "yes", "on"].includes(
  String(process.env.RX_EMAIL_NOTIFICATIONS || "").trim().toLowerCase()
);

function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function hmacTokenizePatientId(patientUserId) {
  const h = crypto.createHmac("sha256", JWT_SECRET);
  h.update(`patient:${patientUserId}`);
  return h.digest("hex").slice(0, 32);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function looksLikeEmail(value) {
  if (!isNonEmptyString(value)) return false;
  const s = value.trim();
  if (s.length > 254) return false;
  // MVP-grade validation (avoid rejecting valid but uncommon addresses).
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

function looksLikeUsername(value) {
  if (!isNonEmptyString(value)) return false;
  const s = value.trim();
  if (s.length < 3 || s.length > 32) return false;
  return /^[a-zA-Z0-9_.-]+$/.test(s);
}

function looksLikePassword(value) {
  if (!isNonEmptyString(value)) return false;
  const s = String(value);
  if (s.length < 8 || s.length > 128) return false;
  return true;
}

function hashPasswordScrypt(password) {
  const salt = crypto.randomBytes(16);
  const N = 16384;
  const r = 8;
  const p = 1;
  const keyLen = 32;
  const derived = crypto.scryptSync(String(password), salt, keyLen, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString("base64url")}$${derived.toString("base64url")}`;
}

function verifyPasswordScrypt(stored, password) {
  if (!isNonEmptyString(stored)) return false;
  const s = String(stored);
  if (!s.startsWith("scrypt$")) return false;
  const parts = s.split("$");
  // Format: scrypt$N$r$p$saltB64u$hashB64u
  if (parts.length !== 6) return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const saltB64u = parts[4];
  const hashB64u = parts[5];
  const salt = Buffer.from(saltB64u, "base64url");
  const expected = Buffer.from(hashB64u, "base64url");
  const derived = crypto.scryptSync(String(password), salt, expected.length, { N, r, p });
  return crypto.timingSafeEqual(expected, derived);
}

function verifyPassword(stored, password) {
  // Backward compatible: support legacy plaintext passwords (demo seeds),
  // but prefer scrypt-hashed values.
  if (verifyPasswordScrypt(stored, password)) return true;
  return String(stored || "") === String(password || "");
}

function computeRpId({ req }) {
  // WebAuthn RP ID must be a hostname (no scheme/path).
  // Prefer PUBLIC_BASE_URL when it's a valid absolute URL; otherwise fall back to request host.
  try {
    const u = new URL(PUBLIC_BASE_URL);
    if (u.hostname) return u.hostname;
  } catch {
    // ignore
  }
  return req?.hostname || req?.get?.("host") || "localhost";
}

function bytesFromUnknown(value) {
  // Accept several formats commonly produced by WebAuthn client code.
  // - Array of numbers (Uint8Array serialized via Array.from)
  // - base64url string
  // - ArrayBuffer / Uint8Array (should not happen after JSON, but handle anyway)
  if (Array.isArray(value)) {
    return Buffer.from(Uint8Array.from(value));
  }
  if (typeof value === "string" && value.trim()) {
    try {
      return Buffer.from(value.trim(), "base64url");
    } catch {
      return null;
    }
  }
  if (value && typeof value === "object") {
    // ArrayBuffer
    if (value instanceof ArrayBuffer) return Buffer.from(new Uint8Array(value));
    // Uint8Array
    if (value instanceof Uint8Array) return Buffer.from(value);
  }
  return null;
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  if (value && typeof value === "object" && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function computeIntegrityHash({ prefix, obj }) {
  return sha256Base64url(`${prefix}:${stableStringify(obj)}:${JWT_SECRET}`);
}

function looksLikeIsoDate(value) {
  if (!isNonEmptyString(value)) return false;
  const s = String(value).trim();
  return /^\d{4}-\d{2}-\d{2}$/.test(s);
}

function looksLikeTimeHHMM(value) {
  if (!isNonEmptyString(value)) return false;
  const s = String(value).trim();
  if (!/^\d{2}:\d{2}$/.test(s)) return false;
  const [hh, mm] = s.split(":").map((x) => Number(x));
  return hh >= 0 && hh <= 23 && mm >= 0 && mm <= 59;
}

function safeNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function clampInt(value, { min, max, fallback }) {
  const n = safeNumber(value);
  if (n === null) return fallback;
  const i = Math.trunc(n);
  if (i < min) return min;
  if (i > max) return max;
  return i;
}

function floorToBucketMs(ms, bucketMs) {
  if (!Number.isFinite(ms) || !Number.isFinite(bucketMs) || bucketMs <= 0) return null;
  return Math.floor(ms / bucketMs) * bucketMs;
}

function getClientIp(req) {
  const xf = req.header("x-forwarded-for");
  if (xf) return xf.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "unknown";
}

function normalizeOrigin(value) {
  if (!isNonEmptyString(value)) return "";
  return String(value).trim().replace(/\/+$/, "");
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
  if (!result.ok) {
    if (result.error === "expired") return res.status(401).json({ error: "token_expired" });
    return res.status(401).json({ error: "invalid_token", detail: result.error });
  }
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
    AccountRequest.init(),
    Assignment.init(),
    Device.init(),
    PatientKey.init(),
    PatientProfile.init(),
    ClinicCode.init(),
    RegistrationAttempt.init(),
    OtpRequest.init(),
    TrustedDevice.init(),
    UserLoginDevice.init(),
    MagicLinkRequest.init(),
    StaffSession.init(),
    Biometric.init(),
    WebAuthnChallenge.init(),
    Medicine.init(),
    Stock.init(),
    QualityVerification.init(),
    Appointment.init(),
    Prescription.init(),
    Batch.init(),
    Dispense.init(),
    Vitals.init(),
    AuditMeta.init(),
    AuditEntry.init(),
  ]);
}

function generateOtp6() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

function hashOtp(otp) {
  return sha256Base64url(`otp:${otp}:${JWT_SECRET}`);
}

async function verifyOtpRequest({ otpRequestId, otp, expectedPurpose }) {
  const request = await OtpRequest.findOne({ id: otpRequestId }).lean();
  if (!request) return { ok: false, status: 404, body: { error: "otp_request_not_found" } };
  if (expectedPurpose && request.purpose !== expectedPurpose) {
    return { ok: false, status: 400, body: { error: "otp_wrong_purpose", purpose: request.purpose } };
  }
  if (request.used) return { ok: false, status: 409, body: { error: "otp_already_used" } };
  if (request.expiresAt.getTime() < Date.now()) return { ok: false, status: 401, body: { error: "otp_expired" } };
  const maxAttempts = expectedPurpose === "RESET" ? 3 : 5;
  if (request.attempts >= maxAttempts) {
    return { ok: false, status: 423, body: { error: "otp_locked", maxAttempts } };
  }

  const matches = hashOtp(otp) === request.otpHash;
  if (!matches) {
    const nextAttempts = (request.attempts || 0) + 1;
    await OtpRequest.updateOne({ id: otpRequestId }, { $inc: { attempts: 1 } });
    await auditAppend({
      actor: { userId: request.userId },
      action: "auth.otp_verify_failed",
      details: { otpRequestId, purpose: request.purpose },
    });
    if (nextAttempts === 3) {
      await auditAppend({
        actor: { userId: request.userId },
        action: "anomaly.otp_failed_multiple",
        details: { otpRequestId, purpose: request.purpose, attempts: nextAttempts },
      });
    }
    const remainingAttempts = Math.max(0, maxAttempts - nextAttempts);
    const status = remainingAttempts === 0 ? 423 : 401;
    return { ok: false, status, body: { error: remainingAttempts === 0 ? "otp_locked" : "invalid_otp", remainingAttempts, maxAttempts } };
  }

  await OtpRequest.updateOne({ id: otpRequestId }, { $set: { used: true }, $inc: { attempts: 1 } });
  return { ok: true, request };
}

function hashRememberToken(token) {
  return sha256Base64url(`remember:${token}:${JWT_SECRET}`);
}

function hashMagicToken(token) {
  return sha256Base64url(`magic:${token}:${JWT_SECRET}`);
}

function looksLikeDeviceId(value) {
  if (!isNonEmptyString(value)) return false;
  const s = value.trim();
  if (s.length < 8 || s.length > 128) return false;
  return /^[a-zA-Z0-9_.:-]+$/.test(s);
}

function isMongoDuplicateKeyError(err) {
  const code = err?.code;
  const name = err?.name;
  return code === 11000 || name === "MongoServerError" || name === "MongoBulkWriteError";
}

function getRequestDeviceId(req) {
  const header = req.header("x-gz-device-id");
  const body = req.body?.deviceId;
  const raw = isNonEmptyString(header) ? header : body;
  const normalized = isNonEmptyString(raw) ? String(raw).trim() : "";
  return looksLikeDeviceId(normalized) ? normalized : null;
}

async function upsertStaffSession({ user, req, deviceId }) {
  const staffRoles = new Set(["pharmacy", "doctor", "admin", "manufacturer"]);
  if (!user || !staffRoles.has(user.role)) return null;
  const did = looksLikeDeviceId(deviceId) ? String(deviceId).trim() : null;
  if (!did) return null;
  const now = new Date();
  const ip = String(getClientIp(req)).slice(0, 128);
  const ua = isNonEmptyString(req.header("user-agent")) ? String(req.header("user-agent")).slice(0, 512) : null;

  await StaffSession.updateOne(
    { userId: user.id, role: user.role, deviceId: did, isActive: true },
    {
      $setOnInsert: { id: randomId("staffsess"), userId: user.id, role: user.role, deviceId: did, firstSeenAt: now },
      $set: { lastSeenAt: now, ipAddress: ip, userAgent: ua, isActive: true },
    },
    { upsert: true }
  );
  return StaffSession.findOne({ userId: user.id, role: user.role, deviceId: did, isActive: true }).lean();
}

async function getActiveStaffSession({ userId, deviceId }) {
  if (!looksLikeDeviceId(deviceId)) return null;
  return StaffSession.findOne({ userId, deviceId: String(deviceId).trim(), isActive: true }).lean();
}

function requirePharmacyBiometric(req, res, next) {
  if (!req.auth || req.auth.role !== "pharmacy") return next();
  const did = getRequestDeviceId(req);
  if (!did) return res.status(400).json({ error: "missing_device_id" });
  return StaffSession.findOne({ userId: req.auth.sub, role: "pharmacy", deviceId: did, isActive: true })
    .lean()
    .then((sess) => {
      if (!sess || !sess.biometricVerified) {
        return res.status(403).json({ error: "biometric_verification_required" });
      }
      return next();
    })
    .catch(next);
}

function requireCsrf(req, res, next) {
  if (!CSRF_ENABLED) return next();
  // Only enforce for browser-like state-changing requests.
  const method = String(req.method || "GET").toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return next();
  if (!req.auth) return res.status(401).json({ error: "missing_bearer_token" });

  const token = req.header("x-gz-csrf");
  if (!isNonEmptyString(token)) return res.status(403).json({ error: "csrf_missing" });
  const verified = jwtVerifyHs256({ token: String(token).trim(), secret: JWT_SECRET });
  if (!verified.ok) return res.status(403).json({ error: "csrf_invalid" });
  const payload = verified.payload || {};
  if (payload.purpose !== "CSRF" || payload.sub !== req.auth.sub) return res.status(403).json({ error: "csrf_invalid" });
  const did = getRequestDeviceId(req);
  if (payload.deviceId && did && String(payload.deviceId) !== String(did)) return res.status(403).json({ error: "csrf_device_mismatch" });
  return next();
}

async function recordLoginSuccess({ userId, deviceId, ip = null, userAgent = null }) {
  if (!looksLikeDeviceId(deviceId)) return;
  const now = new Date();
  const ipNorm = isNonEmptyString(ip) ? String(ip).slice(0, 128) : null;
  const uaNorm = isNonEmptyString(userAgent) ? String(userAgent).slice(0, 512) : null;
  await Promise.all([
    User.updateOne(
      { id: userId },
      { $set: { lastLoginAt: now, lastLoginDeviceId: String(deviceId).trim() } }
    ),
    UserLoginDevice.updateOne(
      { userId, deviceId: String(deviceId).trim() },
      {
        $setOnInsert: {
          id: randomId("ulogdev"),
          userId,
          deviceId: String(deviceId).trim(),
          firstSeenAt: now,
          firstIp: ipNorm,
        },
        $set: { lastSeenAt: now, blockedAt: null, lastIp: ipNorm, lastUserAgent: uaNorm },
      },
      { upsert: true }
    ),
  ]);
}

async function issueOtpRequest({ user, purpose, context = null }) {
  const otp = generateOtp6();
  const otpRequestId = randomId("otp");
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  const sentTo = user.email || `${user.username}@demo.local`;

  await OtpRequest.create({
    id: otpRequestId,
    userId: user.id,
    purpose,
    otpHash: hashOtp(otp),
    expiresAt,
    attempts: 0,
    used: false,
    sentTo,
    lastSentAt: new Date(),
    context,
  });

  if (isSmtpEnabled()) {
    if (!user.email || user.email.endsWith("@demo.local") || !looksLikeEmail(user.email)) {
      throw new Error("mfa_email_missing");
    }
    await sendOtpEmail({ to: user.email, otp, expiresAtIso: expiresAt.toISOString() });
    // eslint-disable-next-line no-console
    console.log(`[OTP] SENT user=${user.username} sentTo=${user.email} expiresAt=${expiresAt.toISOString()}`);
  } else {
    // Fallback delivery for local demo.
    // eslint-disable-next-line no-console
    console.log(`[OTP] user=${user.username} sentTo=${sentTo} otp=${otp} expiresAt=${expiresAt.toISOString()}`);
  }

  return {
    otpRequestId,
    expiresAt: expiresAt.toISOString(),
    sentTo,
    delivery: isSmtpEnabled() ? "email" : "console",
  };
}

async function issueLoginOtp({ user }) {
  return issueOtpRequest({ user, purpose: "LOGIN" });
}

async function buildApp() {
  await connectMongo();
  await ensureIndexes();

  const app = express();
  app.disable("x-powered-by");

  const isProdEnv =
    String(process.env.NODE_ENV || "").toLowerCase() === "production" ||
    String(process.env.VERCEL || "").toLowerCase() === "1";

  const allowedOriginsFromEnv = CORS_ORIGIN.split(",").map(normalizeOrigin).filter(Boolean);
  const defaultDevOrigins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
  ].map(normalizeOrigin);

  const allowedOrigins =
    allowedOriginsFromEnv.length > 0 ? allowedOriginsFromEnv : isProdEnv ? [] : defaultDevOrigins;

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          "default-src": ["'self'"],
          "script-src": ["'self'"],
          "style-src": ["'self'", "https://unpkg.com", "'unsafe-inline'"],
          "img-src": ["'self'", "data:"],
          // Allow unpkg for CSS sourcemaps and related fetches in the hosted static UI.
          "connect-src": ["'self'", "https://unpkg.com"],
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
    cors({
      origin: (origin, cb) => {
        // Allow same-origin / non-browser clients
        if (!origin) return cb(null, true);

        if (allowedOrigins.length === 0) return cb(null, false);
        if (allowedOrigins.includes(normalizeOrigin(origin))) return cb(null, true);
        return cb(null, false);
      },
      methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"],
      allowedHeaders: ["content-type", "authorization", "x-gz-device-id", "x-gz-csrf"],
      optionsSuccessStatus: 204,
    })
  );

  // Ensure CORS preflights are handled for all routes
  app.options(
    "*",
    cors({
      origin: (origin, cb) => {
        if (!origin) return cb(null, true);
        if (allowedOrigins.length === 0) return cb(null, false);
        if (allowedOrigins.includes(normalizeOrigin(origin))) return cb(null, true);
        return cb(null, false);
      },
      methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"],
      allowedHeaders: ["content-type", "authorization", "x-gz-device-id", "x-gz-csrf"],
      optionsSuccessStatus: 204,
    })
  );

  app.use(express.json({ limit: "1mb", type: ["application/json", "application/*+json"] }));
  app.use(mongoSanitize({ replaceWith: "_" }));

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const publicDir = path.resolve(__dirname, "../public");

  // Avoid noisy 404s for default browser icon requests in hosted environments.
  app.get(["/favicon.ico", "/favicon.png"], (req, res) => res.status(204).end());

  // If the backend is hosted separately from the frontend, redirect browser navigations
  // to the configured public URL (e.g. Firebase Hosting). Keep API routes unaffected.
  // In local dev, redirect to the Vite frontend (http://localhost:3001) so port 3000 behaves as "API only".
  const apiPrefixes = [
    "/health",
    "/auth",
    "/patients",
    "/clinic",
    "/admin",
    "/audit",
    "/analytics",
    "/demo",
    "/prescriptions",
    "/batches",
    "/dispense",
    "/pharmacist",
    "/biometric",
    "/pharmacy",
    "/appointments",
    "/doctor",
    "/vitals",
  ];
  app.use((req, res, next) => {
    const method = String(req.method || "").toUpperCase();
    if (method !== "GET" && method !== "HEAD") return next();

    const accept = req.header("accept") || "";
    if (!accept.includes("text/html")) return next();

    const pathOnly = req.path || "/";
    const isApi =
      apiPrefixes.includes(pathOnly) || apiPrefixes.some((p) => pathOnly.startsWith(`${p}/`));
    if (isApi) return next();

    const current = normalizeOrigin(`${req.protocol}://${req.get("host")}`);
    const pub = normalizeOrigin(PUBLIC_BASE_URL);
    const devFrontend = normalizeOrigin((process.env.DEV_FRONTEND_URL || "http://localhost:3001").trim());

    const targetBase = pub || (!isProdEnv ? devFrontend : "");
    if (!targetBase || !current || targetBase === current) return next();

    const original = String(req.originalUrl || "/");
    const target = `${targetBase}${original.startsWith("/") ? original : `/${original}`}`;
    return res.redirect(302, target);
  });

  app.use("/", express.static(publicDir));

  // Friendly aliases / SPA-style paths
  app.get(["/home", "/home/"], (req, res) => res.redirect(302, "/"));

  // Serve pharmacist signup page with route-scoped CSP allowing inline scripts (page contains inline JS).
  app.get("/pharmacist/signup", (req, res) => {
    res.setHeader(
      "Content-Security-Policy",
      [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' https://unpkg.com 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self' https://unpkg.com",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
      ].join("; ")
    );
    return res.sendFile(path.join(publicDir, "pharmacist-signup.html"));
  });

  app.get("/health", asyncRoute(async (req, res) => {
    res.json({ ok: true, ts: nowIso() });
  }));

  // --- Auth ---
  app.get("/auth/csrf", requireAuth, asyncRoute(async (req, res) => {
    const did = getRequestDeviceId(req);
    const token = jwtSignHs256({
      payload: { sub: req.auth.sub, purpose: "CSRF", deviceId: did || null },
      secret: JWT_SECRET,
      expiresInSeconds: 60 * 60,
    });
    res.json({ ok: true, csrfToken: token, expiresInSeconds: 60 * 60 });
  }));

  app.post("/auth/login", asyncRoute(async (req, res) => {
    const { username, email, identifier, password, mfaCode } = req.body || {};
    const deviceId = req.body?.deviceId;
    const rememberToken = req.body?.rememberToken;
    const idRaw = identifier || email || username;
    const id = isNonEmptyString(idRaw) ? String(idRaw).trim() : "";
    const pwd = isNonEmptyString(password) ? String(password) : "";
    const mfa = isNonEmptyString(mfaCode) ? String(mfaCode).trim() : "";
    if (!isNonEmptyString(id) || !isNonEmptyString(pwd)) {
      return res.status(400).json({ error: "bad_request", message: "identifier + password required" });
    }

    const user = await User.findOne({
      $or: [{ username: id }, { email: id }],
    }).lean();
    if (!user || !verifyPassword(user.password, pwd)) {
      await auditAppend({
        actor: { identifier: id },
        action: "auth.login_failed",
        details: { reason: "bad_credentials_or_inactive" },
      });
      return res.status(401).json({ error: "invalid_credentials" });
    }
    if (user.status !== "active") {
      const err =
        user.status === "pending"
          ? "account_pending_admin_approval"
          : user.status === "blocked"
            ? "account_blocked"
            : user.status === "deleted"
              ? "account_deleted"
              : "account_inactive";
      await auditAppend({
        actor: { userId: user.id, role: user.role, username: user.username },
        action: "auth.login_blocked",
        details: { reason: err, status: user.status },
      });
      return res.status(403).json({ error: err });
    }

    // Opportunistic upgrade: if legacy plaintext password was used, replace with scrypt hash.
    if (isNonEmptyString(user.password) && !String(user.password).startsWith("scrypt$")) {
      try {
        await User.updateOne({ id: user.id }, { $set: { password: hashPasswordScrypt(pwd) } });
        await auditAppend({
          actor: { userId: user.id, role: user.role, username: user.username },
          action: "auth.password_upgraded",
          details: {},
        });
      } catch {
        // ignore upgrade failures (do not block login)
      }
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

    // Step-up OTP for new device (patient/doctor by default)
    if (looksLikeDeviceId(deviceId) && DEVICE_STEP_UP_ROLES.has(user.role)) {
      const normalizedDeviceId = String(deviceId).trim();
      const ip = getClientIp(req);
      const userAgent = req.header("user-agent") || null;
      const existing = await UserLoginDevice.findOne({ userId: user.id, deviceId: normalizedDeviceId }).lean();
      if (existing?.blockedAt) return res.status(403).json({ error: "device_blocked" });

      if (!existing || !existing.verifiedAt) {
        // Bootstrap rule: allow the *first* verified device without step-up,
        // then require step-up when a *new* device appears later.
        const anyVerified = await UserLoginDevice.findOne({ userId: user.id, verifiedAt: { $ne: null } }).lean();
        if (!anyVerified) {
          const now = new Date();
          await UserLoginDevice.updateOne(
            { userId: user.id, deviceId: normalizedDeviceId },
            {
              $setOnInsert: {
                id: randomId("ulogdev"),
                userId: user.id,
                deviceId: normalizedDeviceId,
                firstSeenAt: now,
                firstIp: isNonEmptyString(ip) ? String(ip).slice(0, 128) : null,
              },
              $set: {
                lastSeenAt: now,
                verifiedAt: now,
                blockedAt: null,
                lastIp: isNonEmptyString(ip) ? String(ip).slice(0, 128) : null,
                lastUserAgent: isNonEmptyString(userAgent) ? String(userAgent).slice(0, 512) : null,
              },
            },
            { upsert: true }
          );
          await auditAppend({
            actor: { userId: user.id, role: user.role, username: user.username },
            action: "auth.first_device_auto_verified",
            details: { deviceId: normalizedDeviceId },
          });
        } else if (isSmtpEnabled()) {
          if (!looksLikeEmail(user.email) || String(user.email).endsWith("@demo.local")) {
            return res.status(400).json({
              error: "mfa_email_missing",
              message: "Set a real email for this user to verify login from a new device (SMTP is enabled).",
            });
          }

          const rawToken = crypto.randomBytes(32).toString("base64url");
          const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
          const id = randomId("ml");
          await MagicLinkRequest.create({
            id,
            userId: user.id,
            purpose: "NEW_DEVICE",
            tokenHash: hashMagicToken(rawToken),
            expiresAt,
            usedAt: null,
            sentTo: user.email,
            context: { deviceId: normalizedDeviceId },
          });
          const verifyUrl = `${PUBLIC_BASE_URL}/?mlt=${encodeURIComponent(rawToken)}`;
          await sendMagicLinkEmail({ to: user.email, verifyUrl, expiresAtIso: expiresAt.toISOString() });

          await auditAppend({
            actor: { userId: user.id, role: user.role, username: user.username },
            action: "auth.new_device_magic_link_sent",
            details: { deviceId: normalizedDeviceId, expiresAt: expiresAt.toISOString(), sentTo: user.email },
          });

          return res.status(200).json({
            mfaRequired: true,
            method: "EMAIL_LINK",
            userId: user.id,
            username: user.username,
            expiresAt: expiresAt.toISOString(),
            sentTo: user.email,
            reason: "NEW_DEVICE",
          });
        } else {

          // No SMTP configured: fall back to OTP (console delivery)
          const otpInfo = await issueOtpRequest({
            user,
            purpose: "STEP_UP",
            context: { reason: "NEW_DEVICE", deviceId: normalizedDeviceId },
          });
          await auditAppend({
            actor: { userId: user.id, role: user.role, username: user.username },
            action: "auth.step_up_new_device_otp_issued",
            details: { otpRequestId: otpInfo.otpRequestId, deviceId: normalizedDeviceId, delivery: otpInfo.delivery },
          });
          return res.status(200).json({
            mfaRequired: true,
            method: "EMAIL_OTP",
            otpRequestId: otpInfo.otpRequestId,
            userId: user.id,
            username: user.username,
            expiresAt: otpInfo.expiresAt,
            sentTo: otpInfo.sentTo,
            delivery: otpInfo.delivery,
            reason: "NEW_DEVICE",
          });
        }
      }

      // Known verified device: update last seen
      if (existing?.verifiedAt) {
        await UserLoginDevice.updateOne(
          { id: existing.id },
          {
            $set: {
              lastSeenAt: new Date(),
              lastIp: isNonEmptyString(ip) ? String(ip).slice(0, 128) : null,
              lastUserAgent: isNonEmptyString(userAgent) ? String(userAgent).slice(0, 512) : null,
            },
          }
        );
      }
    }

    if (user.mfaEnabled && user.mfaMethod === "EMAIL_OTP") {
      // If the user previously trusted this browser/device, allow password-only login.
      if (looksLikeDeviceId(deviceId) && isNonEmptyString(rememberToken)) {
        const trusted = await TrustedDevice.findOne({
          userId: user.id,
          deviceId: String(deviceId).trim(),
          revokedAt: null,
        }).lean();
        if (trusted && trusted.expiresAt.getTime() > Date.now() && trusted.tokenHash === hashRememberToken(String(rememberToken).trim())) {
          await TrustedDevice.updateOne(
            { id: trusted.id },
            { $set: { lastUsedAt: new Date() } }
          );
          const token = jwtSignHs256({
            payload: { sub: user.id, role: user.role, username: user.username },
            secret: JWT_SECRET,
            expiresInSeconds: 15 * 60,
          });
          await recordLoginSuccess({
            userId: user.id,
            deviceId: String(deviceId).trim(),
            ip: getClientIp(req),
            userAgent: req.header("user-agent") || null,
          });
          await upsertStaffSession({ user, req, deviceId: String(deviceId).trim() });
          await auditAppend({
            actor: { userId: user.id, role: user.role, username: user.username },
            action: "auth.mfa_bypassed_trusted_device",
            details: { deviceId: String(deviceId).trim() },
          });
          return res.status(200).json({ token, role: user.role, userId: user.id, mfaBypassed: true });
        }
      }

      let otpInfo;
      try {
        otpInfo = await issueLoginOtp({ user });
      } catch (err) {
        if (String(err?.message || err) === "mfa_email_missing") {
          return res.status(400).json({
            error: "mfa_email_missing",
            message: "Set a real email for this patient before using Email OTP MFA.",
          });
        }
        // eslint-disable-next-line no-console
        console.error(err);
        return res.status(500).json({ error: "otp_send_failed" });
      }
      await auditAppend({
        actor: { userId: user.id, role: user.role, username: user.username },
        action: "auth.otp_issued",
        details: { otpRequestId: otpInfo.otpRequestId, purpose: "LOGIN", expiresAt: otpInfo.expiresAt, sentTo: otpInfo.sentTo, delivery: otpInfo.delivery },
      });
      return res.status(200).json({
        mfaRequired: true,
        method: "EMAIL_OTP",
        otpRequestId: otpInfo.otpRequestId,
        userId: user.id,
        username: user.username,
        expiresAt: otpInfo.expiresAt,
        sentTo: otpInfo.sentTo,
        delivery: otpInfo.delivery,
      });
    }

    if (MFA_REQUIRED_ROLES.has(user.role) && mfa !== DEMO_MFA_CODE) {
      return res.status(401).json({
        error: "mfa_required_or_invalid",
        message: "Enter the demo MFA code for this role.",
      });
    }

    const token = jwtSignHs256({
      payload: { sub: user.id, role: user.role, username: user.username },
      secret: JWT_SECRET,
      expiresInSeconds: 15 * 60,
    });

    await recordLoginSuccess({
      userId: user.id,
      deviceId: String(deviceId || "").trim(),
      ip: getClientIp(req),
      userAgent: req.header("user-agent") || null,
    });

    await upsertStaffSession({ user, req, deviceId: String(deviceId || "").trim() });

    await auditAppend({
      actor: { userId: user.id, role: user.role, username: user.username },
      action: "auth.login_success",
      details: {},
    });

    return res.json({ token, role: user.role, userId: user.id });
  }));

  // Login device history for the current user (for "account created device" + "last used device" UX)
  app.get("/auth/login-devices", requireAuth, asyncRoute(async (req, res) => {
    const userId = req.auth.sub;
    const user = await User.findOne(
      { id: userId },
      { _id: 0, id: 1, username: 1, role: 1, createdFromDeviceId: 1, lastLoginDeviceId: 1, lastLoginAt: 1 }
    ).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });

    const devices = await UserLoginDevice.find({ userId }, { _id: 0, __v: 0 })
      .sort({ lastSeenAt: -1, firstSeenAt: -1 })
      .lean();

    res.json({ user, count: devices.length, devices });
  }));

  // Consume magic link (no JWT yet) to verify new device, then issue JWT
  app.post("/auth/magic-link/consume", asyncRoute(async (req, res) => {
    const { token, deviceId } = req.body || {};
    if (!isNonEmptyString(token) || !looksLikeDeviceId(deviceId)) {
      return res.status(400).json({ error: "bad_request", message: "token + deviceId required" });
    }
    const record = await MagicLinkRequest.findOne({ tokenHash: hashMagicToken(String(token).trim()), purpose: "NEW_DEVICE" }).lean();
    if (!record) return res.status(404).json({ error: "magic_link_not_found" });
    if (record.usedAt) return res.status(409).json({ error: "magic_link_used" });
    if (record.expiresAt.getTime() < Date.now()) return res.status(401).json({ error: "magic_link_expired" });
    if (String(record.context?.deviceId || "") !== String(deviceId).trim()) {
      return res.status(403).json({ error: "device_mismatch" });
    }

    const user = await User.findOne({ id: record.userId }).lean();
    if (!user || user.status !== "active") return res.status(401).json({ error: "invalid_user" });

    const now = new Date();
    const ip = getClientIp(req);
    const userAgent = req.header("user-agent") || null;
    await Promise.all([
      MagicLinkRequest.updateOne({ id: record.id }, { $set: { usedAt: now } }),
      UserLoginDevice.updateOne(
        { userId: user.id, deviceId: String(deviceId).trim() },
        {
          $setOnInsert: {
            id: randomId("ulogdev"),
            userId: user.id,
            deviceId: String(deviceId).trim(),
            firstSeenAt: now,
            firstIp: isNonEmptyString(ip) ? String(ip).slice(0, 128) : null,
          },
          $set: {
            lastSeenAt: now,
            verifiedAt: now,
            blockedAt: null,
            lastIp: isNonEmptyString(ip) ? String(ip).slice(0, 128) : null,
            lastUserAgent: isNonEmptyString(userAgent) ? String(userAgent).slice(0, 512) : null,
          },
        },
        { upsert: true }
      ),
    ]);

    await auditAppend({
      actor: { userId: user.id, role: user.role, username: user.username },
      action: "auth.new_device_magic_link_consumed",
      details: { deviceId: String(deviceId).trim() },
    });

    const jwt = jwtSignHs256({
      payload: { sub: user.id, role: user.role, username: user.username },
      secret: JWT_SECRET,
      expiresInSeconds: 15 * 60,
    });
    await recordLoginSuccess({
      userId: user.id,
      deviceId: String(deviceId).trim(),
      ip: getClientIp(req),
      userAgent: req.header("user-agent") || null,
    });
    await upsertStaffSession({ user, req, deviceId: String(deviceId).trim() });
    return res.json({ token: jwt, role: user.role, userId: user.id });
  }));

  app.post("/auth/verify-otp", asyncRoute(async (req, res) => {
    const { otpRequestId, otp, rememberDevice, deviceId } = req.body || {};
    if (!isNonEmptyString(otpRequestId) || !isNonEmptyString(otp)) {
      return res.status(400).json({ error: "bad_request", message: "otpRequestId + otp required" });
    }

    // Accept both LOGIN and STEP_UP here; device-based step-up uses STEP_UP with context.
    const loginVerified = await verifyOtpRequest({ otpRequestId, otp, expectedPurpose: "LOGIN" });
    const stepUpVerified = !loginVerified.ok ? await verifyOtpRequest({ otpRequestId, otp, expectedPurpose: "STEP_UP" }) : null;
    const verified = loginVerified.ok ? loginVerified : stepUpVerified;
    if (!verified.ok) return res.status(verified.status).json(verified.body);

    const user = await User.findOne({ id: verified.request.userId }).lean();
    if (!user || user.status !== "active") return res.status(401).json({ error: "invalid_user" });

    const token = jwtSignHs256({
      payload: { sub: user.id, role: user.role, username: user.username },
      secret: JWT_SECRET,
      expiresInSeconds: 15 * 60,
    });

    let rememberOut = null;
    if (rememberDevice && looksLikeDeviceId(deviceId) && user.mfaEnabled && user.mfaMethod === "EMAIL_OTP") {
      const raw = crypto.randomBytes(32).toString("base64url");
      const trustedId = randomId("trusted");
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      await TrustedDevice.updateOne(
        { userId: user.id, deviceId: String(deviceId).trim() },
        {
          $set: {
            id: trustedId,
            userId: user.id,
            deviceId: String(deviceId).trim(),
            tokenHash: hashRememberToken(raw),
            expiresAt,
            revokedAt: null,
            lastUsedAt: new Date(),
          },
        },
        { upsert: true }
      );
      rememberOut = { rememberToken: raw, deviceId: String(deviceId).trim(), expiresAt: expiresAt.toISOString() };
      await auditAppend({
        actor: { userId: user.id, role: user.role, username: user.username },
        action: "auth.trusted_device_added",
        details: { deviceId: String(deviceId).trim(), expiresAt: expiresAt.toISOString() },
      });
    }

    // If this OTP was a step-up for a new login device, mark device verified
    if (verified.request.purpose === "STEP_UP" && verified.request.context?.reason === "NEW_DEVICE") {
      const normalizedDeviceId = String(verified.request.context.deviceId || "").trim();
      if (looksLikeDeviceId(normalizedDeviceId)) {
        const now = new Date();
        const ip = getClientIp(req);
        const userAgent = req.header("user-agent") || null;
        await UserLoginDevice.updateOne(
          { userId: user.id, deviceId: normalizedDeviceId },
          {
            $setOnInsert: {
              id: randomId("ulogdev"),
              userId: user.id,
              deviceId: normalizedDeviceId,
              firstSeenAt: now,
              firstIp: isNonEmptyString(ip) ? String(ip).slice(0, 128) : null,
            },
            $set: {
              lastSeenAt: now,
              verifiedAt: now,
              blockedAt: null,
              lastIp: isNonEmptyString(ip) ? String(ip).slice(0, 128) : null,
              lastUserAgent: isNonEmptyString(userAgent) ? String(userAgent).slice(0, 512) : null,
            },
          },
          { upsert: true }
        );
        await auditAppend({
          actor: { userId: user.id, role: user.role, username: user.username },
          action: "auth.step_up_new_device_verified",
          details: { deviceId: normalizedDeviceId },
        });
      }
    }

    await auditAppend({
      actor: { userId: user.id, role: user.role, username: user.username },
      action: "auth.otp_verified",
      details: { otpRequestId, purpose: verified.request.purpose },
    });

    await recordLoginSuccess({
      userId: user.id,
      deviceId: String(deviceId || "").trim(),
      ip: getClientIp(req),
      userAgent: req.header("user-agent") || null,
    });
    await upsertStaffSession({ user, req, deviceId: String(deviceId || "").trim() });

    return res.json({ token, role: user.role, userId: user.id, ...(rememberOut ? rememberOut : {}) });
  }));

  // Trusted devices: list + remove (removal requires email OTP)
  app.get("/auth/trusted-devices", requireAuth, asyncRoute(async (req, res) => {
    const devices = await TrustedDevice.find(
      { userId: req.auth.sub, revokedAt: null, expiresAt: { $gt: new Date() } },
      { _id: 0, __v: 0, tokenHash: 0 }
    )
      .sort({ lastUsedAt: -1, createdAt: -1 })
      .lean();
    res.json({ count: devices.length, devices });
  }));

  app.post("/auth/trusted-devices/remove/request", requireAuth, asyncRoute(async (req, res) => {
    const { deviceId } = req.body || {};
    if (!looksLikeDeviceId(deviceId)) return res.status(400).json({ error: "bad_request", message: "deviceId required" });

    const device = await TrustedDevice.findOne({ userId: req.auth.sub, deviceId: String(deviceId).trim(), revokedAt: null }).lean();
    if (!device) return res.status(404).json({ error: "trusted_device_not_found" });

    const user = await User.findOne({ id: req.auth.sub }).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });
    if (!looksLikeEmail(user.email) || String(user.email).endsWith("@demo.local")) {
      return res.status(400).json({ error: "mfa_email_missing", message: "Set a real email on your account before removing devices." });
    }

    let otpInfo;
    try {
      otpInfo = await issueOtpRequest({
        user,
        purpose: "DEVICE_REMOVE",
        context: { deviceId: String(deviceId).trim() },
      });
    } catch (err) {
      if (String(err?.message || err) === "mfa_email_missing") return res.status(400).json({ error: "mfa_email_missing" });
      // eslint-disable-next-line no-console
      console.error(err);
      return res.status(500).json({ error: "otp_send_failed" });
    }

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "auth.trusted_device_remove_requested",
      details: { deviceId: String(deviceId).trim(), otpRequestId: otpInfo.otpRequestId, delivery: otpInfo.delivery },
    });

    res.json({
      ok: true,
      otpRequestId: otpInfo.otpRequestId,
      expiresAt: otpInfo.expiresAt,
      sentTo: otpInfo.sentTo,
      delivery: otpInfo.delivery,
    });
  }));

  app.post("/auth/trusted-devices/remove/confirm", requireAuth, asyncRoute(async (req, res) => {
    const { otpRequestId, otp } = req.body || {};
    if (!isNonEmptyString(otpRequestId) || !isNonEmptyString(otp)) {
      return res.status(400).json({ error: "bad_request", message: "otpRequestId + otp required" });
    }
    const verified = await verifyOtpRequest({ otpRequestId, otp, expectedPurpose: "DEVICE_REMOVE" });
    if (!verified.ok) return res.status(verified.status).json(verified.body);
    if (verified.request.userId !== req.auth.sub) return res.status(403).json({ error: "forbidden" });

    const ctxDeviceId = verified.request.context?.deviceId;
    if (!looksLikeDeviceId(ctxDeviceId)) return res.status(400).json({ error: "bad_request", message: "invalid request context" });

    await TrustedDevice.updateOne(
      { userId: req.auth.sub, deviceId: String(ctxDeviceId).trim(), revokedAt: null },
      { $set: { revokedAt: new Date() } }
    );

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "auth.trusted_device_revoked",
      details: { deviceId: String(ctxDeviceId).trim(), via: "email_otp" },
    });

    res.json({ ok: true, deviceId: String(ctxDeviceId).trim() });
  }));

  // Deprecated: kept to avoid breaking old UI. Use the flows above.
  app.post("/auth/forget-device", requireAuth, asyncRoute(async (req, res) => {
    return res.status(410).json({ error: "deprecated", message: "Use /auth/trusted-devices/remove/request and /confirm (email verification required)." });
  }));

  // Logout for hosted deployments (clears staff biometric verification for this device).
  app.post("/auth/logout", requireAuth, asyncRoute(async (req, res) => {
    const did = getRequestDeviceId(req);
    if (did && req.auth.role !== "patient") {
      await StaffSession.updateOne(
        { userId: req.auth.sub, role: req.auth.role, deviceId: did, isActive: true },
        { $set: { isActive: false, biometricVerified: false, biometricVerifiedAt: null, lastSeenAt: new Date() } }
      );
    }
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
      action: "auth.logout",
      details: { deviceId: did },
    });
    res.json({ ok: true });
  }));

  // Forgot password (Email OTP)
  // Security notes:
  // - Response is intentionally non-enumerating: unknown users still get {ok:true}.
  // - OTP is stored hashed (OtpRequest) and expires quickly.
  app.post("/auth/forgot-password/request", asyncRoute(async (req, res) => {
    const { identifier, deviceId } = req.body || {};
    const id = isNonEmptyString(identifier) ? String(identifier).trim() : "";
    const did = looksLikeDeviceId(deviceId) ? String(deviceId).trim() : getRequestDeviceId(req);
    if (!isNonEmptyString(id)) return res.status(400).json({ error: "bad_request", message: "identifier required" });

    const user = await User.findOne({ $or: [{ username: id }, { email: id }] }).lean();

    await auditAppend({
      actor: { identifier: id },
      action: "auth.password_reset_requested",
      details: { deviceId: did, hasUser: Boolean(user) },
    });

    if (!user || user.status !== "active") {
      return res.json({ ok: true });
    }

    if (!looksLikeEmail(user.email) || String(user.email).endsWith("@demo.local")) {
      // Can't deliver OTP without a real email. Still return ok to avoid user enumeration.
      return res.json({ ok: true });
    }

    // Simple rate limit per user (MVP): max 5 RESET OTPs in the last hour.
    const since = new Date(Date.now() - 60 * 60 * 1000);
    const recent = await OtpRequest.countDocuments({ userId: user.id, purpose: "RESET", createdAt: { $gte: since } });
    if (recent >= 5) {
      await auditAppend({
        actor: { userId: user.id, role: user.role, username: user.username },
        action: "anomaly.password_reset_rate_limited",
        details: { countLastHour: recent },
      });
      return res.json({ ok: true });
    }

    const knownDevice = did
      ? Boolean(await UserLoginDevice.findOne({ userId: user.id, deviceId: did, verifiedAt: { $ne: null } }).lean())
      : false;
    if (!knownDevice) {
      await auditAppend({
        actor: { userId: user.id, role: user.role, username: user.username },
        action: "anomaly.password_reset_new_device",
        details: { deviceId: did },
      });
    }

    const otpInfo = await issueOtpRequest({ user, purpose: "RESET", context: { deviceId: did, knownDevice } });
    return res.json({ ok: true, ...otpInfo });
  }));

  app.post("/auth/forgot-password/verify-otp", asyncRoute(async (req, res) => {
    const { otpRequestId, otp } = req.body || {};
    if (!isNonEmptyString(otpRequestId) || !isNonEmptyString(otp)) {
      return res.status(400).json({ error: "bad_request", message: "otpRequestId + otp required" });
    }

    const reqRecord = await OtpRequest.findOne({ id: otpRequestId }).lean();
    if (!reqRecord) return res.status(404).json({ error: "otp_request_not_found" });

    const user = await User.findOne({ id: reqRecord.userId }).lean();
    if (!user || user.status !== "active") return res.status(404).json({ error: "user_not_found" });

    if (user.passwordResetLockedUntil && user.passwordResetLockedUntil.getTime() > Date.now()) {
      return res.status(403).json({ error: "password_reset_locked_admin_required" });
    }

    const verified = await verifyOtpRequest({ otpRequestId, otp, expectedPurpose: "RESET" });
    if (!verified.ok) {
      // If max attempts exceeded, lock the user's password reset until admin unlock.
      if (verified.body?.error === "otp_locked") {
        await User.updateOne(
          { id: user.id },
          {
            $set: {
              passwordResetLockedUntil: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000),
              passwordResetLockedAt: new Date(),
              passwordResetLockedReason: "otp_failed_3",
              passwordResetLockedBy: null,
            },
          }
        );
        await auditAppend({
          actor: { userId: user.id, role: user.role, username: user.username },
          action: "auth.password_reset_locked",
          details: { otpRequestId },
        });
        return res.status(423).json({ error: "password_reset_locked_admin_required" });
      }
      return res.status(verified.status).json(verified.body);
    }

    await auditAppend({
      actor: { userId: user.id, role: user.role, username: user.username },
      action: "auth.password_reset_otp_verified",
      details: { otpRequestId },
    });

    const resetToken = jwtSignHs256({
      payload: { sub: user.id, purpose: "RESET_PASSWORD", otpRequestId },
      secret: JWT_SECRET,
      expiresInSeconds: 10 * 60,
    });

    return res.json({ ok: true, resetToken });
  }));

  app.post("/auth/forgot-password/set-password", asyncRoute(async (req, res) => {
    const { resetToken, newPassword, resetMfa } = req.body || {};
    if (!isNonEmptyString(resetToken) || !looksLikePassword(newPassword)) {
      return res.status(400).json({ error: "bad_request", message: "resetToken + newPassword required" });
    }

    const verifiedJwt = jwtVerifyHs256({ token: String(resetToken).trim(), secret: JWT_SECRET });
    if (!verifiedJwt.ok) return res.status(401).json({ error: "invalid_reset_token" });
    const payload = verifiedJwt.payload || {};
    if (payload.purpose !== "RESET_PASSWORD" || !isNonEmptyString(payload.sub) || !isNonEmptyString(payload.otpRequestId)) {
      return res.status(401).json({ error: "invalid_reset_token" });
    }

    const user = await User.findOne({ id: payload.sub }).lean();
    if (!user || user.status !== "active") return res.status(404).json({ error: "user_not_found" });

    if (user.passwordResetLockedUntil && user.passwordResetLockedUntil.getTime() > Date.now()) {
      return res.status(403).json({ error: "password_reset_locked_admin_required" });
    }

    const update = { password: hashPasswordScrypt(newPassword) };
    const doResetMfa = Boolean(resetMfa);
    if (doResetMfa) {
      update.mfaEnabled = false;
      update.mfaMethod = "NONE";
    }
    await User.updateOne({ id: user.id }, { $set: update });

    // Defensive: revoke trusted-device bypass tokens after password reset.
    await TrustedDevice.updateMany({ userId: user.id, revokedAt: null }, { $set: { revokedAt: new Date() } });

    await auditAppend({
      actor: { userId: user.id, role: user.role, username: user.username },
      action: "auth.password_reset_completed",
      details: { otpRequestId: payload.otpRequestId, resetMfa: doResetMfa },
    });

    return res.json({ ok: true });
  }));

  app.post("/auth/resend-otp", asyncRoute(async (req, res) => {
    const { otpRequestId } = req.body || {};
    if (!isNonEmptyString(otpRequestId)) {
      return res.status(400).json({ error: "bad_request", message: "otpRequestId required" });
    }
    const request = await OtpRequest.findOne({ id: otpRequestId }).lean();
    if (!request) return res.status(404).json({ error: "otp_request_not_found" });
    if (request.used) return res.status(409).json({ error: "otp_already_used" });
    if (request.expiresAt.getTime() < Date.now()) return res.status(401).json({ error: "otp_expired" });

    const cooldownMs = 60 * 1000;
    const nextAllowedAt = new Date(request.lastSentAt.getTime() + cooldownMs);
    if (Date.now() < nextAllowedAt.getTime()) {
      const cooldownSeconds = Math.ceil((nextAllowedAt.getTime() - Date.now()) / 1000);
      return res.status(429).json({ error: "cooldown", cooldownSeconds });
    }

    const user = await User.findOne({ id: request.userId }).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });

    const otp = generateOtp6();
    await OtpRequest.updateOne(
      { id: otpRequestId },
      { $set: { otpHash: hashOtp(otp), lastSentAt: new Date() } }
    );

    const sentTo = user.email || `${user.username}@demo.local`;
    if (isSmtpEnabled()) {
      if (!user.email || user.email.endsWith("@demo.local")) {
        return res.status(400).json({ error: "mfa_email_missing" });
      }
      try {
        await sendOtpEmail({ to: user.email, otp, expiresAtIso: request.expiresAt.toISOString() });
        // eslint-disable-next-line no-console
        console.log(`[OTP] RESEND SENT user=${user.username} sentTo=${user.email} expiresAt=${request.expiresAt.toISOString()}`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(err);
        return res.status(500).json({ error: "otp_send_failed" });
      }
    } else {
      // eslint-disable-next-line no-console
      console.log(`[OTP] RESEND user=${user.username} sentTo=${sentTo} otp=${otp} expiresAt=${request.expiresAt.toISOString()}`);
    }

    await auditAppend({
      actor: { userId: user.id, role: user.role, username: user.username },
      action: "auth.otp_resent",
      details: { otpRequestId, sentTo, delivery: isSmtpEnabled() ? "email" : "console" },
    });

    return res.json({ resent: true, cooldownSeconds: 60, delivery: isSmtpEnabled() ? "email" : "console", sentTo });
  }));

  // --- Patient registration + strong verification (clinic code) ---
  app.post("/patients/pre-register", asyncRoute(async (req, res) => {
    const { username, password, geo, deviceId, email } = req.body || {};
    if (!looksLikeUsername(username) || !looksLikePassword(password)) {
      return res.status(400).json({
        error: "bad_request",
        message: "username (3-32 chars, letters/numbers/._-) and password (min 8 chars) required",
      });
    }
    if (email && !looksLikeEmail(email)) {
      return res.status(400).json({ error: "bad_request", message: "invalid email" });
    }

    const ip = getClientIp(req);
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const ipReuseCount = await RegistrationAttempt.countDocuments({ ip, ts: { $gte: since } });
    if (ipReuseCount >= 25) {
      await auditAppend({
        actor: { username, role: "patient" },
        action: "anomaly.registration_burst",
        details: { ipReuseCount, ip },
      });
    }

    const normalizedEmail = looksLikeEmail(email) ? String(email).trim().toLowerCase() : null;

    const existing = await User.findOne({ $or: [{ username }, ...(normalizedEmail ? [{ email: normalizedEmail }] : [])] }).lean();
    if (existing) {
      if (existing.username === username) return res.status(409).json({ error: "username_taken" });
      if (normalizedEmail && existing.email === normalizedEmail) return res.status(409).json({ error: "email_taken" });
      return res.status(409).json({ error: "conflict" });
    }

    const patientId = randomId("u_patient");
    await RegistrationAttempt.create({ ip, patientId, ts: new Date() });

    const { score, top3 } = buildTrustScore({
      // At registration time, the device is "new" by definition. We don't penalize for it in the MVP.
      newDevice: false,
      ipReuseCount,
      failedOtpAttempts: 0,
      clinicCodeUsed: false,
      geoAnomaly: false,
    });

    const normalizedDeviceId = looksLikeDeviceId(deviceId) ? String(deviceId).trim() : null;

    try {
      await User.create({
        id: patientId,
        username,
        role: "patient",
        password: hashPasswordScrypt(password),
        status: "pending",
        email: normalizedEmail || `${username}@demo.local`,
        mfaEnabled: false,
        mfaMethod: "NONE",
        createdFromDeviceId: normalizedDeviceId,
      });
      await PatientProfile.create({
        patientId,
        status: score >= 80 ? "VERIFIED" : "PENDING",
        trustScore: score,
        trustExplainTop3: top3,
        lastKnownGeo: isNonEmptyString(geo) ? geo : null,
      });
    } catch (err) {
      if (isMongoDuplicateKeyError(err)) {
        const msg = String(err?.message || "");
        if (msg.includes("username")) return res.status(409).json({ error: "username_taken" });
        if (msg.includes("email")) return res.status(409).json({ error: "email_taken" });
        return res.status(409).json({ error: "conflict" });
      }
      throw err;
    }

    // If the patient is PENDING, auto-issue a one-time verification code (demo-friendly).
    let verification = null;
    if (score < 80) {
      const code = crypto.randomBytes(4).toString("hex").toUpperCase(); // 8 chars
      const codeHash = sha256Base64url(`clinic:${code}:${JWT_SECRET}`);
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
      await ClinicCode.create({
        codeHash,
        patientId,
        expiresAt,
        usedAt: null,
        usedByPatientId: null,
      });

      let delivery = "console";
      let sentTo = null;
      const patientEmail = looksLikeEmail(email) ? String(email).trim().toLowerCase() : null;
      if (isSmtpEnabled() && patientEmail && !patientEmail.endsWith("@demo.local")) {
        try {
          await sendClinicCodeEmail({ to: patientEmail, code, expiresAtIso: expiresAt.toISOString() });
          delivery = "email";
          sentTo = patientEmail;
        } catch (err) {
          // eslint-disable-next-line no-console
          console.error(err);
          // fall back to console so the demo can proceed
          // eslint-disable-next-line no-console
          console.log(`[CLINIC_CODE] FALLBACK user=${username} patientId=${patientId} code=${code} expiresAt=${expiresAt.toISOString()}`);
        }
      } else {
        // eslint-disable-next-line no-console
        console.log(`[CLINIC_CODE] user=${username} patientId=${patientId} code=${code} expiresAt=${expiresAt.toISOString()}`);
      }

      verification = {
        required: true,
        method: "CLINIC_CODE",
        expiresAt: expiresAt.toISOString(),
        delivery,
        sentTo,
      };

      await auditAppend({
        actor: { username, role: "patient" },
        action: "patient.verification_code_issued",
        details: { patientId, expiresAt: expiresAt.toISOString(), delivery, sentTo },
      });
    }

    if (normalizedDeviceId) {
      const now = new Date();
      await UserLoginDevice.updateOne(
        { userId: patientId, deviceId: normalizedDeviceId },
        {
          $setOnInsert: {
            id: randomId("ulogdev"),
            userId: patientId,
            deviceId: normalizedDeviceId,
            firstSeenAt: now,
            firstIp: String(getClientIp(req)).slice(0, 128),
          },
          $set: {
            lastSeenAt: now,
            verifiedAt: now,
            blockedAt: null,
            lastIp: String(getClientIp(req)).slice(0, 128),
            lastUserAgent: isNonEmptyString(req.header("user-agent")) ? String(req.header("user-agent")).slice(0, 512) : null,
          },
        },
        { upsert: true }
      );
      await auditAppend({
        actor: { username, role: "patient" },
        action: "patient.created_device_recorded",
        details: { patientId, deviceId: normalizedDeviceId },
      });
    }

    await auditAppend({
      actor: { username, role: "patient" },
      action: "patient.pre_register",
      details: {
        patientId,
        ipReuseCount,
        trustScore: score,
        trustExplainTop3: top3,
        decidedStatus: score >= 80 ? "VERIFIED" : "PENDING",
        createdFromDeviceId: normalizedDeviceId,
      },
    });

    // No-trust: require admin approval before account activation.
    await AccountRequest.create({
      id: randomId("acctreq"),
      type: "ACTIVATE",
      userId: patientId,
      role: "patient",
      status: "PENDING",
      createdAtIso: nowIso(),
      email: normalizedEmail || `${username}@demo.local`,
      username,
    });
    await auditAppend({
      actor: { username, role: "patient" },
      action: "account.activate_requested",
      details: { userId: patientId, role: "patient" },
    });

    return res.status(201).json({
      patientId,
      status: score >= 80 ? "VERIFIED" : "PENDING",
      accountStatus: "PENDING_ADMIN_APPROVAL",
      trustScore: score,
      trustExplainTop3: top3,
      next: "await_admin_approval",
      ...(verification ? { verification } : {}),
    });
  }));

  // Doctor: create account (pending admin approval)
  app.post("/doctors/pre-register", asyncRoute(async (req, res) => {
    const { username, email, password } = req.body || {};
    if (!looksLikeUsername(username) || !looksLikePassword(password) || !looksLikeEmail(email)) {
      return res.status(400).json({ error: "bad_request", message: "username + email + password required" });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = await User.findOne({ $or: [{ username }, { email: normalizedEmail }] }).lean();
    if (existing) return res.status(409).json({ error: "user_exists" });

    // Generate signing keys (Ed25519) for Rx signing when activated.
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });

    const doctorId = randomId("u_doctor");
    await User.create({
      id: doctorId,
      username: String(username).trim(),
      email: normalizedEmail,
      role: "doctor",
      password: hashPasswordScrypt(password),
      status: "pending",
      // Prefer per-user Email OTP MFA for staff accounts (unique per user),
      // fall back to demo MFA when SMTP isn't configured.
      mfaEnabled: isSmtpEnabled(),
      mfaMethod: isSmtpEnabled() ? "EMAIL_OTP" : "NONE",
      publicKeyPem,
      privateKeyPem,
    });

    await AccountRequest.create({
      id: randomId("acctreq"),
      type: "ACTIVATE",
      userId: doctorId,
      role: "doctor",
      status: "PENDING",
      createdAtIso: nowIso(),
      email: normalizedEmail,
      username: String(username).trim(),
    });

    await auditAppend({
      actor: { username: String(username).trim(), role: "doctor" },
      action: "account.activate_requested",
      details: { userId: doctorId, role: "doctor" },
    });

    return res.status(201).json({ ok: true, doctorId, accountStatus: "PENDING_ADMIN_APPROVAL", next: "await_admin_approval" });
  }));

  // User (doctor/patient): request account deletion (admin approval required)
  app.post("/account/delete-request", requireAuth, requireRole(["doctor", "patient"]), asyncRoute(async (req, res) => {
    const user = await User.findOne({ id: req.auth.sub }).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });
    if (user.status !== "active") return res.status(403).json({ error: "account_not_active" });

    const existing = await AccountRequest.findOne({ userId: user.id, type: "DELETE", status: "PENDING" }).lean();
    if (existing) return res.status(409).json({ error: "delete_request_already_pending" });

    const reqId = randomId("acctreq");
    await AccountRequest.create({
      id: reqId,
      type: "DELETE",
      userId: user.id,
      role: user.role,
      status: "PENDING",
      createdAtIso: nowIso(),
      email: user.email,
      username: user.username,
    });
    await auditAppend({
      actor: { userId: user.id, role: user.role, username: user.username },
      action: "account.delete_requested",
      details: { requestId: reqId },
    });

    return res.status(201).json({ ok: true, requestId: reqId, status: "PENDING" });
  }));

  // --- Pharmacist (pharmacy role) signup ---
  app.post("/pharmacist/signup", asyncRoute(async (req, res) => {
    const { username, email, password, mfaCode, deviceId } = req.body || {};
    if (!looksLikeUsername(username) || !looksLikePassword(password) || !looksLikeEmail(email)) {
      return res.status(400).json({ error: "bad_request", message: "username + email + password required" });
    }
    // Signup gate: registration code (NOT MFA). Prevents random public signups in the MVP.
    if (String(mfaCode || "").trim() !== String(PHARMACIST_REGISTRATION_CODE)) {
      return res.status(401).json({ error: "invalid_registration_code", message: "Invalid registration code." });
    }
    const existing = await User.findOne({ $or: [{ username }, { email: String(email).trim().toLowerCase() }] }).lean();
    if (existing) return res.status(409).json({ error: "user_exists" });

    const normalizedEmail = String(email).trim().toLowerCase();
    // If SMTP is enabled, default to per-user Email OTP MFA for pharmacy accounts.
    // Otherwise, keep demo MFA flow (login uses DEMO_MFA_CODE for staff roles).
    const useEmailOtpMfa =
      isSmtpEnabled() && looksLikeEmail(normalizedEmail) && !String(normalizedEmail).endsWith("@demo.local");

    const userId = randomId("u_pharmacy");
    const user = await User.create({
      id: userId,
      username: String(username).trim(),
      email: normalizedEmail,
      role: "pharmacy",
      password: hashPasswordScrypt(password),
      status: "active",
      mfaEnabled: useEmailOtpMfa,
      mfaMethod: useEmailOtpMfa ? "EMAIL_OTP" : "NONE",
      biometricEnrolled: false,
      biometricEnrolledAt: null,
      createdFromDeviceId: looksLikeDeviceId(deviceId) ? String(deviceId).trim() : null,
    });

    const token = jwtSignHs256({
      payload: { sub: user.id, role: user.role, username: user.username },
      secret: JWT_SECRET,
      expiresInSeconds: 15 * 60,
    });

    await recordLoginSuccess({
      userId: user.id,
      deviceId: String(deviceId || "").trim(),
      ip: getClientIp(req),
      userAgent: req.header("user-agent") || null,
    });
    await upsertStaffSession({ user, req, deviceId: String(deviceId || "").trim() });

    await auditAppend({
      actor: { userId: user.id, role: "pharmacy", username: user.username },
      action: "pharmacist.registered",
      details: { pharmacistId: user.id, username: user.username, email: user.email },
    });

    return res.status(201).json({
      ok: true,
      pharmacistId: user.id,
      username: user.username,
      email: user.email,
      token,
      message: "Pharmacist account created successfully. You are now logged in.",
      next: "enroll_biometric",
      biometricEnrollmentRequired: true,
    });
  }));

  // --- Biometric (WebAuthn MVP) ---
  app.get("/biometric/status", requireAuth, asyncRoute(async (req, res) => {
    const user = await User.findOne(
      { id: req.auth.sub },
      { _id: 0, biometricEnrolled: 1, biometricEnrolledAt: 1 }
    ).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });
    const biometrics = await Biometric.find({ userId: req.auth.sub, isActive: true })
      .sort({ enrolledAt: -1 })
      .limit(20)
      .lean();
    // Self-heal: if DB has biometrics but the user flag wasn't updated (or was lost), fix it.
    const enrolledByRecords = biometrics.length > 0;
    const enrolled = Boolean(user.biometricEnrolled) || enrolledByRecords;
    if (enrolledByRecords && !user.biometricEnrolled) {
      try {
        await User.updateOne({ id: req.auth.sub }, { $set: { biometricEnrolled: true, biometricEnrolledAt: biometrics[0].enrolledAt || new Date() } });
      } catch {
        // ignore
      }
    }
    res.json({
      enrolled,
      enrolledAt: enrolled ? (user.biometricEnrolledAt ? new Date(user.biometricEnrolledAt).toISOString() : (biometrics[0]?.enrolledAt ? new Date(biometrics[0].enrolledAt).toISOString() : null)) : null,
      biometrics: biometrics.map((b) => ({
        id: b.id,
        deviceName: b.deviceName || null,
        enrolledAt: b.enrolledAt ? new Date(b.enrolledAt).toISOString() : null,
        lastUsedAt: b.lastUsedAt ? new Date(b.lastUsedAt).toISOString() : null,
      })),
    });
  }));

  app.get("/pharmacy/biometric-status", requireAuth, requireRole(["pharmacy"]), asyncRoute(async (req, res) => {
    const did = getRequestDeviceId(req);
    if (!did) return res.status(400).json({ error: "missing_device_id" });
    const session = await getActiveStaffSession({ userId: req.auth.sub, deviceId: did });
    res.json({
      biometricVerified: Boolean(session?.biometricVerified),
      biometricVerifiedAt: session?.biometricVerifiedAt ? new Date(session.biometricVerifiedAt).toISOString() : null,
      deviceId: did,
      sessionId: session?.id || null,
    });
  }));

  app.post("/biometric/enroll/start", requireAuth, requireRole(["pharmacy"]), asyncRoute(async (req, res) => {
    const rpId = computeRpId({ req });
    const challenge = crypto.randomBytes(32).toString("base64url");
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await WebAuthnChallenge.create({
      id: randomId("wac"),
      userId: req.auth.sub,
      purpose: "ENROLL",
      challenge,
      expiresAt,
    });

    res.json({
      challenge,
      rp: { id: rpId, name: "Genzhiper Pharmacy System" },
      user: {
        id: Buffer.from(req.auth.sub).toString("base64url"),
        name: req.auth.username,
        displayName: req.auth.username,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
      },
      timeout: 60000,
      attestation: "direct",
    });
  }));

  app.post("/biometric/enroll/complete", requireAuth, requireRole(["pharmacy"]), asyncRoute(async (req, res) => {
    const did = getRequestDeviceId(req);
    const { credential, challenge, deviceName } = req.body || {};
    if (!credential || !isNonEmptyString(challenge)) {
      return res.status(400).json({ error: "bad_request", message: "credential and challenge required" });
    }

    const latest = await WebAuthnChallenge.findOne({ userId: req.auth.sub, purpose: "ENROLL", expiresAt: { $gt: new Date() } })
      .sort({ expiresAt: -1 })
      .lean();
    if (!latest) return res.status(400).json({ error: "challenge_missing" });
    if (String(challenge) !== String(latest.challenge)) return res.status(401).json({ error: "challenge_mismatch" });

    const rawIdBuf = bytesFromUnknown(credential.rawId) || bytesFromUnknown(credential.rawIdB64u) || bytesFromUnknown(credential.id);
    const credIdB64u = rawIdBuf ? rawIdBuf.toString("base64url") : null;
    if (!isNonEmptyString(credIdB64u)) return res.status(400).json({ error: "bad_request", message: "credential.rawId required" });

    const existing = await Biometric.findOne({ credentialIdB64u: credIdB64u }).lean();
    if (existing) {
      // Idempotent: if this same user already enrolled this credential, treat as success.
      if (existing.userId === req.auth.sub) {
        const isActive = existing.isActive !== false;
        if (!isActive) {
          await Biometric.updateOne(
            { id: existing.id },
            {
              $set: {
                isActive: true,
                lastUsedAt: null,
                ...(isNonEmptyString(deviceName) ? { deviceName: String(deviceName).trim().slice(0, 64) } : {}),
              },
            }
          );
        }
        return res.status(200).json({ ok: true, alreadyEnrolled: true, reactivated: !isActive });
      }

      // If the credential is orphaned (user missing/deleted), clean it up and allow enrollment to proceed.
      const owner = await User.findOne({ id: existing.userId }).lean();
      if (!owner || owner.status === "deleted") {
        await Biometric.deleteOne({ id: existing.id });
        await auditAppend({
          actor: { userId: req.auth.sub, role: "pharmacy", username: req.auth.username },
          action: "biometric.orphan_deleted",
          details: { credentialId: credIdB64u, deletedBiometricId: existing.id, ownerUserId: existing.userId, ownerStatus: owner?.status || "missing" },
        });
        // Best-effort: if we deleted the last biometric for the old user, clear their flag.
        if (owner?.id) {
          const remaining = await Biometric.countDocuments({ userId: owner.id, isActive: true });
          if (remaining === 0) {
            await User.updateOne({ id: owner.id }, { $set: { biometricEnrolled: false, biometricEnrolledAt: null } });
          }
        }
      } else {
        // eslint-disable-next-line no-console
        console.log(`[BIOMETRIC] credential_exists credentialId=${credIdB64u} ownerUserId=${existing.userId}`);
        return res.status(409).json({
          error: "credential_exists",
          credentialIdB64u: credIdB64u,
          message: "This device biometric is already enrolled for another account. Use a different browser profile/device, or ask an admin to clear the old enrollment.",
        });
      }
    }

    const attObjBuf = bytesFromUnknown(credential?.response?.attestationObject);
    const cdjBuf = bytesFromUnknown(credential?.response?.clientDataJSON);
    if (!attObjBuf || !cdjBuf) return res.status(400).json({ error: "bad_request", message: "credential.response fields required" });
    const publicKeyJson = JSON.stringify({
      id: credential.id || credIdB64u,
      rawId: rawIdBuf ? Array.from(rawIdBuf) : [],
      type: credential.type || "public-key",
      response: {
        attestationObject: attObjBuf.toString("base64url"),
        clientDataJSON: cdjBuf.toString("base64url"),
      },
    });

    try {
      await Biometric.create({
        id: randomId("bio"),
        userId: req.auth.sub,
        role: "pharmacy",
        credentialIdB64u: credIdB64u,
        publicKeyJson,
        counter: 0,
        deviceName: isNonEmptyString(deviceName) ? String(deviceName).trim().slice(0, 64) : "Biometric Device",
        enrolledAt: new Date(),
        lastUsedAt: null,
        isActive: true,
      });
    } catch (err) {
      // Avoid leaking DB internals to clients, but do return a meaningful reason for common cases.
      if (String(err?.code) === "11000") {
        return res.status(409).json({
          error: "credential_exists",
          credentialIdB64u: credIdB64u,
          message: "This device biometric is already enrolled for another account (or a stale record exists).",
        });
      }
      throw err;
    }

    await Promise.all([
      User.updateOne({ id: req.auth.sub }, { $set: { biometricEnrolled: true, biometricEnrolledAt: new Date() } }),
      WebAuthnChallenge.deleteOne({ id: latest.id }),
    ]);

    // Convenience: if we have a staff session deviceId, mark the current session as verified
    // so signup -> enroll immediately unlocks the pharmacy dashboard.
    if (did) {
      const now = new Date();
      await StaffSession.updateOne(
        { userId: req.auth.sub, role: "pharmacy", deviceId: did, isActive: true },
        {
          $setOnInsert: {
            id: randomId("staffsess"),
            userId: req.auth.sub,
            role: "pharmacy",
            deviceId: did,
            firstSeenAt: now,
            ipAddress: String(getClientIp(req)).slice(0, 128),
            userAgent: isNonEmptyString(req.header("user-agent")) ? String(req.header("user-agent")).slice(0, 512) : null,
          },
          $set: { lastSeenAt: now, biometricVerified: true, biometricVerifiedAt: now, isActive: true },
        },
        { upsert: true }
      );
    }

    await auditAppend({
      actor: { userId: req.auth.sub, role: "pharmacy", username: req.auth.username },
      action: "biometric.enrolled",
      details: { credentialId: credIdB64u },
    });

    res.status(201).json({ ok: true });
  }));

  app.post("/biometric/verify/start", requireAuth, requireRole(["pharmacy"]), asyncRoute(async (req, res) => {
    const rpId = computeRpId({ req });
    const credsRaw = await Biometric.find({ userId: req.auth.sub, isActive: true }, { _id: 0, credentialIdB64u: 1 }).lean();
    const creds = (credsRaw || []).filter((c) => isNonEmptyString(c?.credentialIdB64u));
    if (!creds.length) return res.status(404).json({ error: "no_biometrics_enrolled" });

    const challenge = crypto.randomBytes(32).toString("base64url");
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await WebAuthnChallenge.create({
      id: randomId("wac"),
      userId: req.auth.sub,
      purpose: "VERIFY",
      challenge,
      expiresAt,
    });

    res.json({
      challenge,
      allowCredentials: creds.map((c) => ({ type: "public-key", id: String(c.credentialIdB64u) })),
      timeout: 60000,
      rpId,
      userVerification: "required",
    });
  }));

  app.post("/biometric/verify/complete", requireAuth, requireRole(["pharmacy"]), asyncRoute(async (req, res) => {
    const did = getRequestDeviceId(req);
    if (!did) return res.status(400).json({ error: "missing_device_id" });
    const { credential, challenge } = req.body || {};
    if (!credential || !isNonEmptyString(challenge)) {
      return res.status(400).json({ error: "bad_request", message: "credential and challenge required" });
    }

    const latest = await WebAuthnChallenge.findOne({ userId: req.auth.sub, purpose: "VERIFY", expiresAt: { $gt: new Date() } })
      .sort({ expiresAt: -1 })
      .lean();
    if (!latest) return res.status(400).json({ error: "challenge_missing" });
    if (String(challenge) !== String(latest.challenge)) return res.status(401).json({ error: "challenge_mismatch" });

    const rawIdBuf = bytesFromUnknown(credential.rawId) || bytesFromUnknown(credential.rawIdB64u) || bytesFromUnknown(credential.id);
    const credIdB64u = rawIdBuf ? rawIdBuf.toString("base64url") : null;
    if (!isNonEmptyString(credIdB64u)) return res.status(400).json({ error: "bad_request", message: "credential.rawId required" });

    const enrolled = await Biometric.findOne({ userId: req.auth.sub, credentialIdB64u: credIdB64u, isActive: true }).lean();
    if (!enrolled) return res.status(403).json({ error: "credential_not_allowed" });

    const now = new Date();
    await Promise.all([
      Biometric.updateOne({ id: enrolled.id }, { $set: { lastUsedAt: now } }),
      StaffSession.updateOne(
        { userId: req.auth.sub, role: "pharmacy", deviceId: did, isActive: true },
        {
          $setOnInsert: {
            id: randomId("staffsess"),
            userId: req.auth.sub,
            role: "pharmacy",
            deviceId: did,
            firstSeenAt: now,
            ipAddress: String(getClientIp(req)).slice(0, 128),
            userAgent: isNonEmptyString(req.header("user-agent")) ? String(req.header("user-agent")).slice(0, 512) : null,
          },
          $set: { lastSeenAt: now, biometricVerified: true, biometricVerifiedAt: now, isActive: true },
        },
        { upsert: true }
      ),
      WebAuthnChallenge.deleteOne({ id: latest.id }),
    ]);

    await auditAppend({
      actor: { userId: req.auth.sub, role: "pharmacy", username: req.auth.username },
      action: "biometric.verified",
      details: { credentialId: credIdB64u, deviceId: did },
    });

    res.json({ biometricVerified: true, message: "Biometric verification successful" });
  }));

  app.get("/patients/me/profile", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
    const profile = await PatientProfile.findOne({ patientId: req.auth.sub }, { _id: 0, __v: 0 }).lean();
    if (!profile) return res.status(404).json({ error: "patient_profile_missing" });
    const patientToken = hmacTokenizePatientId(req.auth.sub);
    const user = await User.findOne(
      { id: req.auth.sub },
      { _id: 0, id: 1, username: 1, email: 1, mfaEnabled: 1, mfaMethod: 1, createdFromDeviceId: 1, lastLoginDeviceId: 1, lastLoginAt: 1 }
    ).lean();
    res.json({ profile, patientToken, user });
  }));

  // Patient: "wallet" of active prescriptions + status
  app.get("/patients/wallet", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
    const patientToken = hmacTokenizePatientId(req.auth.sub);
    const prescriptions = await Prescription.find(
      { patientIdToken: patientToken, status: "active" },
      { _id: 0, __v: 0 }
    )
      .sort({ issuedAt: -1, createdAt: -1 })
      .limit(100)
      .lean();

    const rxIds = prescriptions.map((p) => p.id);
    const dispensed = rxIds.length
      ? await Dispense.find({ rxId: { $in: rxIds }, allowed: true }, { _id: 0, rxId: 1, ts: 1 }).lean()
      : [];
    const usedByRxId = new Map();
    for (const d of dispensed) {
      if (!isNonEmptyString(d?.rxId)) continue;
      const key = String(d.rxId);
      const prev = usedByRxId.get(key);
      if (!prev || String(d.ts).localeCompare(String(prev)) > 0) usedByRxId.set(key, d.ts);
    }

    const doctorIds = [...new Set(prescriptions.map((p) => p.doctorId).filter((id) => isNonEmptyString(id)))];
    const doctors = doctorIds.length
      ? await User.find({ id: { $in: doctorIds }, role: "doctor" }, { _id: 0, id: 1, username: 1, publicKeyPem: 1 }).lean()
      : [];
    const doctorById = new Map(doctors.map((d) => [d.id, d]));

    const wallet = prescriptions.map((rx) => {
      const expired = Date.parse(rx.expiry) < Date.now();
      const usedAt = usedByRxId.get(rx.id) || null;
      const doctor = doctorById.get(rx.doctorId) || null;
      let signatureOk = null;
      try {
        if (doctor?.publicKeyPem) {
          const rxCore = {
            patientIdToken: rx.patientIdToken,
            medicineId: rx.medicineId,
            dosage: rx.dosage,
            durationDays: rx.durationDays,
            issuedAt: rx.issuedAt,
            expiry: rx.expiry,
            nonce: rx.nonce,
          };
          signatureOk = verifyObjectEd25519({ obj: rxCore, signatureB64url: rx.signatureB64url, publicKeyPem: doctor.publicKeyPem });
        }
      } catch {
        signatureOk = false;
      }

      const status = usedAt ? "USED" : expired ? "EXPIRED" : "VALID";
      return {
        prescription: rx,
        status,
        usedAt,
        checks: { signatureOk, expired, used: Boolean(usedAt) },
        doctor: doctor ? { id: doctor.id, username: doctor.username } : null,
        // For QR: patient can present the signed Rx object to the pharmacist scanner.
        qrPayload: JSON.stringify(rx),
      };
    });

    res.json({ ok: true, count: wallet.length, wallet });
  }));

  // Admin generates 1-time clinic code (expires in 10 minutes by default)
  app.post("/clinic/codes", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const { patientId, expiresMinutes, sendEmail } = req.body || {};
    const mins = safeNumber(expiresMinutes) ?? 10;
    const code = crypto.randomBytes(4).toString("hex").toUpperCase(); // 8 chars
    const codeHash = sha256Base64url(`clinic:${code}:${JWT_SECRET}`);
    const expiresAt = new Date(Date.now() + mins * 60 * 1000);

    let delivery = "console";
    let sentTo = null;
    let warning = null;
    const wantsEmail = Boolean(sendEmail);
    if (wantsEmail) {
      if (!isSmtpEnabled()) {
        warning = "SMTP not configured; generated code is shown in the admin UI (console delivery).";
      } else if (!isNonEmptyString(patientId)) {
        warning = "patientId required to email the code; generated code is shown in the admin UI (console delivery).";
      } else {
        const patientUser = await User.findOne({ id: patientId, role: "patient" }).lean();
        if (!patientUser) {
          warning = "Patient not found; generated code is shown in the admin UI (console delivery).";
        } else if (!looksLikeEmail(patientUser.email) || String(patientUser.email).endsWith("@demo.local")) {
          warning = "Patient has no real email; generated code is shown in the admin UI (console delivery).";
        } else {
          const verify = await verifySmtpConnection();
          if (!verify.ok) {
            warning = "SMTP verification failed; generated code is shown in the admin UI (console delivery).";
          } else {
            try {
              await sendClinicCodeEmail({
                to: patientUser.email,
                code,
                expiresAtIso: expiresAt.toISOString(),
              });
              delivery = "email";
              sentTo = patientUser.email;
            } catch (err) {
              // eslint-disable-next-line no-console
              console.error(err);
              warning = "Email send failed; generated code is shown in the admin UI (console delivery).";
            }
          }
        }
      }
    }

    await ClinicCode.create({
      codeHash,
      patientId: isNonEmptyString(patientId) ? patientId : null,
      expiresAt,
      usedAt: null,
      usedByPatientId: null,
    });

    if (delivery === "console") {
      // eslint-disable-next-line no-console
      console.log(`[CLINIC_CODE] patientId=${isNonEmptyString(patientId) ? patientId : "unbound"} code=${code} expiresAt=${expiresAt.toISOString()}`);
    }

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "clinic.code_issued",
      details: {
        patientId: isNonEmptyString(patientId) ? patientId : null,
        expiresAt: expiresAt.toISOString(),
        delivery,
        sentTo,
      },
    });

    // For demo: still return the code even if emailed (fallback).
    return res.status(201).json({
      code,
      delivery,
      sentTo,
      expiresAt: expiresAt.toISOString(),
      boundPatientId: isNonEmptyString(patientId) ? patientId : null,
      ...(warning ? { warning } : {}),
    });
  }));

  // Admin: list patients with profiles for dashboard workflows
  app.get("/admin/patients", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const status = isNonEmptyString(req.query?.status) ? String(req.query.status) : null;
    const filter = status ? { status } : {};
    const profiles = await PatientProfile.find(filter, { _id: 0, patientId: 1, status: 1, trustScore: 1, trustExplainTop3: 1, createdAt: 1 }).sort({ createdAt: -1 }).limit(200).lean();
    const patientIds = profiles.map((p) => p.patientId);
    const users = await User.find({ id: { $in: patientIds }, role: "patient" }, { _id: 0, id: 1, username: 1, email: 1, status: 1 }).lean();
    const userById = new Map(users.map((u) => [u.id, u]));
    const out = profiles.map((p) => ({ ...p, user: userById.get(p.patientId) || null }));
    res.json({ count: out.length, patients: out });
  }));

  // Admin: send a test email to confirm SMTP works
  app.post("/admin/mail/test", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const { to } = req.body || {};
    if (!looksLikeEmail(to)) return res.status(400).json({ error: "bad_request", message: "valid 'to' email required" });
    if (!isSmtpEnabled()) return res.status(400).json({ error: "smtp_not_configured" });
    const verify = await verifySmtpConnection();
    if (!verify.ok) return res.status(400).json({ error: verify.error, detail: verify.detail });
    try {
      await sendOtpEmail({ to, otp: "000000", expiresAtIso: new Date(Date.now() + 5 * 60 * 1000).toISOString() });
      await auditAppend({
        actor: { userId: req.auth.sub, role: req.auth.role },
        action: "admin.mail_test_sent",
        details: { to },
      });
      return res.json({ ok: true });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
      return res.status(500).json({
        error: "email_send_failed",
        detail: {
          name: err?.name,
          code: err?.code,
          message: err?.message,
          responseCode: err?.responseCode,
          response: err?.response,
          command: err?.command,
        },
      });
    }
  }));

  // Admin: biometric lookup (debug/support) and delete (clear stale enrollments)
  app.get("/admin/biometrics/lookup", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const credentialIdB64u = isNonEmptyString(req.query?.credentialIdB64u) ? String(req.query.credentialIdB64u).trim() : "";
    if (!isNonEmptyString(credentialIdB64u)) {
      return res.status(400).json({ error: "bad_request", message: "credentialIdB64u query param required" });
    }

    const bio = await Biometric.findOne({ credentialIdB64u }, { _id: 0, __v: 0 }).lean();
    if (!bio) return res.json({ ok: true, found: false });

    const owner = await User.findOne({ id: bio.userId }, { _id: 0, id: 1, username: 1, role: 1, status: 1, email: 1 }).lean();
    return res.json({
      ok: true,
      found: true,
      biometric: {
        id: bio.id,
        userId: bio.userId,
        role: bio.role,
        credentialIdB64u: bio.credentialIdB64u,
        deviceName: bio.deviceName || null,
        enrolledAt: bio.enrolledAt ? new Date(bio.enrolledAt).toISOString() : null,
        isActive: bio.isActive !== false,
      },
      owner: owner
        ? { id: owner.id, username: owner.username, role: owner.role, status: owner.status, email: owner.email }
        : null,
    });
  }));

  app.post("/admin/biometrics/delete", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const credentialIdB64u = isNonEmptyString(req.body?.credentialIdB64u) ? String(req.body.credentialIdB64u).trim() : "";
    if (!isNonEmptyString(credentialIdB64u)) {
      return res.status(400).json({ error: "bad_request", message: "credentialIdB64u required" });
    }

    const existing = await Biometric.findOne({ credentialIdB64u }).lean();
    if (!existing) return res.json({ ok: true, deleted: false });

    await Biometric.deleteOne({ id: existing.id });
    const remaining = await Biometric.countDocuments({ userId: existing.userId, isActive: true });
    if (remaining === 0) {
      await User.updateOne({ id: existing.userId }, { $set: { biometricEnrolled: false, biometricEnrolledAt: null } });
    }
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
      action: "admin.biometric_deleted",
      details: { credentialIdB64u, deletedBiometricId: existing.id, deletedUserId: existing.userId },
    });

    return res.json({ ok: true, deleted: true });
  }));

  // Admin: account approval queue (no-trust activation + delete requests)
  app.get("/admin/account-requests", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const type = isNonEmptyString(req.query?.type) ? String(req.query.type).trim().toUpperCase() : null;
    const status = isNonEmptyString(req.query?.status) ? String(req.query.status).trim().toUpperCase() : "PENDING";
    const limit = clampInt(req.query?.limit, { min: 1, max: 200, fallback: 100 });

    const filter = {
      ...(type ? { type } : {}),
      ...(status ? { status } : {}),
    };

    const reqs = await AccountRequest.find(filter, { _id: 0, __v: 0 })
      .sort({ createdAtIso: -1 })
      .limit(limit)
      .lean();

    const userIds = [...new Set(reqs.map((r) => r.userId))];
    const users = userIds.length
      ? await User.find({ id: { $in: userIds } }, { _id: 0, id: 1, username: 1, email: 1, role: 1, status: 1 }).lean()
      : [];
    const userById = new Map(users.map((u) => [u.id, u]));

    res.json({
      ok: true,
      count: reqs.length,
      requests: reqs.map((r) => ({ ...r, user: userById.get(r.userId) || null })),
    });
  }));

  app.post("/admin/account-requests/:id/approve", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const id = String(req.params?.id || "").trim();
    const note = isNonEmptyString(req.body?.note) ? String(req.body.note).trim().slice(0, 200) : null;
    const ar = await AccountRequest.findOne({ id }).lean();
    if (!ar) return res.status(404).json({ error: "request_not_found" });
    if (ar.status !== "PENDING") return res.status(409).json({ error: "request_already_decided", status: ar.status });

    const user = await User.findOne({ id: ar.userId }).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });

    if (ar.type === "ACTIVATE") {
      await User.updateOne({ id: user.id }, { $set: { status: "active" } });
      await auditAppend({
        actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
        action: "admin.account_activated",
        details: { userId: user.id, role: user.role },
      });

      if (isSmtpEnabled() && looksLikeEmail(user.email) && !String(user.email).endsWith("@demo.local")) {
        try {
          await sendAccountActivatedEmail({ to: user.email, role: user.role });
        } catch (err) {
          // eslint-disable-next-line no-console
          console.error(err);
        }
      }
    } else if (ar.type === "DELETE") {
      await User.updateOne({ id: user.id }, { $set: { status: "deleted" } });
      await auditAppend({
        actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
        action: "admin.account_deleted",
        details: { userId: user.id, role: user.role },
      });
      if (isSmtpEnabled() && looksLikeEmail(user.email) && !String(user.email).endsWith("@demo.local")) {
        try {
          await sendAccountDeletedEmail({ to: user.email, role: user.role });
        } catch (err) {
          // eslint-disable-next-line no-console
          console.error(err);
        }
      }
    } else {
      return res.status(400).json({ error: "unsupported_request_type", type: ar.type });
    }

    await AccountRequest.updateOne(
      { id },
      { $set: { status: "APPROVED", decidedAtIso: nowIso(), decidedBy: req.auth.sub, note } }
    );

    res.json({ ok: true });
  }));

  app.post("/admin/account-requests/:id/reject", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const id = String(req.params?.id || "").trim();
    const note = isNonEmptyString(req.body?.note) ? String(req.body.note).trim().slice(0, 200) : null;
    const ar = await AccountRequest.findOne({ id }).lean();
    if (!ar) return res.status(404).json({ error: "request_not_found" });
    if (ar.status !== "PENDING") return res.status(409).json({ error: "request_already_decided", status: ar.status });

    await AccountRequest.updateOne(
      { id },
      { $set: { status: "REJECTED", decidedAtIso: nowIso(), decidedBy: req.auth.sub, note } }
    );

    // For activation rejects, block the account to prevent login.
    if (ar.type === "ACTIVATE") {
      await User.updateOne({ id: ar.userId }, { $set: { status: "blocked" } });
      await auditAppend({
        actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
        action: "admin.account_activation_rejected",
        details: { userId: ar.userId, role: ar.role, note },
      });
    } else if (ar.type === "DELETE") {
      await auditAppend({
        actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
        action: "admin.account_delete_rejected",
        details: { userId: ar.userId, role: ar.role, note },
      });
    }

    res.json({ ok: true });
  }));

  // Admin: unlock password reset after OTP lockout
  app.post("/admin/password-reset/unlock", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const { userId, identifier } = req.body || {};
    const id = isNonEmptyString(userId) ? String(userId).trim() : isNonEmptyString(identifier) ? String(identifier).trim() : "";
    if (!isNonEmptyString(id)) return res.status(400).json({ error: "bad_request", message: "userId or identifier required" });

    const user = await User.findOne({ $or: [{ id }, { username: id }, { email: id }] }).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });

    await User.updateOne(
      { id: user.id },
      {
        $set: {
          passwordResetLockedUntil: null,
          passwordResetLockedAt: null,
          passwordResetLockedReason: null,
          passwordResetLockedBy: req.auth.sub,
        },
      }
    );

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
      action: "admin.password_reset_unlocked",
      details: { unlockedUserId: user.id, unlockedUsername: user.username },
    });

    return res.json({ ok: true, userId: user.id, username: user.username });
  }));

  // Admin: reset MFA for a user (used when user forgot BOTH password + email/MFA access)
  app.post("/admin/mfa/reset", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const { userId, identifier } = req.body || {};
    const id = isNonEmptyString(userId) ? String(userId).trim() : isNonEmptyString(identifier) ? String(identifier).trim() : "";
    if (!isNonEmptyString(id)) return res.status(400).json({ error: "bad_request", message: "userId or identifier required" });

    const user = await User.findOne({ $or: [{ id }, { username: id }, { email: id }] }).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });

    await User.updateOne({ id: user.id }, { $set: { mfaEnabled: false, mfaMethod: "NONE" } });
    await TrustedDevice.updateMany({ userId: user.id, revokedAt: null }, { $set: { revokedAt: new Date() } });

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
      action: "admin.mfa_reset",
      details: { targetUserId: user.id, targetRole: user.role, targetUsername: user.username },
    });

    return res.json({ ok: true, userId: user.id, username: user.username, role: user.role });
  }));

  // User: enable per-user MFA (Email OTP) for staff roles (doctor/pharmacy/manufacturer/admin)
  app.post("/mfa/enable", requireAuth, asyncRoute(async (req, res) => {
    const { method, email } = req.body || {};
    const m = isNonEmptyString(method) ? String(method).trim().toUpperCase() : "EMAIL_OTP";
    if (m !== "EMAIL_OTP") return res.status(400).json({ error: "unsupported_mfa_method" });

    const user = await User.findOne({ id: req.auth.sub }).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });
    if (user.role === "patient") {
      // Keep patient-specific verification logic in /patients/enable-mfa
      return res.status(400).json({ error: "use_patient_endpoint", message: "Use POST /patients/enable-mfa for patients." });
    }

    const nextEmail = isNonEmptyString(email) ? String(email).trim().toLowerCase() : null;
    if (nextEmail && !looksLikeEmail(nextEmail)) return res.status(400).json({ error: "bad_request", message: "invalid email" });

    if (isSmtpEnabled()) {
      const effective = nextEmail || user.email;
      if (!looksLikeEmail(effective) || String(effective).endsWith("@demo.local")) {
        return res.status(400).json({
          error: "mfa_email_missing",
          message: "Provide a real email address to enable Email OTP MFA when SMTP is enabled.",
        });
      }
    }

    const update = { mfaEnabled: true, mfaMethod: "EMAIL_OTP" };
    if (nextEmail) update.email = nextEmail;
    await User.updateOne({ id: user.id }, { $set: update });

    await auditAppend({
      actor: { userId: user.id, role: user.role, username: user.username },
      action: "user.mfa_enabled",
      details: { method: "EMAIL_OTP", emailUpdated: Boolean(nextEmail) },
    });

    return res.json({ ok: true, method: "EMAIL_OTP" });
  }));

  // Admin: check SMTP connectivity/auth without sending an email
  app.get("/admin/mail/status", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    if (!isSmtpEnabled()) return res.status(200).json({ ok: false, error: "smtp_not_configured" });
    const verify = await verifySmtpConnection();
    if (!verify.ok) return res.status(200).json({ ok: false, error: verify.error, detail: verify.detail });
    return res.status(200).json({ ok: true });
  }));

  app.post("/patients/verify-clinic-code", asyncRoute(async (req, res) => {
    const { username, patientId, code } = req.body || {};
    if (!isNonEmptyString(code) || (!isNonEmptyString(username) && !isNonEmptyString(patientId))) {
      return res.status(400).json({ error: "bad_request", message: "code + (username or patientId) required" });
    }

    const normalizedCode = String(code).trim().toUpperCase();

    const user = isNonEmptyString(patientId)
      ? await User.findOne({ id: patientId, role: "patient" }).lean()
      : await User.findOne({ username, role: "patient" }).lean();
    if (!user) return res.status(404).json({ error: "patient_not_found" });

    const codeHash = sha256Base64url(`clinic:${normalizedCode}:${JWT_SECRET}`);
    const record = await ClinicCode.findOne({ codeHash }).lean();
    if (!record) {
      return res.status(401).json({
        error: "invalid_code",
        hint: "Check code case (use uppercase) and ensure JWT_SECRET was not changed after issuing the code.",
      });
    }
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
  }));

  // After verification, patient can provision DID + data key
  app.post("/patients/issue-did", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
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
  }));

  app.post("/patients/enable-mfa", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
    const { method, email } = req.body || {};
    const m = isNonEmptyString(method) ? String(method) : "EMAIL_OTP";
    if (m !== "EMAIL_OTP") return res.status(400).json({ error: "unsupported_mfa_method" });
    if (email && !isNonEmptyString(email)) return res.status(400).json({ error: "bad_request", message: "email must be a string" });
    if (email && !looksLikeEmail(email)) return res.status(400).json({ error: "bad_request", message: "invalid email" });

    const profile = await PatientProfile.findOne({ patientId: req.auth.sub }).lean();
    if (!profile || (profile.status !== "ACTIVE" && profile.status !== "VERIFIED")) {
      return res.status(403).json({ error: "patient_not_verified" });
    }

    if (isSmtpEnabled()) {
      const existingUser = await User.findOne({ id: req.auth.sub }).lean();
      const effectiveEmail = looksLikeEmail(email)
        ? String(email).trim().toLowerCase()
        : existingUser?.email;
      if (!looksLikeEmail(effectiveEmail) || String(effectiveEmail).endsWith("@demo.local")) {
        return res.status(400).json({
          error: "mfa_email_missing",
          message: "Provide a real email address to enable Email OTP MFA when SMTP is enabled.",
        });
      }
    }

    const update = { mfaEnabled: true, mfaMethod: "EMAIL_OTP" };
    if (isNonEmptyString(email)) update.email = String(email).trim().toLowerCase();
    await User.updateOne({ id: req.auth.sub }, { $set: update });

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "patient.mfa_enabled",
      details: { method: "EMAIL_OTP", emailUpdated: Boolean(update.email) },
    });

    return res.json({ ok: true, method: "EMAIL_OTP" });
  }));

  // Disable MFA requires email OTP confirmation
  app.post("/patients/disable-mfa/request", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
    const user = await User.findOne({ id: req.auth.sub }).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });
    if (!user.mfaEnabled || user.mfaMethod !== "EMAIL_OTP") {
      return res.status(409).json({ error: "mfa_not_enabled" });
    }
    if (!looksLikeEmail(user.email) || String(user.email).endsWith("@demo.local")) {
      return res.status(400).json({ error: "mfa_email_missing" });
    }
    let otpInfo;
    try {
      otpInfo = await issueOtpRequest({ user, purpose: "MFA_DISABLE", context: { userId: user.id } });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
      return res.status(500).json({ error: "otp_send_failed" });
    }
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "patient.mfa_disable_requested",
      details: { otpRequestId: otpInfo.otpRequestId, delivery: otpInfo.delivery },
    });
    return res.json({ ok: true, otpRequestId: otpInfo.otpRequestId, expiresAt: otpInfo.expiresAt, sentTo: otpInfo.sentTo, delivery: otpInfo.delivery });
  }));

  app.post("/patients/disable-mfa/confirm", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
    const { otpRequestId, otp } = req.body || {};
    if (!isNonEmptyString(otpRequestId) || !isNonEmptyString(otp)) {
      return res.status(400).json({ error: "bad_request", message: "otpRequestId + otp required" });
    }
    const verified = await verifyOtpRequest({ otpRequestId, otp, expectedPurpose: "MFA_DISABLE" });
    if (!verified.ok) return res.status(verified.status).json(verified.body);
    if (verified.request.userId !== req.auth.sub) return res.status(403).json({ error: "forbidden" });

    await User.updateOne({ id: req.auth.sub }, { $set: { mfaEnabled: false, mfaMethod: "NONE" } });
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "patient.mfa_disabled",
      details: {},
    });
    return res.json({ ok: true });
  }));

  app.post("/patients/provision-data-key", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
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
  }));

  // --- Devices (device binding) ---
  const bindDeviceHandler = async (req, res) => {
    const { deviceId, publicKeyPem, fingerprintHash, keyAlg } = req.body || {};
    if (!isNonEmptyString(deviceId) || !isNonEmptyString(publicKeyPem)) {
      return res.status(400).json({ error: "bad_request", message: "deviceId/publicKeyPem required" });
    }
    const alg = isNonEmptyString(keyAlg) ? String(keyAlg) : "Ed25519";
    if (alg !== "Ed25519" && alg !== "ES256") {
      return res.status(400).json({ error: "bad_request", message: "keyAlg must be Ed25519 or ES256" });
    }
    const patientToken = hmacTokenizePatientId(req.auth.sub);

    const exists = await Device.findOne({ deviceId }).lean();
    if (exists) {
      // Idempotent bind for the same patient/device (prevents 409 loops on refresh/re-login).
      if (exists.patientToken !== patientToken) return res.status(409).json({ error: "device_exists" });

      // If already active, just return.
      if (exists.status === "active") {
        return res.status(200).json({ ok: true, deviceId, patientToken, status: "active" });
      }

      // Prevent an attacker from rebinding the same deviceId with a different key.
      const sameAlg = String(exists.keyAlg || "Ed25519") === alg;
      const sameKey = String(exists.publicKeyPem || "").trim() === String(publicKeyPem || "").trim();
      if (!sameAlg || !sameKey) {
        return res.status(409).json({ error: "device_exists_key_mismatch" });
      }

      const nonce = randomId("chal");
      await Device.updateOne(
        { deviceId },
        {
          $set: { challengeNonce: nonce, challengeIssuedAt: new Date(), lastSeenAt: new Date() },
        }
      );
      return res.status(200).json({
        ok: true,
        deviceId,
        patientToken,
        status: "pending",
        challenge: { deviceId, nonce },
        next: "auth/device-verify",
      });
    }

    const nonce = randomId("chal");
    await Device.create({
      deviceId,
      patientToken,
      keyAlg: alg,
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

  app.post("/patients/bind-device", requireAuth, requireRole(["patient"]), asyncRoute(bindDeviceHandler));
  app.post("/devices/register", requireAuth, requireRole(["patient"]), bindDeviceHandler);

  app.post("/auth/device-challenge", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
    const { deviceId } = req.body || {};
    if (!isNonEmptyString(deviceId)) return res.status(400).json({ error: "bad_request", message: "deviceId required" });
    const patientToken = hmacTokenizePatientId(req.auth.sub);
    const device = await Device.findOne({ deviceId, patientToken }).lean();
    if (!device) return res.status(404).json({ error: "device_not_found" });
    if (device.status === "active") return res.json({ ok: true, deviceId, status: "active" });
    const nonce = randomId("chal");
    await Device.updateOne({ deviceId }, { $set: { challengeNonce: nonce, challengeIssuedAt: new Date() } });
    return res.json({ ok: true, challenge: { deviceId, nonce } });
  }));

  app.post("/auth/device-verify", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
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
    const ok =
      device.keyAlg === "ES256"
        ? verifyObjectEs256({ obj: challengePayload, signatureB64url, publicKeyPem: device.publicKeyPem })
        : verifyObjectEd25519({ obj: challengePayload, signatureB64url, publicKeyPem: device.publicKeyPem });
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
  }));

  // --- Vitals upload ---
  app.post("/vitals/upload", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
    const { deviceId, payload, signatureB64url } = req.body || {};
    if (!isNonEmptyString(deviceId) || !payload || !isNonEmptyString(signatureB64url)) {
      return res.status(400).json({ error: "bad_request", message: "deviceId/payload/signatureB64url required" });
    }

    const patientToken = hmacTokenizePatientId(req.auth.sub);
    const device = await Device.findOne({ deviceId, patientToken, status: "active" }).lean();
    if (!device) return res.status(403).json({ error: "device_not_bound" });

    const ok =
      device.keyAlg === "ES256"
        ? verifyObjectEs256({ obj: payload, signatureB64url, publicKeyPem: device.publicKeyPem })
        : verifyObjectEd25519({ obj: payload, signatureB64url, publicKeyPem: device.publicKeyPem });
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
  }));

  // --- Vitals read (doctor; ABAC + break-glass) ---
  app.get("/vitals/:patientToken", requireAuth, requireRole(["doctor"]), asyncRoute(async (req, res) => {
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
  }));

  // --- Prescriptions ---
  app.post("/prescriptions", requireAuth, requireRole(["doctor"]), asyncRoute(async (req, res) => {
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

    // Best-effort patient notification (email). Dashboard remains source of truth.
    let notification = { attempted: false, delivery: "none", sentTo: null };
    if (RX_EMAIL_NOTIFICATIONS && isSmtpEnabled()) {
      const patientEmail =
        looksLikeEmail(patient.email) && !String(patient.email).endsWith("@demo.local")
          ? String(patient.email).trim().toLowerCase()
          : null;
      if (patientEmail) {
        notification.attempted = true;
        try {
          await sendPrescriptionIssuedEmail({ to: patientEmail, doctorUsername: doctor.username, rx });
          notification = { attempted: true, delivery: "email", sentTo: patientEmail };
          await auditAppend({
            actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
            action: "rx.patient_notified",
            details: { rxId: rx.id, sentTo: patientEmail },
          });
        } catch (err) {
          // eslint-disable-next-line no-console
          console.error(err);
          notification = { attempted: true, delivery: "failed", sentTo: patientEmail };
          await auditAppend({
            actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
            action: "rx.patient_notify_failed",
            details: { rxId: rx.id, sentTo: patientEmail, error: String(err?.message || "send_failed").slice(0, 200) },
          });
        }
      }
    }

    return res.status(201).json({ ...rx, notification });
  }));

  app.post("/prescriptions/verify", asyncRoute(async (req, res) => {
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
  }));

  // --- Batches ---
  app.post("/batches", requireAuth, requireRole(["manufacturer"]), asyncRoute(async (req, res) => {
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
  }));

  app.post("/batches/verify", asyncRoute(async (req, res) => {
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
  }));

  // --- Dispense ---
  app.post("/dispense", requireAuth, requireRole(["pharmacy"]), requirePharmacyBiometric, asyncRoute(async (req, res) => {
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
  }));

  // --- Audit viewer ---
  app.get("/audit/logs", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const { patientId, patientToken, action, userId, username } = req.query || {};
    const filter = {};
    if (isNonEmptyString(action)) filter.action = String(action);

    const or = [];
    if (isNonEmptyString(userId)) {
      or.push({ "actor.userId": String(userId) });
      or.push({ "actor.patientId": String(userId) });
    }
    if (isNonEmptyString(username)) {
      // Some events use actor.username, others use actor.identifier (e.g., failed logins).
      or.push({ "actor.username": String(username) });
      or.push({ "actor.identifier": String(username) });
    }

    if (isNonEmptyString(patientId)) {
      // best-effort filter by patient token inside audit details
      const token = hmacTokenizePatientId(String(patientId));
      or.push(
        { "actor.userId": String(patientId) },
        { "actor.patientId": String(patientId) },
        { "details.patientToken": token },
      );
    } else if (isNonEmptyString(patientToken)) {
      filter["details.patientToken"] = String(patientToken);
    }

    if (or.length > 0) filter.$or = or;

    const entries = await AuditEntry.find(filter).sort({ ts: -1 }).limit(200).lean();
    res.json({ count: entries.length, entries });
  }));

  // --- Analytics / Fraud management (admin) ---
  app.get("/analytics/summary", requireAuth, requireRole(["admin"]), asyncRoute(async (req, res) => {
    const windowHours = clampInt(req.query?.windowHours, { min: 1, max: 24 * 30, fallback: 24 });
    const bucketMinutes = clampInt(req.query?.bucketMinutes, { min: 5, max: 60, fallback: 60 });
    const bucketMs = bucketMinutes * 60 * 1000;
    const maxEntries = clampInt(req.query?.maxEntries, { min: 200, max: 20000, fallback: 5000 });

    const to = new Date();
    const from = new Date(Date.now() - windowHours * 60 * 60 * 1000);
    const fromIso = from.toISOString();
    const toIso = to.toISOString();

    const entries = await AuditEntry.find(
      { ts: { $gte: fromIso, $lte: toIso } },
      { _id: 0, __v: 0 }
    )
      .sort({ ts: 1 })
      .limit(maxEntries)
      .lean();

	    const ACTION_WEIGHTS = {
	      "auth.login_failed": 3,
	      "auth.login_blocked": 6,
	      "auth.otp_verify_failed": 2,
	      "anomaly.otp_failed_multiple": 8,
	      "auth.password_reset_requested": 4,
	      "auth.password_reset_locked": 10,
	      "anomaly.password_reset_rate_limited": 12,
	      "anomaly.password_reset_new_device": 8,
	      "auth.new_device_magic_link_sent": 5,
	      "auth.step_up_new_device_otp_issued": 5,
	      "clinic.code_issued": 3,
	      "patient.device_bind_failed": 4,
	      "dispense.blocked": 8,
	      "vitals.upload_rejected": 6,
	      "vitals.read_break_glass": 12,
	    };

	    const actionCounts = new Map();
	    const identifierRisk = new Map(); // identifier -> { score, counts }
	    const userRisk = new Map(); // userId -> { score, counts, reasons:Set }
	    const alerts = [];

	    const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
	    const normalizeSeverity = (s) => (s in SEVERITY_RANK ? s : "info");
	    const pushAlert = ({ ts, severity, type, title, actor, details }) => {
	      if (alerts.length >= 600) return;
	      const a = {
	        ts: isNonEmptyString(ts) ? String(ts) : nowIso(),
	        severity: normalizeSeverity(String(severity || "info")),
	        type: isNonEmptyString(type) ? String(type).slice(0, 64) : "unknown",
	        title: isNonEmptyString(title) ? String(title).slice(0, 160) : "Suspicious activity",
	        actor: actor && typeof actor === "object" ? actor : {},
	        details: details && typeof details === "object" ? details : {},
	      };
	      alerts.push(a);
	    };

	    const maskIp = (ip) => {
	      if (!isNonEmptyString(ip)) return null;
	      const s = String(ip).trim();
	      if (s.includes(".")) {
	        const p = s.split(".");
	        if (p.length === 4) return `${p[0]}.${p[1]}.${p[2]}.x`;
	      }
	      if (s.includes(":")) {
	        const p = s.split(":").filter(Boolean);
	        return `${p.slice(0, 3).join(":")}:…`;
	      }
	      return `${s.slice(0, 8)}…`;
	    };

	    const initBucket = (key) => ({
	      bucketStart: key,
	      total: 0,
	      loginFailed: 0,
	      loginSuccess: 0,
	      loginBlocked: 0,
	      otpIssued: 0,
	      otpVerified: 0,
	      otpResent: 0,
	      otpVerifyFailed: 0,
	      passwordResetRequested: 0,
	      passwordResetOtpVerified: 0,
	      passwordResetCompleted: 0,
	      passwordResetLocked: 0,
	      magicLinkSent: 0,
	      magicLinkConsumed: 0,
	      newDeviceStepUpIssued: 0,
	      newDeviceStepUpVerified: 0,
	      trustedDeviceAdded: 0,
	      trustedDeviceRemoveRequested: 0,
	      trustedDeviceRevoked: 0,
	      clinicCodeIssued: 0,
	      patientVerificationCodeIssued: 0,
	      patientVerified: 0,
	      deviceBindRequested: 0,
	      deviceBound: 0,
	      deviceBindFailed: 0,
	      vitalsRead: 0,
	      vitalsReadBreakGlass: 0,
	      vitalsUploaded: 0,
	      vitalsUploadRejected: 0,
	      dispenseAllowed: 0,
	      dispenseBlocked: 0,
	      patientPreRegister: 0,
	      appointmentCreated: 0,
	      rxCreated: 0,
	      batchRegistered: 0,
	      biometricEnrolled: 0,
	      biometricVerified: 0,
	      pharmacistRegistered: 0,
	      anomalies: 0,
	    });

    const fromMs = Date.parse(fromIso);
    const toMs = Date.parse(toIso);
    const startMs = floorToBucketMs(fromMs, bucketMs);
    const endMs = floorToBucketMs(toMs, bucketMs);
    const seriesMap = new Map();
    if (startMs !== null && endMs !== null) {
      for (let t = startMs; t <= endMs; t += bucketMs) {
        const key = new Date(t).toISOString();
        seriesMap.set(key, initBucket(key));
      }
    }

	    const addUserRisk = ({ userId, action, entry, extraWeight = 0, reason = null }) => {
	      if (!isNonEmptyString(userId)) return;
	      const key = String(userId);
	      const rec = userRisk.get(key) || { userId: key, score: 0, counts: {}, reasons: new Set(), lastTs: null };
	      const base = ACTION_WEIGHTS[action] || (String(action).startsWith("anomaly.") ? 10 : 0);
	      const w = base + (safeNumber(extraWeight) ?? 0);
	      if (w !== 0) rec.score += w;
	      rec.counts[action] = (rec.counts[action] || 0) + 1;
	      if (isNonEmptyString(entry?.ts)) rec.lastTs = String(entry.ts);
	      if (reason) rec.reasons.add(String(reason).slice(0, 160));
	      const detailReason = entry?.details?.reason;
	      if (isNonEmptyString(detailReason)) rec.reasons.add(String(detailReason).slice(0, 160));
	      userRisk.set(key, rec);
	    };

	    const addIdentifierRisk = ({ identifier, action }) => {
	      if (!isNonEmptyString(identifier)) return;
	      const key = String(identifier).trim();
	      const rec = identifierRisk.get(key) || { identifier: key, score: 0, counts: {}, lastTs: null };
	      const base = ACTION_WEIGHTS[action] || (String(action).startsWith("anomaly.") ? 10 : 0);
	      rec.score += base;
	      rec.counts[action] = (rec.counts[action] || 0) + 1;
	      identifierRisk.set(key, rec);
	    };

	    const buildAlertActor = (e) => {
	      const actor = e?.actor || {};
	      const out = {};
	      if (isNonEmptyString(actor.userId)) out.userId = String(actor.userId);
	      if (isNonEmptyString(actor.username)) out.username = String(actor.username);
	      if (isNonEmptyString(actor.role)) out.role = String(actor.role);
	      if (isNonEmptyString(actor.identifier)) out.identifier = String(actor.identifier);
	      return out;
	    };

	    for (const e of entries) {
	      const action = String(e.action || "");
	      actionCounts.set(action, (actionCounts.get(action) || 0) + 1);

      const tsMs = Date.parse(String(e.ts || ""));
      const bMs = floorToBucketMs(tsMs, bucketMs);
      const bKey = bMs !== null ? new Date(bMs).toISOString() : null;
      const bucket = bKey ? (seriesMap.get(bKey) || initBucket(bKey)) : null;
	      if (bucket && bKey && !seriesMap.has(bKey)) seriesMap.set(bKey, bucket);
	      if (bucket) bucket.total += 1;

	      if (action === "auth.login_failed") {
	        if (bucket) bucket.loginFailed += 1;
	        addIdentifierRisk({ identifier: e.actor?.identifier, action });
	        const ident = isNonEmptyString(e.actor?.identifier) ? String(e.actor.identifier).trim() : null;
	        if (ident) {
	          const rec = identifierRisk.get(ident);
	          if (rec) rec.lastTs = isNonEmptyString(e.ts) ? String(e.ts) : rec.lastTs;
	        }
	      }
	      if (action === "auth.login_success") {
	        if (bucket) bucket.loginSuccess += 1;
	      }
	      if (action === "auth.login_blocked") {
	        if (bucket) bucket.loginBlocked += 1;
	      }
	      if (action === "auth.otp_issued") {
	        if (bucket) bucket.otpIssued += 1;
	      }
	      if (action === "auth.otp_verified") {
	        if (bucket) bucket.otpVerified += 1;
	      }
	      if (action === "auth.otp_resent") {
	        if (bucket) bucket.otpResent += 1;
	      }
	      if (action === "auth.otp_verify_failed") {
	        if (bucket) bucket.otpVerifyFailed += 1;
	      }
	      if (action === "auth.password_reset_requested") {
	        if (bucket) bucket.passwordResetRequested += 1;
	      }
	      if (action === "auth.password_reset_otp_verified") {
	        if (bucket) bucket.passwordResetOtpVerified += 1;
	      }
	      if (action === "auth.password_reset_completed") {
	        if (bucket) bucket.passwordResetCompleted += 1;
	      }
	      if (action === "auth.password_reset_locked") {
	        if (bucket) bucket.passwordResetLocked += 1;
	      }
	      if (action === "auth.new_device_magic_link_sent" || action === "auth.step_up_new_device_otp_issued") {
	        if (bucket) bucket.newDeviceStepUpIssued += 1;
	      }
	      if (action === "auth.new_device_magic_link_sent") {
	        if (bucket) bucket.magicLinkSent += 1;
	      }
	      if (action === "auth.new_device_magic_link_consumed") {
	        if (bucket) bucket.magicLinkConsumed += 1;
	        if (bucket) bucket.newDeviceStepUpVerified += 1;
	      }
	      if (action === "auth.step_up_new_device_verified") {
	        if (bucket) bucket.newDeviceStepUpVerified += 1;
	      }
	      if (action === "auth.trusted_device_added") {
	        if (bucket) bucket.trustedDeviceAdded += 1;
	      }
	      if (action === "auth.trusted_device_remove_requested") {
	        if (bucket) bucket.trustedDeviceRemoveRequested += 1;
	      }
	      if (action === "auth.trusted_device_revoked") {
	        if (bucket) bucket.trustedDeviceRevoked += 1;
	      }
	      if (action === "clinic.code_issued") {
	        if (bucket) bucket.clinicCodeIssued += 1;
	      }
	      if (action === "patient.verification_code_issued") {
	        if (bucket) bucket.patientVerificationCodeIssued += 1;
	      }
	      if (action === "patient.verified") {
	        if (bucket) bucket.patientVerified += 1;
	      }
	      if (action === "patient.device_bind_requested") {
	        if (bucket) bucket.deviceBindRequested += 1;
	      }
	      if (action === "patient.device_bound") {
	        if (bucket) bucket.deviceBound += 1;
	      }
	      if (action === "patient.device_bind_failed") {
	        if (bucket) bucket.deviceBindFailed += 1;
	      }
	      if (action === "vitals.read") {
	        if (bucket) bucket.vitalsRead += 1;
	      }
	      if (action === "vitals.read_break_glass") {
	        if (bucket) bucket.vitalsReadBreakGlass += 1;
	      }
	      if (action === "vitals.upload") {
	        if (bucket) bucket.vitalsUploaded += 1;
	      }
	      if (action === "vitals.upload_rejected") {
	        if (bucket) bucket.vitalsUploadRejected += 1;
	      }
	      if (action === "dispense.allowed") {
	        if (bucket) bucket.dispenseAllowed += 1;
	      }
	      if (action === "dispense.blocked") {
	        if (bucket) bucket.dispenseBlocked += 1;
	      }
	      if (action === "patient.pre_register") {
	        if (bucket) bucket.patientPreRegister += 1;
	      }
	      if (action === "appointment.created") {
	        if (bucket) bucket.appointmentCreated += 1;
	      }
	      if (action === "rx.create") {
	        if (bucket) bucket.rxCreated += 1;
	      }
	      if (action === "batch.register") {
	        if (bucket) bucket.batchRegistered += 1;
	      }
	      if (action === "biometric.enrolled") {
	        if (bucket) bucket.biometricEnrolled += 1;
	      }
	      if (action === "biometric.verified") {
	        if (bucket) bucket.biometricVerified += 1;
	      }
	      if (action === "pharmacist.registered") {
	        if (bucket) bucket.pharmacistRegistered += 1;
	      }
	      if (action.startsWith("anomaly.")) {
	        if (bucket) bucket.anomalies += 1;
	      }

	      if (action.startsWith("anomaly.")) {
	        const det = e.details || {};
	        const ip = isNonEmptyString(det.ip) ? maskIp(det.ip) : null;
	        pushAlert({
	          ts: e.ts,
	          severity: action === "anomaly.password_reset_rate_limited" ? "high" : "medium",
	          type: action,
	          title: `Anomaly detected: ${action}`,
	          actor: buildAlertActor(e),
	          details: {
	            reason: isNonEmptyString(det.reason) ? String(det.reason).slice(0, 160) : null,
	            ipReuseCount: safeNumber(det.ipReuseCount),
	            countLastHour: safeNumber(det.countLastHour),
	            deviceId: looksLikeDeviceId(det.deviceId) ? String(det.deviceId) : null,
	            ip,
	          },
	        });
	      }

	      if (action === "auth.password_reset_locked") {
	        pushAlert({
	          ts: e.ts,
	          severity: "high",
	          type: action,
	          title: "Password reset locked (OTP attempts exceeded)",
	          actor: buildAlertActor(e),
	          details: { otpRequestId: isNonEmptyString(e.details?.otpRequestId) ? String(e.details.otpRequestId) : null },
	        });
	      }

	      if (action === "dispense.blocked") {
	        pushAlert({
	          ts: e.ts,
	          severity: "critical",
	          type: action,
	          title: "Dispense blocked (integrity/provenance failure)",
	          actor: buildAlertActor(e),
	          details: {
	            recordId: isNonEmptyString(e.details?.recordId) ? String(e.details.recordId) : null,
	            rxId: isNonEmptyString(e.details?.rxId) ? String(e.details.rxId) : null,
	            batchId: isNonEmptyString(e.details?.batchId) ? String(e.details.batchId) : null,
	          },
	        });
	      }

	      if (action === "patient.device_bind_failed") {
	        pushAlert({
	          ts: e.ts,
	          severity: "medium",
	          type: action,
	          title: "Device binding failed (bad signature)",
	          actor: buildAlertActor(e),
	          details: {
	            deviceId: looksLikeDeviceId(e.details?.deviceId) ? String(e.details.deviceId) : null,
	            reason: isNonEmptyString(e.details?.reason) ? String(e.details.reason).slice(0, 160) : null,
	          },
	        });
	      }

	      if (action === "vitals.upload_rejected") {
	        pushAlert({
	          ts: e.ts,
	          severity: "high",
	          type: action,
	          title: "Vitals upload rejected (bad signature)",
	          actor: buildAlertActor(e),
	          details: {
	            deviceId: looksLikeDeviceId(e.details?.deviceId) ? String(e.details.deviceId) : null,
	            reason: isNonEmptyString(e.details?.reason) ? String(e.details.reason).slice(0, 160) : null,
	          },
	        });
	      }

	      if (action === "vitals.read_break_glass") {
	        pushAlert({
	          ts: e.ts,
	          severity: "high",
	          type: action,
	          title: "Break-glass vitals access",
	          actor: buildAlertActor(e),
	          details: {
	            patientToken: isNonEmptyString(e.details?.patientToken) ? String(e.details.patientToken) : null,
	            returned: safeNumber(e.details?.returned),
	          },
	        });
	      }

	      const actorUserId =
	        (isNonEmptyString(e.actor?.userId) && String(e.actor.userId)) ||
	        (isNonEmptyString(e.actor?.patientId) && String(e.actor.patientId)) ||
	        (isNonEmptyString(e.details?.patientId) && String(e.details.patientId)) ||
        (isNonEmptyString(e.details?.pharmacistId) && String(e.details.pharmacistId)) ||
        (isNonEmptyString(e.details?.unlockedUserId) && String(e.details.unlockedUserId)) ||
        null;

      let extra = 0;
      let reason = null;
      if (action === "patient.pre_register") {
        const trustScore = safeNumber(e.details?.trustScore);
        if (trustScore !== null && trustScore < 50) {
          extra += 6;
          reason = `low_trust_score:${trustScore}`;
        }
        const ipReuse = safeNumber(e.details?.ipReuseCount);
        if (ipReuse !== null && ipReuse >= 3) {
          extra += 4;
          reason = reason ? `${reason}, ip_reuse:${ipReuse}` : `ip_reuse:${ipReuse}`;
        }
      }

      addUserRisk({ userId: actorUserId, action, entry: e, extraWeight: extra, reason });
    }

    const topActions = [...actionCounts.entries()]
      .map(([action, count]) => ({ action, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);

    const series = [...seriesMap.values()].sort((a, b) => String(a.bucketStart).localeCompare(String(b.bucketStart)));

    const riskyUsersRaw = [...userRisk.values()]
      .map((r) => ({ ...r, reasons: [...r.reasons] }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 20);

	    const riskyIds = [...identifierRisk.values()]
	      .sort((a, b) => b.score - a.score)
	      .slice(0, 20);

	    // Aggregate alerts (threshold-based)
	    for (const r of riskyIds) {
	      const fails = safeNumber(r.counts?.["auth.login_failed"]) ?? 0;
	      if (fails >= 10) {
	        pushAlert({
	          ts: isNonEmptyString(r.lastTs) ? r.lastTs : toIso,
	          severity: fails >= 20 ? "high" : "medium",
	          type: "bruteforce.identifier",
	          title: `Repeated login failures for "${String(r.identifier).slice(0, 64)}"`,
	          actor: { identifier: r.identifier },
	          details: { loginFailed: fails, windowHours },
	        });
	      }
	    }

	    for (const u of userRisk.values()) {
	      const otpFails = safeNumber(u.counts?.["auth.otp_verify_failed"]) ?? 0;
	      if (otpFails >= 5) {
	        pushAlert({
	          ts: isNonEmptyString(u.lastTs) ? u.lastTs : toIso,
	          severity: otpFails >= 10 ? "high" : "medium",
	          type: "otp.abuse",
	          title: "Multiple OTP verification failures",
	          actor: { userId: u.userId },
	          details: { otpVerifyFailed: otpFails, windowHours },
	        });
	      }

	      const bindFails = safeNumber(u.counts?.["patient.device_bind_failed"]) ?? 0;
	      if (bindFails >= 3) {
	        pushAlert({
	          ts: isNonEmptyString(u.lastTs) ? u.lastTs : toIso,
	          severity: bindFails >= 6 ? "high" : "medium",
	          type: "device.bind_failures",
	          title: "Repeated device binding failures",
	          actor: { userId: u.userId },
	          details: { deviceBindFailed: bindFails, windowHours },
	        });
	      }

	      const blockedDispense = safeNumber(u.counts?.["dispense.blocked"]) ?? 0;
	      if (blockedDispense >= 2) {
	        pushAlert({
	          ts: isNonEmptyString(u.lastTs) ? u.lastTs : toIso,
	          severity: blockedDispense >= 5 ? "critical" : "high",
	          type: "dispense.blocked_repeated",
	          title: "Repeated blocked dispense attempts",
	          actor: { userId: u.userId },
	          details: { dispenseBlocked: blockedDispense, windowHours },
	        });
	      }

	      const breakGlass = safeNumber(u.counts?.["vitals.read_break_glass"]) ?? 0;
	      if (breakGlass >= 1) {
	        pushAlert({
	          ts: isNonEmptyString(u.lastTs) ? u.lastTs : toIso,
	          severity: breakGlass >= 3 ? "critical" : "high",
	          type: "vitals.break_glass",
	          title: "Break-glass vitals access observed",
	          actor: { userId: u.userId },
	          details: { breakGlassReads: breakGlass, windowHours },
	        });
	      }
	    }

	    const riskUserIds = riskyUsersRaw.map((r) => r.userId);
	    const users = riskUserIds.length
	      ? await User.find(
          { id: { $in: riskUserIds } },
          { _id: 0, id: 1, username: 1, role: 1, status: 1, passwordResetLockedAt: 1, passwordResetLockedReason: 1 }
        ).lean()
      : [];
    const userById = new Map(users.map((u) => [u.id, u]));
    const riskyUsers = riskyUsersRaw.map((r) => {
      const u = userById.get(r.userId) || null;
      return {
        userId: r.userId,
        username: u?.username || null,
        role: u?.role || null,
        status: u?.status || null,
        passwordResetLockedAt: u?.passwordResetLockedAt ? new Date(u.passwordResetLockedAt).toISOString() : null,
        passwordResetLockedReason: u?.passwordResetLockedReason || null,
        score: r.score,
        counts: r.counts,
        reasons: r.reasons,
      };
    });

    const lockedUsers = await User.find(
      { passwordResetLockedAt: { $ne: null } },
      { _id: 0, id: 1, username: 1, role: 1, status: 1, passwordResetLockedAt: 1, passwordResetLockedReason: 1 }
    )
      .sort({ passwordResetLockedAt: -1 })
      .limit(50)
      .lean();

	    const totals = series.reduce(
	      (acc, b) => {
	        acc.events += b.total;
	        acc.loginFailed += b.loginFailed;
	        acc.loginSuccess += b.loginSuccess;
	        acc.loginBlocked += b.loginBlocked;
	        acc.otpIssued += b.otpIssued;
	        acc.otpVerified += b.otpVerified;
	        acc.otpResent += b.otpResent;
	        acc.otpVerifyFailed += b.otpVerifyFailed;
	        acc.passwordResetRequested += b.passwordResetRequested;
	        acc.passwordResetOtpVerified += b.passwordResetOtpVerified;
	        acc.passwordResetCompleted += b.passwordResetCompleted;
	        acc.passwordResetLocked += b.passwordResetLocked;
	        acc.magicLinkSent += b.magicLinkSent;
	        acc.magicLinkConsumed += b.magicLinkConsumed;
	        acc.newDeviceStepUpIssued += b.newDeviceStepUpIssued;
	        acc.newDeviceStepUpVerified += b.newDeviceStepUpVerified;
	        acc.trustedDeviceAdded += b.trustedDeviceAdded;
	        acc.trustedDeviceRemoveRequested += b.trustedDeviceRemoveRequested;
	        acc.trustedDeviceRevoked += b.trustedDeviceRevoked;
	        acc.clinicCodeIssued += b.clinicCodeIssued;
	        acc.patientVerificationCodeIssued += b.patientVerificationCodeIssued;
	        acc.patientVerified += b.patientVerified;
	        acc.deviceBindRequested += b.deviceBindRequested;
	        acc.deviceBound += b.deviceBound;
	        acc.deviceBindFailed += b.deviceBindFailed;
	        acc.vitalsRead += b.vitalsRead;
	        acc.vitalsReadBreakGlass += b.vitalsReadBreakGlass;
	        acc.vitalsUploaded += b.vitalsUploaded;
	        acc.vitalsUploadRejected += b.vitalsUploadRejected;
	        acc.dispenseAllowed += b.dispenseAllowed;
	        acc.dispenseBlocked += b.dispenseBlocked;
	        acc.patientPreRegister += b.patientPreRegister;
	        acc.appointmentCreated += b.appointmentCreated;
	        acc.rxCreated += b.rxCreated;
	        acc.batchRegistered += b.batchRegistered;
	        acc.biometricEnrolled += b.biometricEnrolled;
	        acc.biometricVerified += b.biometricVerified;
	        acc.pharmacistRegistered += b.pharmacistRegistered;
	        acc.anomalies += b.anomalies;
	        return acc;
	      },
	      {
	        events: 0,
	        loginFailed: 0,
	        loginSuccess: 0,
	        loginBlocked: 0,
	        otpIssued: 0,
	        otpVerified: 0,
	        otpResent: 0,
	        otpVerifyFailed: 0,
	        passwordResetRequested: 0,
	        passwordResetOtpVerified: 0,
	        passwordResetCompleted: 0,
	        passwordResetLocked: 0,
	        magicLinkSent: 0,
	        magicLinkConsumed: 0,
	        newDeviceStepUpIssued: 0,
	        newDeviceStepUpVerified: 0,
	        trustedDeviceAdded: 0,
	        trustedDeviceRemoveRequested: 0,
	        trustedDeviceRevoked: 0,
	        clinicCodeIssued: 0,
	        patientVerificationCodeIssued: 0,
	        patientVerified: 0,
	        deviceBindRequested: 0,
	        deviceBound: 0,
	        deviceBindFailed: 0,
	        vitalsRead: 0,
	        vitalsReadBreakGlass: 0,
	        vitalsUploaded: 0,
	        vitalsUploadRejected: 0,
	        dispenseAllowed: 0,
	        dispenseBlocked: 0,
	        patientPreRegister: 0,
	        appointmentCreated: 0,
	        rxCreated: 0,
	        batchRegistered: 0,
	        biometricEnrolled: 0,
	        biometricVerified: 0,
	        pharmacistRegistered: 0,
	        anomalies: 0,
	      }
	    );

	    const alertsOut = alerts
	      .sort((a, b) => {
	        const s = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
	        if (s !== 0) return s;
	        return String(b.ts).localeCompare(String(a.ts));
	      })
	      .slice(0, 50);

	    const alertTotals = alertsOut.reduce(
	      (acc, a) => {
	        acc.total += 1;
	        acc.bySeverity[a.severity] = (acc.bySeverity[a.severity] || 0) + 1;
	        return acc;
	      },
	      { total: 0, bySeverity: {} }
	    );

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
      action: "analytics.summary_viewed",
      details: { windowHours, bucketMinutes, returnedEntries: entries.length },
    });

    res.json({
      ok: true,
      windowHours,
      bucketMinutes,
      from: fromIso,
      to: toIso,
      counts: { entries: entries.length, maxEntries },
      totals,
      topActions,
      series,
      riskyUsers,
	      riskyIdentifiers: riskyIds,
	      lockedUsers: lockedUsers.map((u) => ({
	        userId: u.id,
	        username: u.username,
	        role: u.role,
	        status: u.status,
	        lockedAt: u.passwordResetLockedAt ? new Date(u.passwordResetLockedAt).toISOString() : null,
	        reason: u.passwordResetLockedReason || null,
	      })),
	      alerts: alertsOut,
	      alertTotals,
	    });
	  }));

  // --- Helpful demo data endpoints (read-only, authenticated) ---
  // Current user (DB-backed)
  app.get("/me", requireAuth, asyncRoute(async (req, res) => {
    const user = await User.findOne(
      { id: req.auth.sub },
      { _id: 0, id: 1, username: 1, email: 1, role: 1, status: 1, mfaEnabled: 1, mfaMethod: 1, biometricEnrolled: 1, biometricEnrolledAt: 1 }
    ).lean();
    if (!user) return res.status(404).json({ error: "user_not_found" });
    return res.json({ user });
  }));

  app.get("/demo/whoami", requireAuth, asyncRoute(async (req, res) => {
    res.json({ auth: req.auth });
  }));

  app.get("/demo/users", requireAuth, asyncRoute(async (req, res) => {
    // Minimal exposure for demo UI
    const users = await User.find({}, { _id: 0, id: 1, username: 1, role: 1, status: 1 }).lean();
    res.json({ users });
  }));

  // --- Doctors + Appointments ---
  app.get("/doctors", requireAuth, asyncRoute(async (req, res) => {
    const doctors = await User.find(
      { role: "doctor", status: "active" },
      { _id: 0, id: 1, username: 1, role: 1, status: 1 }
    )
      .sort({ username: 1 })
      .lean();
    res.json({ count: doctors.length, doctors });
  }));

  app.post("/appointments", requireAuth, requireRole(["patient"]), requireCsrf, asyncRoute(async (req, res) => {
    const { doctorId, appointmentDate, appointmentTime, notes } = req.body || {};
    if (!isNonEmptyString(doctorId) || !looksLikeIsoDate(appointmentDate) || !looksLikeTimeHHMM(appointmentTime)) {
      return res.status(400).json({ error: "bad_request", message: "doctorId + appointmentDate(YYYY-MM-DD) + appointmentTime(HH:MM) required" });
    }

    const doctor = await User.findOne({ id: String(doctorId).trim(), role: "doctor", status: "active" }).lean();
    if (!doctor) return res.status(404).json({ error: "doctor_not_found" });

    const patientToken = hmacTokenizePatientId(req.auth.sub);
    const did = getRequestDeviceId(req);
    const core = {
      patientId: req.auth.sub,
      doctorId: doctor.id,
      appointmentDate: String(appointmentDate).trim(),
      appointmentTime: String(appointmentTime).trim(),
      notes: isNonEmptyString(notes) ? String(notes).trim().slice(0, 500) : null,
      status: "scheduled",
    };
    const integrityHash = computeIntegrityHash({ prefix: "appointment", obj: core });

    const record = {
      id: randomId("apt"),
      ...core,
      patientToken,
      requestedDeviceId: did,
      requestedIp: String(getClientIp(req)).slice(0, 128),
      integrityHash,
      createdAt: nowIso(),
    };

    await Appointment.create(record);
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
      action: "appointment.created",
      details: { appointmentId: record.id, doctorId: record.doctorId, appointmentDate: record.appointmentDate, appointmentTime: record.appointmentTime },
    });

    return res.status(201).json({
      id: record.id,
      doctorId: record.doctorId,
      appointmentDate: record.appointmentDate,
      appointmentTime: record.appointmentTime,
      notes: record.notes,
      status: record.status,
      createdAt: record.createdAt,
      integrityHash: record.integrityHash,
    });
  }));

  app.get("/appointments", requireAuth, requireRole(["patient"]), asyncRoute(async (req, res) => {
    const appointments = await Appointment.find(
      { patientId: req.auth.sub },
      { _id: 0, __v: 0, patientId: 0, patientToken: 0, requestedIp: 0 }
    )
      .sort({ appointmentDate: -1, appointmentTime: -1, createdAt: -1 })
      .limit(100)
      .lean();
    res.json({ count: appointments.length, appointments });
  }));

  // Doctor: view appointments assigned to them
  app.get("/doctor/appointments", requireAuth, requireRole(["doctor"]), asyncRoute(async (req, res) => {
    const status = isNonEmptyString(req.query?.status) ? String(req.query.status).trim() : null;
    const date = isNonEmptyString(req.query?.date) ? String(req.query.date).trim() : null;
    if (date && !looksLikeIsoDate(date)) {
      return res.status(400).json({ error: "bad_request", message: "date must be YYYY-MM-DD" });
    }
    const filter = {
      doctorId: req.auth.sub,
      ...(status ? { status } : {}),
      ...(date ? { appointmentDate: date } : {}),
    };

    const appointments = await Appointment.find(
      filter,
      { _id: 0, __v: 0, requestedIp: 0, patientToken: 0, integrityHash: 0 }
    )
      .sort({ appointmentDate: -1, appointmentTime: -1, createdAt: -1 })
      .limit(200)
      .lean();

    const patientIds = [...new Set(appointments.map((a) => a.patientId))];
    const patients = await User.find(
      { id: { $in: patientIds }, role: "patient" },
      { _id: 0, id: 1, username: 1, email: 1, status: 1 }
    ).lean();
    const patientById = new Map(patients.map((p) => [p.id, p]));

    const out = appointments.map((a) => ({
      ...a,
      patient: patientById.get(a.patientId) ? { id: a.patientId, username: patientById.get(a.patientId).username } : { id: a.patientId, username: null },
    }));

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role, username: req.auth.username },
      action: "appointment.doctor_list",
      details: { returned: out.length, status: status || null, date: date || null },
    });

    res.json({ count: out.length, appointments: out });
  }));

  // Doctor: patient search (used by UI)
  app.get("/doctors/patients/search", requireAuth, requireRole(["doctor"]), asyncRoute(async (req, res) => {
    const q = isNonEmptyString(req.query?.query) ? String(req.query.query).trim() : "";
    if (q.length < 2) return res.json({ count: 0, patients: [] });
    const patients = await User.find(
      { role: "patient", username: { $regex: q, $options: "i" }, status: "active" },
      { _id: 0, id: 1, username: 1, role: 1, status: 1 }
    )
      .sort({ username: 1 })
      .limit(20)
      .lean();
    res.json({ count: patients.length, patients });
  }));

  // Doctor: assigned cases (patient identity trust indicators)
  app.get("/doctor/cases", requireAuth, requireRole(["doctor"]), asyncRoute(async (req, res) => {
    const assignment = await Assignment.findOne({ doctorId: req.auth.sub }).lean();
    const tokens = assignment?.patientTokens || [];
    if (!tokens.length) return res.json({ count: 0, patients: [] });

    const tokenSet = new Set(tokens.map((t) => String(t)));
    const patients = await User.find(
      { role: "patient", status: "active" },
      { _id: 0, id: 1, username: 1, email: 1, status: 1 }
    ).lean();

    const patientIds = patients.map((p) => p.id);
    const profiles = patientIds.length
      ? await PatientProfile.find({ patientId: { $in: patientIds } }, { _id: 0, __v: 0 }).lean()
      : [];
    const profileById = new Map(profiles.map((p) => [p.patientId, p]));

    const assigned = [];
    for (const p of patients) {
      const patientToken = hmacTokenizePatientId(p.id);
      if (!tokenSet.has(patientToken)) continue;
      const profile = profileById.get(p.id) || null;
      assigned.push({
        patientId: p.id,
        username: p.username,
        status: profile?.status || null,
        trustScore: safeNumber(profile?.trustScore),
        trustExplainTop3: Array.isArray(profile?.trustExplainTop3) ? profile.trustExplainTop3 : [],
        patientToken,
      });
    }

    assigned.sort((a, b) => String(a.username || a.patientId).localeCompare(String(b.username || b.patientId)));
    res.json({ count: assigned.length, patients: assigned });
  }));

  // Doctor: recent prescriptions created by this doctor (for dashboard)
  app.get("/doctor/prescriptions", requireAuth, requireRole(["doctor"]), asyncRoute(async (req, res) => {
    const limit = clampInt(req.query?.limit, { min: 1, max: 200, fallback: 50 });
    const items = await Prescription.find(
      { doctorId: req.auth.sub },
      { _id: 0, __v: 0 }
    )
      .sort({ issuedAt: -1, createdAt: -1 })
      .limit(limit)
      .lean();

    // Try to map patientIdToken -> username (best-effort)
    const patients = await User.find({ role: "patient" }, { _id: 0, id: 1, username: 1 }).lean();
    const tokenToPatient = new Map(patients.map((p) => [hmacTokenizePatientId(p.id), p]));

    res.json({
      count: items.length,
      prescriptions: items.map((rx) => ({
        ...rx,
        patient: tokenToPatient.get(rx.patientIdToken) ? { id: tokenToPatient.get(rx.patientIdToken).id, username: tokenToPatient.get(rx.patientIdToken).username } : null,
        expired: Date.parse(rx.expiry) < Date.now(),
      })),
    });
  }));

  // Doctor: prescriptions for a selected patient (ongoing + past)
  app.get("/doctor/patient-prescriptions", requireAuth, requireRole(["doctor"]), asyncRoute(async (req, res) => {
    const patientUserId = isNonEmptyString(req.query?.patientUserId) ? String(req.query.patientUserId).trim() : "";
    const limit = clampInt(req.query?.limit, { min: 1, max: 200, fallback: 100 });
    if (!isNonEmptyString(patientUserId)) {
      return res.status(400).json({ error: "bad_request", message: "patientUserId query param required" });
    }

    const doctor = await User.findOne({ id: req.auth.sub, role: "doctor" }).lean();
    const patient = await User.findOne({ id: patientUserId, role: "patient" }).lean();
    if (!doctor) return res.status(404).json({ error: "doctor_not_found" });
    if (!patient) return res.status(404).json({ error: "patient_not_found" });

    const patientToken = hmacTokenizePatientId(patient.id);
    const assignment = await Assignment.findOne({ doctorId: doctor.id }).lean();
    const assigned = assignment?.patientTokens?.includes(patientToken);
    if (!assigned) return res.status(403).json({ error: "not_assigned_to_patient" });

    const prescriptions = await Prescription.find(
      { doctorId: doctor.id, patientIdToken: patientToken, status: "active" },
      { _id: 0, __v: 0 }
    )
      .sort({ issuedAt: -1, createdAt: -1 })
      .limit(limit)
      .lean();

    const rxIds = prescriptions.map((p) => p.id).filter((id) => isNonEmptyString(id));
    const dispensed = rxIds.length
      ? await Dispense.find({ rxId: { $in: rxIds }, allowed: true }, { _id: 0, rxId: 1, ts: 1 }).lean()
      : [];
    const usedByRxId = new Map();
    for (const d of dispensed) {
      if (!isNonEmptyString(d?.rxId)) continue;
      const key = String(d.rxId);
      const prev = usedByRxId.get(key);
      if (!prev || String(d.ts).localeCompare(String(prev)) > 0) usedByRxId.set(key, d.ts);
    }

    const items = prescriptions.map((rx) => {
      const expired = Date.parse(rx.expiry) < Date.now();
      const usedAt = usedByRxId.get(rx.id) || null;
      const status = usedAt ? "USED" : expired ? "EXPIRED" : "VALID";
      return { prescription: rx, status, usedAt };
    });

    const ongoing = items.filter((i) => i.status === "VALID");
    const past = items.filter((i) => i.status !== "VALID");

    return res.json({
      ok: true,
      patient: { id: patient.id, username: patient.username },
      patientToken,
      count: items.length,
      ongoingCount: ongoing.length,
      pastCount: past.length,
      ongoing,
      past,
      items,
    });
  }));

  // Alert feed derived from audit logs (high-signal, role-scoped).
  app.get("/alerts/feed", requireAuth, asyncRoute(async (req, res) => {
    const windowHours = clampInt(req.query?.windowHours, { min: 1, max: 24 * 30, fallback: 24 });
    const limit = clampInt(req.query?.limit, { min: 1, max: 100, fallback: 50 });
    const to = new Date();
    const from = new Date(Date.now() - windowHours * 60 * 60 * 1000);
    const fromIso = from.toISOString();
    const toIso = to.toISOString();

    const severityForAction = (action) => {
      const a = String(action || "");
      if (a === "dispense.blocked") return "critical";
      if (a === "vitals.read_break_glass") return "high";
      if (a === "vitals.upload_rejected") return "high";
      if (a === "auth.password_reset_locked") return "high";
      if (a === "patient.device_bind_failed") return "medium";
      if (a.startsWith("anomaly.")) return a === "anomaly.password_reset_rate_limited" ? "high" : "medium";
      if (a === "auth.login_blocked") return "medium";
      return "info";
    };

    const titleForAction = (e) => {
      const action = String(e?.action || "");
      if (action === "dispense.blocked") return "Dispense blocked — possible tampering";
      if (action === "vitals.read_break_glass") return "Emergency access (break-glass) used";
      if (action === "vitals.upload_rejected") return "Vitals upload rejected";
      if (action === "auth.password_reset_locked") return "Password reset locked (admin approval required)";
      if (action === "patient.device_bind_failed") return "Device verification failed";
      if (action.startsWith("anomaly.")) return `Suspicious activity detected (${action})`;
      if (action === "auth.login_blocked") return "Login blocked";
      return action;
    };

    const actorLabel = (actor) =>
      (isNonEmptyString(actor?.username) && String(actor.username)) ||
      (isNonEmptyString(actor?.identifier) && String(actor.identifier)) ||
      (isNonEmptyString(actor?.userId) && String(actor.userId)) ||
      "—";

    const toAlert = (e, { overrideTitle = null } = {}) => ({
      ts: e.ts,
      severity: severityForAction(e.action),
      action: e.action,
      title: overrideTitle || titleForAction(e),
      actor: { label: actorLabel(e.actor || {}), ...(e.actor || {}) },
      details: e.details || {},
    });

    const role = req.auth.role;
    const userId = req.auth.sub;

    const directFilter = {
      ts: { $gte: fromIso, $lte: toIso },
      $or: [{ "actor.userId": userId }, { "actor.patientId": userId }],
    };

    const direct = await AuditEntry.find(directFilter, { _id: 0, __v: 0 }).sort({ ts: -1 }).limit(200).lean();
    const out = [];

    // Always include direct high-signal actions first.
    for (const e of direct) {
      const action = String(e.action || "");
      if (
        action === "auth.password_reset_locked" ||
        action === "auth.login_blocked" ||
        action === "patient.device_bind_failed" ||
        action === "vitals.read_break_glass" ||
        action === "vitals.upload_rejected" ||
        action.startsWith("anomaly.")
      ) {
        out.push(toAlert(e));
      }
    }

    // Doctor: include dispense.blocked related to their prescriptions (tamper attempts at pharmacy)
    if (role === "doctor") {
      const blocked = await AuditEntry.find(
        { ts: { $gte: fromIso, $lte: toIso }, action: "dispense.blocked" },
        { _id: 0, ts: 1, action: 1, actor: 1, details: 1 }
      )
        .sort({ ts: -1 })
        .limit(200)
        .lean();
      const rxIds = blocked.map((b) => b.details?.rxId).filter((id) => isNonEmptyString(id)).map((id) => String(id));
      const rxDocs = rxIds.length
        ? await Prescription.find({ id: { $in: rxIds }, doctorId: userId }, { _id: 0, id: 1 }).lean()
        : [];
      const myRxIdSet = new Set(rxDocs.map((r) => r.id));
      for (const b of blocked) {
        const rxId = b.details?.rxId;
        if (!isNonEmptyString(rxId) || !myRxIdSet.has(String(rxId))) continue;
        out.push(toAlert(b, { overrideTitle: "Tampering attempt detected — dispense blocked for your prescription" }));
      }
    }

    // Pharmacy: include dispense.blocked and dispense.allowed for operational awareness.
    if (role === "pharmacy") {
      const recentDispense = await AuditEntry.find(
        { ts: { $gte: fromIso, $lte: toIso }, $or: [{ action: "dispense.blocked" }, { action: "dispense.allowed" }], "actor.userId": userId },
        { _id: 0, ts: 1, action: 1, actor: 1, details: 1 }
      )
        .sort({ ts: -1 })
        .limit(100)
        .lean();
      for (const e of recentDispense) out.push(toAlert(e));
    }

    // Admin: also include top anomalies + dispense blocks (overview).
    if (role === "admin") {
      const adminExtra = await AuditEntry.find(
        {
          ts: { $gte: fromIso, $lte: toIso },
          $or: [{ action: "dispense.blocked" }, { action: "auth.password_reset_locked" }, { action: { $regex: "^anomaly\\." } }],
        },
        { _id: 0, ts: 1, action: 1, actor: 1, details: 1 }
      )
        .sort({ ts: -1 })
        .limit(200)
        .lean();
      for (const e of adminExtra) out.push(toAlert(e));
    }

    // De-dupe by (ts,action,actorLabel)
    const seen = new Set();
    const deduped = [];
    for (const a of out) {
      const key = `${a.ts}|${a.action}|${a.actor?.label || ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(a);
    }

    // Order by severity then newest
    const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    deduped.sort((a, b) => {
      const s = (rank[b.severity] || 0) - (rank[a.severity] || 0);
      if (s !== 0) return s;
      return String(b.ts).localeCompare(String(a.ts));
    });

    res.json({ ok: true, windowHours, from: fromIso, to: toIso, count: Math.min(limit, deduped.length), alerts: deduped.slice(0, limit) });
  }));

  // --- Pharmacy/Pharmacist Endpoints (dashboard) ---
  function requirePharmacyWithBiometric() {
    return [requireAuth, requireRole(["pharmacy"]), requirePharmacyBiometric];
  }

  app.get("/pharmacy/dashboard", ...requirePharmacyWithBiometric(), asyncRoute(async (req, res) => {
    const [medicinesCount, stockCount, lowStockCount, expiredCount, pendingVerifications] = await Promise.all([
      Medicine.countDocuments({ status: "active" }),
      Stock.countDocuments({ status: { $in: ["available", "low_stock", "out_of_stock", "quarantined", "expired"] } }),
      Stock.countDocuments({ status: "low_stock" }),
      Stock.countDocuments({ status: "expired" }),
      QualityVerification.countDocuments({ overallStatus: "pending" }),
    ]);

    return res.json({
      statistics: {
        totalMedicines: medicinesCount,
        totalStockItems: stockCount,
        lowStockItems: lowStockCount,
        expiredItems: expiredCount,
        pendingVerifications,
      },
    });
  }));

  // Medicine management
  app.post("/pharmacy/medicines", ...requirePharmacyWithBiometric(), asyncRoute(async (req, res) => {
    const {
      name,
      genericName,
      manufacturer,
      category,
      dosageForms,
      strengths,
      description,
      storageConditions,
      expiryPeriod,
      requiresPrescription,
    } = req.body || {};

    if (!isNonEmptyString(name) || !isNonEmptyString(manufacturer) || !isNonEmptyString(category)) {
      return res.status(400).json({ error: "bad_request", message: "name/manufacturer/category required" });
    }

    const medicine = {
      id: randomId("med"),
      name: name.trim(),
      genericName: isNonEmptyString(genericName) ? genericName.trim() : null,
      manufacturer: manufacturer.trim(),
      category: category.trim(),
      dosageForms: Array.isArray(dosageForms) ? dosageForms.filter(isNonEmptyString).map((s) => String(s).trim()) : [],
      strengths: Array.isArray(strengths) ? strengths.filter(isNonEmptyString).map((s) => String(s).trim()) : [],
      description: isNonEmptyString(description) ? description.trim() : null,
      storageConditions: isNonEmptyString(storageConditions) ? storageConditions.trim() : null,
      expiryPeriod: expiryPeriod !== undefined && expiryPeriod !== null ? Number(expiryPeriod) : null,
      requiresPrescription: requiresPrescription !== undefined ? Boolean(requiresPrescription) : true,
      status: "active",
      createdBy: req.auth.sub,
      createdAt: nowIso(),
    };

    await Medicine.create(medicine);
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "medicine.created",
      details: { medicineId: medicine.id, name: medicine.name },
    });

    return res.status(201).json(medicine);
  }));

  app.get("/pharmacy/medicines", ...requirePharmacyWithBiometric(), asyncRoute(async (req, res) => {
    const { search, category, status, limit = 100 } = req.query || {};
    const query = {};

    if (isNonEmptyString(search)) {
      query.$or = [
        { name: { $regex: String(search), $options: "i" } },
        { genericName: { $regex: String(search), $options: "i" } },
        { manufacturer: { $regex: String(search), $options: "i" } },
      ];
    }
    if (isNonEmptyString(category)) query.category = String(category);
    if (isNonEmptyString(status)) query.status = String(status);

    const medicines = await Medicine.find(query).sort({ createdAt: -1 }).limit(Number(limit)).lean();
    return res.json({ count: medicines.length, medicines });
  }));

  app.put("/pharmacy/medicines/:medicineId", ...requirePharmacyWithBiometric(), asyncRoute(async (req, res) => {
    const { medicineId } = req.params;
    const medicine = await Medicine.findOne({ id: medicineId }).lean();
    if (!medicine) return res.status(404).json({ error: "medicine_not_found" });

    const {
      name,
      genericName,
      manufacturer,
      category,
      dosageForms,
      strengths,
      description,
      storageConditions,
      expiryPeriod,
      requiresPrescription,
      status,
    } = req.body || {};

    const updateData = {};
    if (name !== undefined) updateData.name = String(name).trim();
    if (genericName !== undefined) updateData.genericName = isNonEmptyString(genericName) ? String(genericName).trim() : null;
    if (manufacturer !== undefined) updateData.manufacturer = String(manufacturer).trim();
    if (category !== undefined) updateData.category = String(category).trim();
    if (dosageForms !== undefined) updateData.dosageForms = Array.isArray(dosageForms) ? dosageForms.filter(isNonEmptyString).map((s) => String(s).trim()) : [];
    if (strengths !== undefined) updateData.strengths = Array.isArray(strengths) ? strengths.filter(isNonEmptyString).map((s) => String(s).trim()) : [];
    if (description !== undefined) updateData.description = isNonEmptyString(description) ? String(description).trim() : null;
    if (storageConditions !== undefined) updateData.storageConditions = isNonEmptyString(storageConditions) ? String(storageConditions).trim() : null;
    if (expiryPeriod !== undefined) updateData.expiryPeriod = expiryPeriod !== null ? Number(expiryPeriod) : null;
    if (requiresPrescription !== undefined) updateData.requiresPrescription = Boolean(requiresPrescription);
    if (status !== undefined) updateData.status = String(status).trim();

    await Medicine.updateOne({ id: medicineId }, { $set: updateData });
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "medicine.updated",
      details: { medicineId, updates: Object.keys(updateData) },
    });

    const updated = await Medicine.findOne({ id: medicineId }).lean();
    return res.json(updated);
  }));

  // Stock management
  app.post("/pharmacy/stock", ...requirePharmacyWithBiometric(), asyncRoute(async (req, res) => {
    const {
      medicineId,
      quantity,
      unit,
      expiryDate,
      batchId,
      location,
      costPerUnit,
      sellingPricePerUnit,
      minStockLevel,
      notes,
    } = req.body || {};

    if (!isNonEmptyString(medicineId) || !Number.isFinite(Number(quantity)) || !isNonEmptyString(expiryDate)) {
      return res.status(400).json({ error: "bad_request", message: "medicineId/quantity/expiryDate required" });
    }

    const medicine = await Medicine.findOne({ id: medicineId }).lean();
    if (!medicine) return res.status(404).json({ error: "medicine_not_found" });

    const qty = Number(quantity);
    const minLvl = Number.isFinite(Number(minStockLevel)) ? Number(minStockLevel) : 10;
    const status = qty === 0 ? "out_of_stock" : qty < minLvl ? "low_stock" : "available";

    const stock = {
      id: randomId("stk"),
      medicineId,
      quantity: qty,
      unit: isNonEmptyString(unit) ? String(unit).trim() : "units",
      expiryDate: String(expiryDate).trim(),
      batchId: isNonEmptyString(batchId) ? String(batchId).trim() : null,
      status,
      location: isNonEmptyString(location) ? String(location).trim() : null,
      minStockLevel: minLvl,
      costPerUnit: costPerUnit !== undefined && costPerUnit !== null ? Number(costPerUnit) : null,
      sellingPricePerUnit: sellingPricePerUnit !== undefined && sellingPricePerUnit !== null ? Number(sellingPricePerUnit) : null,
      notes: isNonEmptyString(notes) ? String(notes).trim() : null,
      createdBy: req.auth.sub,
      createdAt: nowIso(),
      lastRestockedAt: nowIso(),
      lastRestockedBy: req.auth.sub,
    };

    await Stock.create(stock);
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "stock.created",
      details: { stockId: stock.id, medicineId },
    });

    return res.status(201).json(stock);
  }));

  app.get("/pharmacy/stock", ...requirePharmacyWithBiometric(), asyncRoute(async (req, res) => {
    const { medicineId, status, limit = 100 } = req.query || {};
    const query = {};
    if (isNonEmptyString(medicineId)) query.medicineId = String(medicineId);
    if (isNonEmptyString(status)) query.status = String(status);

    const stock = await Stock.find(query).sort({ createdAt: -1 }).limit(Number(limit)).lean();
    const medicineIds = [...new Set(stock.map((s) => s.medicineId))];
    const medicines = await Medicine.find({ id: { $in: medicineIds } }, { _id: 0, id: 1, name: 1 }).lean();
    const medNameById = new Map(medicines.map((m) => [m.id, m.name]));
    const enriched = stock.map((s) => ({ ...s, medicineName: medNameById.get(s.medicineId) || null }));

    return res.json({ count: enriched.length, stock: enriched });
  }));

  app.put("/pharmacy/stock/:stockId", ...requirePharmacyWithBiometric(), asyncRoute(async (req, res) => {
    const { stockId } = req.params;
    const stock = await Stock.findOne({ id: stockId }).lean();
    if (!stock) return res.status(404).json({ error: "stock_not_found" });

    const {
      quantity,
      unit,
      expiryDate,
      batchId,
      location,
      costPerUnit,
      sellingPricePerUnit,
      minStockLevel,
      notes,
    } = req.body || {};

    const updateData = {};
    if (quantity !== undefined) updateData.quantity = Number(quantity);
    if (unit !== undefined) updateData.unit = isNonEmptyString(unit) ? String(unit).trim() : "units";
    if (expiryDate !== undefined) updateData.expiryDate = String(expiryDate).trim();
    if (batchId !== undefined) updateData.batchId = isNonEmptyString(batchId) ? String(batchId).trim() : null;
    if (location !== undefined) updateData.location = isNonEmptyString(location) ? String(location).trim() : null;
    if (minStockLevel !== undefined) updateData.minStockLevel = Number(minStockLevel);
    if (costPerUnit !== undefined) updateData.costPerUnit = costPerUnit !== null ? Number(costPerUnit) : null;
    if (sellingPricePerUnit !== undefined) updateData.sellingPricePerUnit = sellingPricePerUnit !== null ? Number(sellingPricePerUnit) : null;
    if (notes !== undefined) updateData.notes = isNonEmptyString(notes) ? String(notes).trim() : null;

    const qty = updateData.quantity ?? stock.quantity;
    const minLvl = updateData.minStockLevel ?? stock.minStockLevel ?? 10;
    updateData.status = qty === 0 ? "out_of_stock" : qty < minLvl ? "low_stock" : "available";
    updateData.lastRestockedAt = nowIso();
    updateData.lastRestockedBy = req.auth.sub;

    await Stock.updateOne({ id: stockId }, { $set: updateData });
    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "stock.updated",
      details: { stockId, updates: Object.keys(updateData) },
    });

    const updated = await Stock.findOne({ id: stockId }).lean();
    return res.json(updated);
  }));

  // Quality verification
  app.post("/pharmacy/quality-verification", ...requirePharmacyWithBiometric(), asyncRoute(async (req, res) => {
    const { medicineId, batchId, stockId, standard, checks, notes, testResults } = req.body || {};
    if (!isNonEmptyString(medicineId) || !isNonEmptyString(standard)) {
      return res.status(400).json({ error: "bad_request", message: "medicineId/standard required" });
    }

    const medicine = await Medicine.findOne({ id: medicineId }).lean();
    if (!medicine) return res.status(404).json({ error: "medicine_not_found" });

    const checkValues = checks ? Object.values(checks) : [];
    let overallStatus = "pending";
    if (checkValues.length > 0) {
      if (checkValues.every((v) => v === "pass")) overallStatus = "approved";
      else if (checkValues.some((v) => v === "fail")) overallStatus = "rejected";
    }

    const verification = {
      id: randomId("qv"),
      medicineId,
      batchId: isNonEmptyString(batchId) ? String(batchId).trim() : null,
      stockId: isNonEmptyString(stockId) ? String(stockId).trim() : null,
      verifiedBy: req.auth.sub,
      verificationDate: nowIso(),
      standard: String(standard).trim(),
      checks: checks || {},
      overallStatus,
      notes: isNonEmptyString(notes) ? String(notes).trim() : null,
      testResults: testResults || null,
      createdAt: nowIso(),
    };

    await QualityVerification.create(verification);

    if (overallStatus === "rejected" && isNonEmptyString(stockId)) {
      await Stock.updateOne({ id: String(stockId).trim() }, { $set: { status: "quarantined" } });
    }

    await auditAppend({
      actor: { userId: req.auth.sub, role: req.auth.role },
      action: "quality.verified",
      details: { verificationId: verification.id, medicineId, overallStatus, standard: verification.standard },
    });

    return res.status(201).json(verification);
  }));

  app.get("/pharmacy/quality-verifications", ...requirePharmacyWithBiometric(), asyncRoute(async (req, res) => {
    const { medicineId, batchId, overallStatus, limit = 100 } = req.query || {};
    const query = {};
    if (isNonEmptyString(medicineId)) query.medicineId = String(medicineId);
    if (isNonEmptyString(batchId)) query.batchId = String(batchId);
    if (isNonEmptyString(overallStatus)) query.overallStatus = String(overallStatus);

    const verifications = await QualityVerification.find(query)
      .sort({ verificationDate: -1 })
      .limit(Number(limit))
      .lean();

    return res.json({ count: verifications.length, verifications });
  }));

  // SPA fallback: serve the UI for unknown GET routes (e.g. /home/)
  app.get("*", (req, res, next) => {
    if (req.method !== "GET") return next();
    if (req.path.includes(".")) return next(); // likely a file
    return res.sendFile(path.join(publicDir, "index.html"));
  });

  // Error handler to avoid ERR_EMPTY_RESPONSE on async errors (Express 4)
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    // eslint-disable-next-line no-console
    console.error(err);
    if (res.headersSent) return;
    res.status(500).json({ error: "internal_error" });
  });

  return app;
}

let __appPromise = null;
export async function getApp() {
  if (!__appPromise) __appPromise = buildApp();
  return __appPromise;
}

export async function startServer() {
  const app = await getApp();
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`MVP listening on http://localhost:${PORT}`);
  });
}

// Vercel/Serverless handler compatibility:
// Some deployments may point directly at `src/server.js` as the entrypoint and expect a default export.
export default async function handler(req, res) {
  const app = await getApp();
  return app(req, res);
}

const __filename = fileURLToPath(import.meta.url);
const __isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename);
if (__isMain) {
  startServer().catch((err) => {
    // eslint-disable-next-line no-console
    console.error(err);
    process.exit(1);
  });
}
