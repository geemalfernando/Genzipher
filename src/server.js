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
import { isSmtpEnabled, sendClinicCodeEmail, sendMagicLinkEmail, sendOtpEmail, verifySmtpConnection } from "./lib/mailer.js";

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const DEMO_MFA_CODE = process.env.DEMO_MFA_CODE || "123456";
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

  const allowedOrigins = CORS_ORIGIN.split(",").map(normalizeOrigin).filter(Boolean);

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          "default-src": ["'self'"],
          "script-src": ["'self'"],
          "style-src": ["'self'", "https://unpkg.com", "'unsafe-inline'"],
          "img-src": ["'self'", "data:"],
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

  // If the backend is hosted separately from the frontend, redirect browser visits to `/`
  // to the configured public URL (e.g. Firebase Hosting). Keep API routes unaffected.
  app.get("/", (req, res, next) => {
    const accept = req.header("accept") || "";
    if (!accept.includes("text/html")) return next();
    const current = normalizeOrigin(`${req.protocol}://${req.get("host")}`);
    const pub = normalizeOrigin(PUBLIC_BASE_URL);
    if (pub && current && pub !== current) return res.redirect(302, `${pub}/`);
    return next();
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
    if (!user || !verifyPassword(user.password, pwd) || user.status !== "active") {
      await auditAppend({
        actor: { identifier: id },
        action: "auth.login_failed",
        details: { reason: "bad_credentials_or_inactive" },
      });
      return res.status(401).json({ error: "invalid_credentials" });
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
    const { resetToken, newPassword } = req.body || {};
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

    await User.updateOne({ id: user.id }, { $set: { password: hashPasswordScrypt(newPassword) } });

    // Defensive: revoke trusted-device bypass tokens after password reset.
    await TrustedDevice.updateMany({ userId: user.id, revokedAt: null }, { $set: { revokedAt: new Date() } });

    await auditAppend({
      actor: { userId: user.id, role: user.role, username: user.username },
      action: "auth.password_reset_completed",
      details: { otpRequestId: payload.otpRequestId },
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
        status: "active",
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

    return res.status(201).json({
      patientId,
      status: score >= 80 ? "VERIFIED" : "PENDING",
      trustScore: score,
      trustExplainTop3: top3,
      next: score >= 80 ? "login" : "verify_clinic_code",
      ...(verification ? { verification } : {}),
    });
  }));

  // --- Pharmacist (pharmacy role) signup ---
  app.post("/pharmacist/signup", asyncRoute(async (req, res) => {
    const { username, email, password, mfaCode, deviceId } = req.body || {};
    if (!looksLikeUsername(username) || !looksLikePassword(password) || !looksLikeEmail(email)) {
      return res.status(400).json({ error: "bad_request", message: "username + email + password required" });
    }
    if (String(mfaCode || "").trim() !== String(DEMO_MFA_CODE)) {
      return res.status(401).json({ error: "invalid_mfa_code", message: "Invalid MFA code. Please use the correct registration code." });
    }
    const existing = await User.findOne({ $or: [{ username }, { email: String(email).trim().toLowerCase() }] }).lean();
    if (existing) return res.status(409).json({ error: "user_exists" });

    const userId = randomId("u_pharmacy");
    const user = await User.create({
      id: userId,
      username: String(username).trim(),
      email: String(email).trim().toLowerCase(),
      role: "pharmacy",
      password: hashPasswordScrypt(password),
      status: "active",
      mfaEnabled: false,
      mfaMethod: "NONE",
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
    res.json({
      enrolled: Boolean(user.biometricEnrolled),
      enrolledAt: user.biometricEnrolledAt ? new Date(user.biometricEnrolledAt).toISOString() : null,
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
    const { credential, challenge, deviceName } = req.body || {};
    if (!credential || !isNonEmptyString(challenge)) {
      return res.status(400).json({ error: "bad_request", message: "credential and challenge required" });
    }

    const latest = await WebAuthnChallenge.findOne({ userId: req.auth.sub, purpose: "ENROLL", expiresAt: { $gt: new Date() } })
      .sort({ expiresAt: -1 })
      .lean();
    if (!latest) return res.status(400).json({ error: "challenge_missing" });
    if (String(challenge) !== String(latest.challenge)) return res.status(401).json({ error: "challenge_mismatch" });

    const rawIdArr = Array.isArray(credential.rawId) ? credential.rawId : [];
    const credIdB64u = rawIdArr.length ? Buffer.from(rawIdArr).toString("base64url") : null;
    if (!isNonEmptyString(credIdB64u)) return res.status(400).json({ error: "bad_request", message: "credential.rawId required" });

    const existing = await Biometric.findOne({ credentialIdB64u: credIdB64u }).lean();
    if (existing) return res.status(409).json({ error: "credential_exists", message: "This biometric credential is already enrolled" });

    const attObj = Array.isArray(credential?.response?.attestationObject) ? credential.response.attestationObject : [];
    const cdj = Array.isArray(credential?.response?.clientDataJSON) ? credential.response.clientDataJSON : [];
    const publicKeyJson = JSON.stringify({
      id: credential.id || credIdB64u,
      rawId: rawIdArr,
      type: credential.type || "public-key",
      response: {
        attestationObject: Buffer.from(attObj).toString("base64url"),
        clientDataJSON: Buffer.from(cdj).toString("base64url"),
      },
    });

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

    await Promise.all([
      User.updateOne({ id: req.auth.sub }, { $set: { biometricEnrolled: true, biometricEnrolledAt: new Date() } }),
      WebAuthnChallenge.deleteOne({ id: latest.id }),
    ]);

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

    const rawIdArr = Array.isArray(credential.rawId) ? credential.rawId : [];
    const credIdB64u = rawIdArr.length ? Buffer.from(rawIdArr).toString("base64url") : null;
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

    return res.status(201).json(rx);
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

  // --- Helpful demo data endpoints (read-only, authenticated) ---
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
