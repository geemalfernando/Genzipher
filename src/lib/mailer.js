import nodemailer from "nodemailer";

function env(key, fallback = "") {
  return (process.env[key] || fallback).trim();
}

function boolEnv(key, fallback = false) {
  const v = env(key, "");
  if (!v) return fallback;
  return ["1", "true", "yes", "on"].includes(v.toLowerCase());
}

export function isSmtpEnabled() {
  return Boolean(env("SMTP_HOST") && env("SMTP_USER") && env("SMTP_PASS"));
}

let cachedTransporter = null;

export function getMailer() {
  if (cachedTransporter) return cachedTransporter;

  const host = env("SMTP_HOST");
  const port = Number(env("SMTP_PORT", "465"));
  const secure = boolEnv("SMTP_SECURE", port === 465);
  const user = env("SMTP_USER");
  const pass = env("SMTP_PASS");
  const debug = boolEnv("SMTP_DEBUG", false);
  const tlsRejectUnauthorized = boolEnv("SMTP_TLS_REJECT_UNAUTHORIZED", true);

  cachedTransporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
    tls: {
      rejectUnauthorized: tlsRejectUnauthorized,
    },
    logger: debug,
    debug,
  });

  return cachedTransporter;
}

export async function verifySmtpConnection() {
  if (!isSmtpEnabled()) return { ok: false, error: "smtp_not_configured" };
  const transporter = getMailer();
  try {
    await transporter.verify();
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      error: "smtp_verify_failed",
      detail: {
        name: err?.name,
        code: err?.code,
        message: err?.message,
        responseCode: err?.responseCode,
        response: err?.response,
        command: err?.command,
      },
    };
  }
}

export async function sendOtpEmail({ to, otp, expiresAtIso }) {
  const transporter = getMailer();
  const from = (process.env.FROM_EMAIL || process.env.SMTP_USER || "").trim();
  if (!from) throw new Error("FROM_EMAIL not set");

  await transporter.sendMail({
    from,
    to,
    subject: "Your GenZipher login code",
    text: `Your login code is: ${otp}\n\nIt expires at: ${expiresAtIso}\n\nIf you did not request this, you can ignore this email.`,
  });
}

export async function sendClinicCodeEmail({ to, code, expiresAtIso }) {
  const transporter = getMailer();
  const from = (process.env.FROM_EMAIL || process.env.SMTP_USER || "").trim();
  if (!from) throw new Error("FROM_EMAIL not set");

  await transporter.sendMail({
    from,
    to,
    subject: "Your GenZipher clinic verification code",
    text: `Your clinic verification code is: ${code}\n\nIt expires at: ${expiresAtIso}\n\nIf you did not request this, you can ignore this email.`,
  });
}

export async function sendMagicLinkEmail({ to, verifyUrl, expiresAtIso }) {
  const transporter = getMailer();
  const from = (process.env.FROM_EMAIL || process.env.SMTP_USER || "").trim();
  if (!from) throw new Error("FROM_EMAIL not set");

  await transporter.sendMail({
    from,
    to,
    subject: "Verify your new device login",
    text: `We detected a login from a new device.\n\nVerify this device by clicking:\n${verifyUrl}\n\nThis link expires at: ${expiresAtIso}\n\nIf this wasn't you, ignore this email.`,
  });
}

export async function sendPrescriptionIssuedEmail({ to, doctorUsername, rx }) {
  const transporter = getMailer();
  const from = (process.env.FROM_EMAIL || process.env.SMTP_USER || "").trim();
  if (!from) throw new Error("FROM_EMAIL not set");

  const safeDoctor = doctorUsername ? String(doctorUsername) : "your doctor";
  const medicineId = rx?.medicineId ? String(rx.medicineId) : "—";
  const dosage = rx?.dosage ? String(rx.dosage) : "—";
  const durationDays = typeof rx?.durationDays === "number" ? String(rx.durationDays) : rx?.durationDays ? String(rx.durationDays) : "—";
  const expiry = rx?.expiry ? String(rx.expiry) : "—";
  const rxId = rx?.id ? String(rx.id) : "—";

  await transporter.sendMail({
    from,
    to,
    subject: "New prescription issued",
    text:
      `A new prescription was issued by ${safeDoctor}.\n\n` +
      `Prescription ID: ${rxId}\n` +
      `Medicine: ${medicineId}\n` +
      `Dosage: ${dosage}\n` +
      `Duration: ${durationDays} day(s)\n` +
      `Expires: ${expiry}\n\n` +
      `You can view this prescription in your GenZipher patient dashboard.\n\n` +
      `If you did not expect this, contact your clinic.`,
  });
}

export async function sendAccountActivatedEmail({ to, role }) {
  const transporter = getMailer();
  const from = (process.env.FROM_EMAIL || process.env.SMTP_USER || "").trim();
  if (!from) throw new Error("FROM_EMAIL not set");

  const r = role ? String(role) : "account";
  await transporter.sendMail({
    from,
    to,
    subject: "Your GenZipher account is activated",
    text: `Your ${r} account has been activated by an administrator.\n\nYou can now sign in to GenZipher.\n\nIf you did not request this, contact your clinic.`,
  });
}

export async function sendAccountDeletedEmail({ to, role }) {
  const transporter = getMailer();
  const from = (process.env.FROM_EMAIL || process.env.SMTP_USER || "").trim();
  if (!from) throw new Error("FROM_EMAIL not set");

  const r = role ? String(role) : "account";
  await transporter.sendMail({
    from,
    to,
    subject: "Your GenZipher account has been deleted",
    text: `Your ${r} account deletion request was approved by an administrator.\n\nIf you did not request this, contact support immediately.`,
  });
}
