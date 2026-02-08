# GenZipher Healthcare Security & Trust Platform (MVP)

This repo is a runnable MVP for a **Healthcare Security & Trust Platform** that blocks identity hijacking, stops vitals leakage, and prevents medicine swaps (placebo sabotage).

## Deployed links

- Frontend (Firebase Hosting): `https://genzipher-40316.web.app`
- Backend (Vercel API base): `https://genzipher.vercel.app/api`
- Backend health check: `https://genzipher.vercel.app/api/health`

## Threat & critical vulnerability (identity trust collapse → fraud, sabotage)

If the system cannot prove:
- **Who is acting** (real identity, role, and device)
- **What is genuine** (prescriptions + medicine provenance)
- **Who accessed what** (auditability and investigations)

…then attackers can impersonate users, drain resources, leak medical data, and silently sabotage dispensing.

## Core security pillars

1. Identity/MFA + onboarding
2. Device binding (proof-of-possession)
3. Data encryption + break-glass access
4. Signed Rx + signed batches + dispense gate
5. Tamper-evident audit
6. AI trust score + anomaly triggers (MVP rules + explainability)

## Identity/MFA + onboarding

- **RBAC** per endpoint (doctor/patient/pharmacy/manufacturer/admin).
- **Patient onboarding**: pre-register → `PENDING` → verify code → `VERIFIED/ACTIVE`.
- **MFA**
  - Per-user **Authenticator MFA (TOTP)** supported (unique per user, changes every ~30 seconds).
  - Optional legacy demo enforcement: set `DEMO_MFA_ENFORCE=true` to require `DEMO_MFA_CODE` for privileged roles that haven’t enabled per-user MFA yet.
  - Email OTP is still used for password reset / certain step-up flows when SMTP is configured.

## Device binding

- Device binding uses challenge–response signatures (server nonce → device signs → server verifies).
- Web UI automates this using WebCrypto (P‑256 / ES256): private key stays on the device.

## Data encryption + break-glass

- Vitals are encrypted at rest with a per-patient **data key** (AES‑256‑GCM).
- Break-glass reads are allowed but logged separately for review.

## Signed Rx + signed batches + dispense gate

- Doctor issues **digitally signed prescriptions** (tamper fails verification).
- Manufacturer registers **signed batch certificates** (tamper/expiry invalidates).
- Pharmacy **dispenses only if Rx + batch both verify**.

## Tamper-evident audit

- Sensitive actions write an audit entry.
- Audit entries are **hash-chained** (tamper-evident).
- Admin UI shows readable logs with optional JSON view/copy/export.

## AI trust score + anomaly triggers

- Trust score is computed during patient pre-registration with explainable top factors.
- Simple anomaly triggers (MVP): repeated OTP failures, bursts of registrations, repeated verification failures → audited for investigation/step-up.

## Quickstart

Prereqs: Node.js 18+ and MongoDB.

1. Install deps:
   - `npm install`
2. Configure env:
   - `cp .env.example .env`
3. Seed MongoDB (creates collections + demo documents):
   - `npm run seed`
4. Run the API:
   - `npm run dev`
5. Run the React UI:
   - `cd chanith-frontend && npm install && npm run dev`

API runs on `http://localhost:3000`.
UI runs on `http://localhost:3001`.

## Patient verification (admin → email)

If SMTP is configured, the admin dashboard can email a 10-minute clinic verification code to a pending patient:

1. Register a patient with a real email (Register tab).
2. Login as `admin1` + MFA `123456`.
3. Admin → Verify patients → select pending patient → Generate code (send email checked).
4. Patient checks email, enters the code in the Register tab → Verify code.

If email isn’t configured, uncheck “send email” and use the generated code (or check server logs for `[CLINIC_CODE]`).

## Demo accounts (seeded)

All passwords are `password123`.

- Doctor: `doctor1`
- Patient: `patient1`
- Pharmacy: `pharmacy1`
- Manufacturer: `mfg1`
- Admin/Compliance: `admin1`

Note: Enable per-user Authenticator MFA (TOTP) from each role dashboard (Security/MFA). If `DEMO_MFA_ENFORCE=true`, the demo code is `DEMO_MFA_CODE` (default `123456`) for privileged roles without per-user MFA enabled.

## MVP endpoints

- `POST /auth/login`
- `POST /patients/pre-register`
- `POST /patients/verify-clinic-code`
- `POST /clinic/codes` (admin issues 1-time clinic code)
- `POST /patients/issue-did` (patient)
- `POST /patients/provision-data-key` (patient)
- `POST /prescriptions` (doctor)
- `POST /prescriptions/verify`
- `POST /batches` (manufacturer)
- `POST /batches/verify`
- `POST /dispense` (pharmacy)
- `POST /patients/bind-device` (patient)
- `POST /auth/device-challenge` (patient)
- `POST /auth/device-verify` (patient)
- `POST /vitals/upload` (patient/device)
- `GET /audit/logs` (admin)

## “Attack” demo

Run:

- `npm run demo:attack`

It logs in, creates a signed prescription, then tampers with the JSON and shows signature verification failing.

## Demo path (3 flows + one attack simulation)

Flow 1 — Patient onboarding + verification
- Register patient (minimal inputs) → `PENDING`
- Admin issues 1‑time verification code (optionally emailed)
- Patient verifies → `VERIFIED/ACTIVE` → login allowed

Flow 2 — Doctor issues tamper-proof Rx
- Doctor logs in (MFA) → creates signed Rx → verify passes

Flow 3 — Manufacturer + pharmacy (provenance + dispense gate)
- Manufacturer registers signed batch certificate → verify passes
- Pharmacy dispenses only if Rx verify + batch verify both pass

Attack simulation
- Modify Rx JSON or batch fields after signing → verification fails → dispense blocked + audit entry created

## Email OTP (actual email)

Some flows (password reset, new-device step-up, clinic code) can send real emails when SMTP is configured.

To enable email sending, set SMTP env vars in `.env` (Gmail example):

- `SMTP_HOST=smtp.gmail.com`
- `SMTP_PORT=465`
- `SMTP_SECURE=true`
- `SMTP_USER=geemal1976@gmail.com`
- `SMTP_PASS=<gmail app password>`
- `FROM_EMAIL=geemal1976@gmail.com`

Note: Gmail usually requires 2FA + an App Password (regular account password won’t work).

## New device verification (automatic)

If SMTP is configured, a login from a new device for patients/doctors triggers an **email verification link**:

- Login from device A → allowed.
- Login from device B → backend emails a link; user clicks it → the app auto-verifies the device and logs in.

This uses `PUBLIC_BASE_URL` to build the link.

## “Don’t ask OTP again” (trusted device)

After a successful OTP verification, check “Trust this device” in the OTP box. For the next 30 days, logins from the same browser/device will skip OTP (still requires password).

To re-enable OTP prompts on this device: Patient → Trusted device → remove this device (requires email OTP).

## Disable MFA

- For **Email OTP MFA** (legacy): patient can disable it from the Patient screen (requires email OTP confirmation).
- For **Authenticator MFA (TOTP)**: use admin break-glass reset (`POST /admin/mfa/reset`) or reset via the “Forgot password” flow with `resetMfa=true`.

## SMTP troubleshooting

Test SMTP from the app (admin-only):

- `POST /admin/mail/test` with JSON `{ "to": "you@example.com" }`

If this fails:
- Use a Gmail App Password (not your login password).
- Confirm `SMTP_HOST/PORT/SECURE/USER/PASS/FROM_EMAIL` in `.env`.
- If you see `EAUTH` / `535` errors, your SMTP credentials are wrong (use an App Password).
- If you see `ETIMEDOUT` / `ECONNREFUSED`, your network/firewall is blocking outbound SMTP.

## MongoDB collections created

Collections are created automatically when seeding and on first write:

- `users`
- `assignments`
- `devices`
- `patientkeys`
- `prescriptions`
- `batches`
- `dispenses`
- `vitals`
- `auditmetas`
- `auditentries`

## Compliance (HIPAA/GDPR/PDPA-aligned principles)

- **Least privilege**: role separation + scoped access.
- **Integrity & authenticity**: signed Rx + signed batch provenance + device proof-of-possession.
- **Confidentiality**: encrypted vitals at rest with per-patient keying.
- **Accountability**: tamper-evident audit trail + per-user activity views.
- **Emergency access**: break-glass supported with extra logging and review.
