# GenZipher Healthcare Security & Trust Platform (MVP)

This is a runnable MVP for the scenario: block medical identity hijacking, prevent vitals leakage, and stop medicine swaps (placebo sabotage) using:

- Zero-trust identity + role-based access (JWT + MFA stub for demo)
- Per-patient encrypted vitals storage (AES-256-GCM)
- Digitally signed prescriptions (Ed25519 via Node.js `crypto`)
- Digitally signed medicine batch certificates (Ed25519)
- Dispense gate that requires both checks (Rx + batch)
- Tamper-evident, hash-chained audit log

## Quickstart

Prereqs: Node.js 18+ and MongoDB.

1. Install deps:
   - `npm install`
2. Configure env:
   - `cp .env.example .env`
3. Seed MongoDB (creates collections + demo documents):
   - `npm run seed`
4. Run the API + UI:
   - `npm run dev`

API runs on `http://localhost:3000`.

## Demo accounts (seeded)

All passwords are `password123`.

- Doctor: `doctor1` (MFA code required: `123456`)
- Patient: `patient1`
- Pharmacy: `pharmacy1` (MFA code required: `123456`)
- Manufacturer: `mfg1` (MFA code required: `123456`)
- Admin/Compliance: `admin1` (MFA code required: `123456`)

## MVP endpoints

- `POST /auth/login`
- `POST /prescriptions` (doctor)
- `POST /prescriptions/verify`
- `POST /batches` (manufacturer)
- `POST /batches/verify`
- `POST /dispense` (pharmacy)
- `POST /devices/register` (patient)
- `POST /vitals/upload` (patient/device)
- `GET /audit/logs` (admin)

## “Attack” demo

Run:

- `npm run demo:attack`

It logs in, creates a signed prescription, then tampers with the JSON and shows signature verification failing.

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
