import crypto from "node:crypto";
import { base64urlDecodeToBuffer, base64urlEncode } from "./base64url.js";

function signHs256({ headerB64, payloadB64, secret }) {
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(`${headerB64}.${payloadB64}`);
  return base64urlEncode(hmac.digest());
}

export function jwtSignHs256({ payload, secret, expiresInSeconds = 900 }) {
  const header = { alg: "HS256", typ: "JWT" };
  const nowSeconds = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iat: nowSeconds,
    exp: nowSeconds + expiresInSeconds,
  };

  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(fullPayload));
  const sigB64 = signHs256({ headerB64, payloadB64, secret });
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

export function jwtVerifyHs256({ token, secret }) {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, error: "invalid_token" };
  const [headerB64, payloadB64, sigB64] = parts;
  const expectedSigB64 = signHs256({ headerB64, payloadB64, secret });
  const sigBuf = Buffer.from(sigB64);
  const expectedBuf = Buffer.from(expectedSigB64);
  if (sigBuf.length !== expectedBuf.length) return { ok: false, error: "bad_signature" };
  if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return { ok: false, error: "bad_signature" };
  }

  const payloadJson = base64urlDecodeToBuffer(payloadB64).toString("utf8");
  const payload = JSON.parse(payloadJson);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && nowSeconds > payload.exp) {
    return { ok: false, error: "expired" };
  }
  return { ok: true, payload };
}
