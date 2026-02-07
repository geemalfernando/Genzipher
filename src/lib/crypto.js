import crypto from "node:crypto";
import { stableStringify } from "./stableJson.js";

export function sha256Base64url(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(String(input));
  const digest = crypto.createHash("sha256").update(buffer).digest();
  return digest
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export function randomId(prefix = "") {
  const id = crypto.randomBytes(16).toString("hex");
  return prefix ? `${prefix}_${id}` : id;
}

export function nowIso() {
  return new Date().toISOString();
}

export function generateEd25519KeyPairPem() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

export function signObjectEd25519({ obj, privateKeyPem }) {
  const message = Buffer.from(stableStringify(obj));
  const signature = crypto.sign(null, message, privateKeyPem);
  return signature
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export function verifyObjectEd25519({ obj, signatureB64url, publicKeyPem }) {
  const message = Buffer.from(stableStringify(obj));
  const signature = Buffer.from(
    signatureB64url.replaceAll("-", "+").replaceAll("_", "/"),
    "base64"
  );
  return crypto.verify(null, message, publicKeyPem, signature);
}

export function verifyObjectEs256({ obj, signatureB64url, publicKeyPem }) {
  const message = Buffer.from(stableStringify(obj));
  const signature = Buffer.from(
    signatureB64url.replaceAll("-", "+").replaceAll("_", "/"),
    "base64"
  );
  return crypto.verify("sha256", message, publicKeyPem, signature);
}

export function aes256gcmEncrypt({ plaintext, keyB64 }) {
  const key = Buffer.from(keyB64, "base64");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    ivB64: iv.toString("base64"),
    tagB64: tag.toString("base64"),
    ciphertextB64: ciphertext.toString("base64"),
  };
}

export function aes256gcmDecrypt({ ivB64, tagB64, ciphertextB64, keyB64 }) {
  const key = Buffer.from(keyB64, "base64");
  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const ciphertext = Buffer.from(ciphertextB64, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
  return plaintext;
}
