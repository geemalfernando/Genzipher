import crypto from "node:crypto";
import fs from "node:fs/promises";
import { stableStringify } from "../src/lib/stableJson.js";

// Usage:
//   node scripts/device-sign.js gen-keys device_keys.json
//   node scripts/device-sign.js sign device_keys.json '{"deviceId":"wearable-01","nonce":"chal_..."}'
//
// Output signature is base64url, compatible with /auth/device-verify.

function base64urlEncode(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);

  if (cmd === "gen-keys") {
    const outPath = rest[0] || "device_keys.json";
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
    await fs.writeFile(outPath, JSON.stringify({ publicKeyPem, privateKeyPem }, null, 2));
    console.log(`Wrote ${outPath}`);
    console.log("Use publicKeyPem in the UI, keep privateKeyPem secret.");
    return;
  }

  if (cmd === "sign") {
    const keysPath = rest[0];
    const payloadJson = rest[1];
    if (!keysPath || !payloadJson) throw new Error("sign requires: keysPath payloadJson");
    const keys = JSON.parse(await fs.readFile(keysPath, "utf8"));
    const payload = JSON.parse(payloadJson);
    const message = Buffer.from(stableStringify(payload));
    const signature = crypto.sign(null, message, keys.privateKeyPem);
    console.log(base64urlEncode(signature));
    return;
  }

  console.log("Commands: gen-keys | sign");
  process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
