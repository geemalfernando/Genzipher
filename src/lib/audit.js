import { appendJsonl, readJson, writeJsonAtomic } from "./store.js";
import { nowIso, randomId, sha256Base64url } from "./crypto.js";
import { stableStringify } from "./stableJson.js";

export function computeAuditHash({ prevHash, entryWithoutHash }) {
  return sha256Base64url(`${prevHash}\n${stableStringify(entryWithoutHash)}`);
}

export async function initAudit({ auditMetaPath }) {
  const meta = await readJson(auditMetaPath, { headHash: "GENESIS" });
  return meta;
}

export async function auditAppend({
  auditLogPath,
  auditMetaPath,
  actor,
  action,
  details,
}) {
  const meta = await initAudit({ auditMetaPath });
  const prevHash = meta.headHash || "GENESIS";
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
  await appendJsonl(auditLogPath, entry);
  await writeJsonAtomic(auditMetaPath, { headHash: hash });
  return entry;
}
