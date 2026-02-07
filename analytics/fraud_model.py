#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from pymongo import MongoClient


def iso_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(s: str) -> datetime:
    # Stored as ISO strings with "Z" suffix.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def clamp_int(value: Any, *, min_v: int, max_v: int, fallback: int) -> int:
    try:
        n = int(float(value))
    except Exception:
        return fallback
    if n < min_v:
        return min_v
    if n > max_v:
        return max_v
    return n


def floor_bucket(dt: datetime, bucket_minutes: int) -> datetime:
    bucket_seconds = bucket_minutes * 60
    ts = int(dt.timestamp())
    floored = (ts // bucket_seconds) * bucket_seconds
    return datetime.fromtimestamp(floored, tz=timezone.utc)


ACTION_WEIGHTS: dict[str, int] = {
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
    "dispense.blocked": 8,
}


def weight_for_action(action: str) -> int:
    if action.startswith("anomaly."):
        return 10
    return ACTION_WEIGHTS.get(action, 0)


@dataclass
class UserRisk:
    user_id: str
    score: int = 0
    counts: dict[str, int] = None  # type: ignore
    reasons: set[str] = None  # type: ignore

    def __post_init__(self) -> None:
        if self.counts is None:
            self.counts = {}
        if self.reasons is None:
            self.reasons = set()


@dataclass
class IdentifierRisk:
    identifier: str
    score: int = 0
    counts: dict[str, int] = None  # type: ignore

    def __post_init__(self) -> None:
        if self.counts is None:
            self.counts = {}


def main() -> int:
    p = argparse.ArgumentParser(description="MVP fraud analytics from audit logs")
    p.add_argument("--window-hours", type=int, default=24)
    p.add_argument("--bucket-minutes", type=int, default=60)
    p.add_argument("--max-entries", type=int, default=5000)
    p.add_argument("--out", type=str, default="")
    args = p.parse_args()

    window_hours = clamp_int(args.window_hours, min_v=1, max_v=24 * 30, fallback=24)
    bucket_minutes = clamp_int(args.bucket_minutes, min_v=5, max_v=60, fallback=60)
    max_entries = clamp_int(args.max_entries, min_v=200, max_v=20000, fallback=5000)

    mongo_uri = os.environ.get("MONGODB_URI", "").strip()
    if not mongo_uri:
        raise SystemExit("Missing MONGODB_URI env var")

    to_dt = datetime.now(tz=timezone.utc)
    from_dt = to_dt - timedelta(hours=window_hours)
    from_iso = from_dt.isoformat().replace("+00:00", "Z")
    to_iso = to_dt.isoformat().replace("+00:00", "Z")

    client = MongoClient(mongo_uri)
    db = client.get_default_database()
    coll = db["auditentries"]

    cursor = (
        coll.find({"ts": {"$gte": from_iso, "$lte": to_iso}}, {"_id": 0})
        .sort("ts", 1)
        .limit(max_entries)
    )
    entries = list(cursor)

    # Initialize series buckets
    series: dict[str, dict[str, Any]] = {}
    start_bucket = floor_bucket(from_dt, bucket_minutes)
    end_bucket = floor_bucket(to_dt, bucket_minutes)
    cur = start_bucket
    while cur <= end_bucket:
        key = cur.isoformat().replace("+00:00", "Z")
        series[key] = {
            "bucketStart": key,
            "total": 0,
            "loginFailed": 0,
            "loginSuccess": 0,
            "otpVerifyFailed": 0,
            "passwordResetRequested": 0,
            "passwordResetLocked": 0,
            "newDeviceStepUpIssued": 0,
            "clinicCodeIssued": 0,
            "dispenseBlocked": 0,
            "patientPreRegister": 0,
            "anomalies": 0,
        }
        cur += timedelta(minutes=bucket_minutes)

    action_counts: dict[str, int] = defaultdict(int)
    id_risk: dict[str, IdentifierRisk] = {}
    user_risk: dict[str, UserRisk] = {}

    def get_actor_user_id(e: dict[str, Any]) -> str | None:
        actor = e.get("actor") or {}
        details = e.get("details") or {}
        for k in ("userId", "patientId"):
            v = actor.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        for k in ("patientId", "pharmacistId", "unlockedUserId"):
            v = details.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return None

    for e in entries:
        action = str(e.get("action") or "")
        action_counts[action] += 1

        ts = e.get("ts")
        try:
            dt = parse_iso(str(ts))
        except Exception:
            continue
        b = floor_bucket(dt, bucket_minutes).isoformat().replace("+00:00", "Z")
        bucket = series.get(b)
        if bucket is None:
            bucket = {
                "bucketStart": b,
                "total": 0,
                "loginFailed": 0,
                "loginSuccess": 0,
                "otpVerifyFailed": 0,
                "passwordResetRequested": 0,
                "passwordResetLocked": 0,
                "newDeviceStepUpIssued": 0,
                "clinicCodeIssued": 0,
                "dispenseBlocked": 0,
                "patientPreRegister": 0,
                "anomalies": 0,
            }
            series[b] = bucket
        bucket["total"] += 1

        if action == "auth.login_failed":
            bucket["loginFailed"] += 1
            ident = (e.get("actor") or {}).get("identifier")
            if isinstance(ident, str) and ident.strip():
                key = ident.strip()
                r = id_risk.get(key) or IdentifierRisk(identifier=key)
                r.score += weight_for_action(action)
                r.counts[action] = r.counts.get(action, 0) + 1
                id_risk[key] = r
        if action == "auth.login_success":
            bucket["loginSuccess"] += 1
        if action == "auth.otp_verify_failed":
            bucket["otpVerifyFailed"] += 1
        if action == "auth.password_reset_requested":
            bucket["passwordResetRequested"] += 1
        if action == "auth.password_reset_locked":
            bucket["passwordResetLocked"] += 1
        if action in ("auth.new_device_magic_link_sent", "auth.step_up_new_device_otp_issued"):
            bucket["newDeviceStepUpIssued"] += 1
        if action == "clinic.code_issued":
            bucket["clinicCodeIssued"] += 1
        if action == "dispense.blocked":
            bucket["dispenseBlocked"] += 1
        if action == "patient.pre_register":
            bucket["patientPreRegister"] += 1
        if action.startswith("anomaly."):
            bucket["anomalies"] += 1

        uid = get_actor_user_id(e)
        if uid:
            ur = user_risk.get(uid) or UserRisk(user_id=uid)
            w = weight_for_action(action)
            extra = 0
            reason = None
            if action == "patient.pre_register":
                details = e.get("details") or {}
                trust_score = details.get("trustScore")
                if isinstance(trust_score, (int, float)) and trust_score < 50:
                    extra += 6
                    reason = f"low_trust_score:{trust_score}"
            ur.score += w + extra
            ur.counts[action] = ur.counts.get(action, 0) + 1
            if reason:
                ur.reasons.add(reason)
            det_reason = (e.get("details") or {}).get("reason")
            if isinstance(det_reason, str) and det_reason.strip():
                ur.reasons.add(det_reason.strip()[:160])
            user_risk[uid] = ur

    top_actions = sorted(
        [{"action": a, "count": c} for a, c in action_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:20]

    series_list = [series[k] for k in sorted(series.keys())]
    totals = {
        "events": sum(b["total"] for b in series_list),
        "loginFailed": sum(b["loginFailed"] for b in series_list),
        "loginSuccess": sum(b["loginSuccess"] for b in series_list),
        "otpVerifyFailed": sum(b["otpVerifyFailed"] for b in series_list),
        "passwordResetRequested": sum(b["passwordResetRequested"] for b in series_list),
        "passwordResetLocked": sum(b["passwordResetLocked"] for b in series_list),
        "newDeviceStepUpIssued": sum(b["newDeviceStepUpIssued"] for b in series_list),
        "clinicCodeIssued": sum(b["clinicCodeIssued"] for b in series_list),
        "dispenseBlocked": sum(b["dispenseBlocked"] for b in series_list),
        "patientPreRegister": sum(b["patientPreRegister"] for b in series_list),
        "anomalies": sum(b["anomalies"] for b in series_list),
    }

    risky_users = sorted(
        [
            {
                "userId": u.user_id,
                "score": u.score,
                "counts": u.counts,
                "reasons": sorted(list(u.reasons))[:5],
            }
            for u in user_risk.values()
        ],
        key=lambda x: x["score"],
        reverse=True,
    )[:20]

    risky_ids = sorted(
        [
            {"identifier": r.identifier, "score": r.score, "counts": r.counts}
            for r in id_risk.values()
        ],
        key=lambda x: x["score"],
        reverse=True,
    )[:20]

    out = {
        "ok": True,
        "ts": iso_now(),
        "windowHours": window_hours,
        "bucketMinutes": bucket_minutes,
        "from": from_iso,
        "to": to_iso,
        "counts": {"entries": len(entries), "maxEntries": max_entries},
        "totals": totals,
        "topActions": top_actions,
        "series": series_list,
        "riskyUsers": risky_users,
        "riskyIdentifiers": risky_ids,
    }

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
    else:
        print(json.dumps(out, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

