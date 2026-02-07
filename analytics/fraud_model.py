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
    "patient.device_bind_failed": 4,
    "dispense.blocked": 8,
    "vitals.upload_rejected": 6,
    "vitals.read_break_glass": 12,
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
    last_ts: str | None = None

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
    last_ts: str | None = None

    def __post_init__(self) -> None:
        if self.counts is None:
            self.counts = {}


def mask_ip(ip: Any) -> str | None:
    if not isinstance(ip, str):
        return None
    s = ip.strip()
    if not s:
        return None
    if "." in s:
        parts = s.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.x"
    if ":" in s:
        parts = [p for p in s.split(":") if p]
        return f"{':'.join(parts[:3])}:…"
    return f"{s[:8]}…"


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
            "loginBlocked": 0,
            "otpIssued": 0,
            "otpVerified": 0,
            "otpResent": 0,
            "otpVerifyFailed": 0,
            "passwordResetRequested": 0,
            "passwordResetOtpVerified": 0,
            "passwordResetCompleted": 0,
            "passwordResetLocked": 0,
            "magicLinkSent": 0,
            "magicLinkConsumed": 0,
            "newDeviceStepUpIssued": 0,
            "newDeviceStepUpVerified": 0,
            "trustedDeviceAdded": 0,
            "trustedDeviceRemoveRequested": 0,
            "trustedDeviceRevoked": 0,
            "clinicCodeIssued": 0,
            "patientVerificationCodeIssued": 0,
            "patientVerified": 0,
            "deviceBindRequested": 0,
            "deviceBound": 0,
            "deviceBindFailed": 0,
            "vitalsRead": 0,
            "vitalsReadBreakGlass": 0,
            "vitalsUploaded": 0,
            "vitalsUploadRejected": 0,
            "dispenseAllowed": 0,
            "dispenseBlocked": 0,
            "patientPreRegister": 0,
            "appointmentCreated": 0,
            "rxCreated": 0,
            "batchRegistered": 0,
            "biometricEnrolled": 0,
            "biometricVerified": 0,
            "pharmacistRegistered": 0,
            "anomalies": 0,
        }
        cur += timedelta(minutes=bucket_minutes)

    action_counts: dict[str, int] = defaultdict(int)
    id_risk: dict[str, IdentifierRisk] = {}
    user_risk: dict[str, UserRisk] = {}
    alerts: list[dict[str, Any]] = []

    SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def push_alert(
        *,
        ts: str | None,
        severity: str,
        type_: str,
        title: str,
        actor: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        if len(alerts) >= 600:
            return
        s = severity if severity in SEVERITY_RANK else "info"
        alerts.append(
            {
                "ts": ts or iso_now(),
                "severity": s,
                "type": type_[:64],
                "title": title[:160],
                "actor": actor or {},
                "details": details or {},
            }
        )

    def build_alert_actor(e: dict[str, Any]) -> dict[str, Any]:
        actor = e.get("actor") or {}
        out: dict[str, Any] = {}
        for k in ("userId", "username", "role", "identifier"):
            v = actor.get(k)
            if isinstance(v, str) and v.strip():
                out[k] = v.strip()
        return out

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
                "loginBlocked": 0,
                "otpIssued": 0,
                "otpVerified": 0,
                "otpResent": 0,
                "otpVerifyFailed": 0,
                "passwordResetRequested": 0,
                "passwordResetOtpVerified": 0,
                "passwordResetCompleted": 0,
                "passwordResetLocked": 0,
                "magicLinkSent": 0,
                "magicLinkConsumed": 0,
                "newDeviceStepUpIssued": 0,
                "newDeviceStepUpVerified": 0,
                "trustedDeviceAdded": 0,
                "trustedDeviceRemoveRequested": 0,
                "trustedDeviceRevoked": 0,
                "clinicCodeIssued": 0,
                "patientVerificationCodeIssued": 0,
                "patientVerified": 0,
                "deviceBindRequested": 0,
                "deviceBound": 0,
                "deviceBindFailed": 0,
                "vitalsRead": 0,
                "vitalsReadBreakGlass": 0,
                "vitalsUploaded": 0,
                "vitalsUploadRejected": 0,
                "dispenseAllowed": 0,
                "dispenseBlocked": 0,
                "patientPreRegister": 0,
                "appointmentCreated": 0,
                "rxCreated": 0,
                "batchRegistered": 0,
                "biometricEnrolled": 0,
                "biometricVerified": 0,
                "pharmacistRegistered": 0,
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
                r.last_ts = str(e.get("ts") or "") or r.last_ts
                id_risk[key] = r
        if action == "auth.login_success":
            bucket["loginSuccess"] += 1
        if action == "auth.login_blocked":
            bucket["loginBlocked"] += 1
        if action == "auth.otp_issued":
            bucket["otpIssued"] += 1
        if action == "auth.otp_verified":
            bucket["otpVerified"] += 1
        if action == "auth.otp_resent":
            bucket["otpResent"] += 1
        if action == "auth.otp_verify_failed":
            bucket["otpVerifyFailed"] += 1
        if action == "auth.password_reset_requested":
            bucket["passwordResetRequested"] += 1
        if action == "auth.password_reset_otp_verified":
            bucket["passwordResetOtpVerified"] += 1
        if action == "auth.password_reset_completed":
            bucket["passwordResetCompleted"] += 1
        if action == "auth.password_reset_locked":
            bucket["passwordResetLocked"] += 1
        if action in ("auth.new_device_magic_link_sent", "auth.step_up_new_device_otp_issued"):
            bucket["newDeviceStepUpIssued"] += 1
        if action == "auth.new_device_magic_link_sent":
            bucket["magicLinkSent"] += 1
        if action == "auth.new_device_magic_link_consumed":
            bucket["magicLinkConsumed"] += 1
            bucket["newDeviceStepUpVerified"] += 1
        if action == "auth.step_up_new_device_verified":
            bucket["newDeviceStepUpVerified"] += 1
        if action == "auth.trusted_device_added":
            bucket["trustedDeviceAdded"] += 1
        if action == "auth.trusted_device_remove_requested":
            bucket["trustedDeviceRemoveRequested"] += 1
        if action == "auth.trusted_device_revoked":
            bucket["trustedDeviceRevoked"] += 1
        if action == "clinic.code_issued":
            bucket["clinicCodeIssued"] += 1
        if action == "patient.verification_code_issued":
            bucket["patientVerificationCodeIssued"] += 1
        if action == "patient.verified":
            bucket["patientVerified"] += 1
        if action == "patient.device_bind_requested":
            bucket["deviceBindRequested"] += 1
        if action == "patient.device_bound":
            bucket["deviceBound"] += 1
        if action == "patient.device_bind_failed":
            bucket["deviceBindFailed"] += 1
        if action == "vitals.read":
            bucket["vitalsRead"] += 1
        if action == "vitals.read_break_glass":
            bucket["vitalsReadBreakGlass"] += 1
        if action == "vitals.upload":
            bucket["vitalsUploaded"] += 1
        if action == "vitals.upload_rejected":
            bucket["vitalsUploadRejected"] += 1
        if action == "dispense.allowed":
            bucket["dispenseAllowed"] += 1
        if action == "dispense.blocked":
            bucket["dispenseBlocked"] += 1
        if action == "patient.pre_register":
            bucket["patientPreRegister"] += 1
        if action == "appointment.created":
            bucket["appointmentCreated"] += 1
        if action == "rx.create":
            bucket["rxCreated"] += 1
        if action == "batch.register":
            bucket["batchRegistered"] += 1
        if action == "biometric.enrolled":
            bucket["biometricEnrolled"] += 1
        if action == "biometric.verified":
            bucket["biometricVerified"] += 1
        if action == "pharmacist.registered":
            bucket["pharmacistRegistered"] += 1
        if action.startswith("anomaly."):
            bucket["anomalies"] += 1

        if action.startswith("anomaly."):
            details = e.get("details") or {}
            push_alert(
                ts=str(e.get("ts") or "") or None,
                severity="high" if action == "anomaly.password_reset_rate_limited" else "medium",
                type_=action,
                title=f"Anomaly detected: {action}",
                actor=build_alert_actor(e),
                details={
                    "reason": (details.get("reason") or "")[:160] if isinstance(details.get("reason"), str) else None,
                    "ipReuseCount": details.get("ipReuseCount"),
                    "countLastHour": details.get("countLastHour"),
                    "deviceId": details.get("deviceId"),
                    "ip": mask_ip(details.get("ip")),
                },
            )

        if action == "auth.password_reset_locked":
            det = e.get("details") or {}
            push_alert(
                ts=str(e.get("ts") or "") or None,
                severity="high",
                type_=action,
                title="Password reset locked (OTP attempts exceeded)",
                actor=build_alert_actor(e),
                details={"otpRequestId": det.get("otpRequestId")},
            )

        if action == "dispense.blocked":
            det = e.get("details") or {}
            push_alert(
                ts=str(e.get("ts") or "") or None,
                severity="critical",
                type_=action,
                title="Dispense blocked (integrity/provenance failure)",
                actor=build_alert_actor(e),
                details={"recordId": det.get("recordId"), "rxId": det.get("rxId"), "batchId": det.get("batchId")},
            )

        if action == "patient.device_bind_failed":
            det = e.get("details") or {}
            push_alert(
                ts=str(e.get("ts") or "") or None,
                severity="medium",
                type_=action,
                title="Device binding failed (bad signature)",
                actor=build_alert_actor(e),
                details={"deviceId": det.get("deviceId"), "reason": det.get("reason")},
            )

        if action == "vitals.upload_rejected":
            det = e.get("details") or {}
            push_alert(
                ts=str(e.get("ts") or "") or None,
                severity="high",
                type_=action,
                title="Vitals upload rejected (bad signature)",
                actor=build_alert_actor(e),
                details={"deviceId": det.get("deviceId"), "reason": det.get("reason")},
            )

        if action == "vitals.read_break_glass":
            det = e.get("details") or {}
            push_alert(
                ts=str(e.get("ts") or "") or None,
                severity="high",
                type_=action,
                title="Break-glass vitals access",
                actor=build_alert_actor(e),
                details={"patientToken": det.get("patientToken"), "returned": det.get("returned")},
            )

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
            ur.last_ts = str(e.get("ts") or "") or ur.last_ts
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
        "loginBlocked": sum(b["loginBlocked"] for b in series_list),
        "otpIssued": sum(b["otpIssued"] for b in series_list),
        "otpVerified": sum(b["otpVerified"] for b in series_list),
        "otpResent": sum(b["otpResent"] for b in series_list),
        "otpVerifyFailed": sum(b["otpVerifyFailed"] for b in series_list),
        "passwordResetRequested": sum(b["passwordResetRequested"] for b in series_list),
        "passwordResetOtpVerified": sum(b["passwordResetOtpVerified"] for b in series_list),
        "passwordResetCompleted": sum(b["passwordResetCompleted"] for b in series_list),
        "passwordResetLocked": sum(b["passwordResetLocked"] for b in series_list),
        "magicLinkSent": sum(b["magicLinkSent"] for b in series_list),
        "magicLinkConsumed": sum(b["magicLinkConsumed"] for b in series_list),
        "newDeviceStepUpIssued": sum(b["newDeviceStepUpIssued"] for b in series_list),
        "newDeviceStepUpVerified": sum(b["newDeviceStepUpVerified"] for b in series_list),
        "trustedDeviceAdded": sum(b["trustedDeviceAdded"] for b in series_list),
        "trustedDeviceRemoveRequested": sum(b["trustedDeviceRemoveRequested"] for b in series_list),
        "trustedDeviceRevoked": sum(b["trustedDeviceRevoked"] for b in series_list),
        "clinicCodeIssued": sum(b["clinicCodeIssued"] for b in series_list),
        "patientVerificationCodeIssued": sum(b["patientVerificationCodeIssued"] for b in series_list),
        "patientVerified": sum(b["patientVerified"] for b in series_list),
        "deviceBindRequested": sum(b["deviceBindRequested"] for b in series_list),
        "deviceBound": sum(b["deviceBound"] for b in series_list),
        "deviceBindFailed": sum(b["deviceBindFailed"] for b in series_list),
        "vitalsRead": sum(b["vitalsRead"] for b in series_list),
        "vitalsReadBreakGlass": sum(b["vitalsReadBreakGlass"] for b in series_list),
        "vitalsUploaded": sum(b["vitalsUploaded"] for b in series_list),
        "vitalsUploadRejected": sum(b["vitalsUploadRejected"] for b in series_list),
        "dispenseAllowed": sum(b["dispenseAllowed"] for b in series_list),
        "dispenseBlocked": sum(b["dispenseBlocked"] for b in series_list),
        "patientPreRegister": sum(b["patientPreRegister"] for b in series_list),
        "appointmentCreated": sum(b["appointmentCreated"] for b in series_list),
        "rxCreated": sum(b["rxCreated"] for b in series_list),
        "batchRegistered": sum(b["batchRegistered"] for b in series_list),
        "biometricEnrolled": sum(b["biometricEnrolled"] for b in series_list),
        "biometricVerified": sum(b["biometricVerified"] for b in series_list),
        "pharmacistRegistered": sum(b["pharmacistRegistered"] for b in series_list),
        "anomalies": sum(b["anomalies"] for b in series_list),
    }

    risky_users = sorted(
        [
            {
                "userId": u.user_id,
                "score": u.score,
                "counts": u.counts,
                "reasons": sorted(list(u.reasons))[:5],
                "lastTs": u.last_ts,
            }
            for u in user_risk.values()
        ],
        key=lambda x: x["score"],
        reverse=True,
    )[:20]

    risky_ids = sorted(
        [
            {"identifier": r.identifier, "score": r.score, "counts": r.counts, "lastTs": r.last_ts}
            for r in id_risk.values()
        ],
        key=lambda x: x["score"],
        reverse=True,
    )[:20]

    # Aggregate alerts (threshold-based)
    for r in risky_ids:
        fails = int((r.get("counts") or {}).get("auth.login_failed") or 0)
        if fails >= 10:
            push_alert(
                ts=r.get("lastTs") or to_iso,
                severity="high" if fails >= 20 else "medium",
                type_="bruteforce.identifier",
                title=f'Repeated login failures for "{str(r.get("identifier") or "")[:64]}"',
                actor={"identifier": r.get("identifier")},
                details={"loginFailed": fails, "windowHours": window_hours},
            )

    for u in risky_users:
        counts = u.get("counts") or {}
        otp_fails = int(counts.get("auth.otp_verify_failed") or 0)
        if otp_fails >= 5:
            push_alert(
                ts=u.get("lastTs") or to_iso,
                severity="high" if otp_fails >= 10 else "medium",
                type_="otp.abuse",
                title="Multiple OTP verification failures",
                actor={"userId": u.get("userId")},
                details={"otpVerifyFailed": otp_fails, "windowHours": window_hours},
            )
        bind_fails = int(counts.get("patient.device_bind_failed") or 0)
        if bind_fails >= 3:
            push_alert(
                ts=u.get("lastTs") or to_iso,
                severity="high" if bind_fails >= 6 else "medium",
                type_="device.bind_failures",
                title="Repeated device binding failures",
                actor={"userId": u.get("userId")},
                details={"deviceBindFailed": bind_fails, "windowHours": window_hours},
            )
        dispense_blocked = int(counts.get("dispense.blocked") or 0)
        if dispense_blocked >= 2:
            push_alert(
                ts=u.get("lastTs") or to_iso,
                severity="critical" if dispense_blocked >= 5 else "high",
                type_="dispense.blocked_repeated",
                title="Repeated blocked dispense attempts",
                actor={"userId": u.get("userId")},
                details={"dispenseBlocked": dispense_blocked, "windowHours": window_hours},
            )
        break_glass = int(counts.get("vitals.read_break_glass") or 0)
        if break_glass >= 1:
            push_alert(
                ts=u.get("lastTs") or to_iso,
                severity="critical" if break_glass >= 3 else "high",
                type_="vitals.break_glass",
                title="Break-glass vitals access observed",
                actor={"userId": u.get("userId")},
                details={"breakGlassReads": break_glass, "windowHours": window_hours},
            )

    alerts_out = sorted(
        alerts,
        key=lambda a: (SEVERITY_RANK.get(str(a.get("severity") or ""), 0), str(a.get("ts") or "")),
        reverse=True,
    )[:50]

    alert_totals: dict[str, Any] = {"total": len(alerts_out), "bySeverity": {}}
    for a in alerts_out:
        sev = str(a.get("severity") or "info")
        alert_totals["bySeverity"][sev] = int(alert_totals["bySeverity"].get(sev) or 0) + 1

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
        "alerts": alerts_out,
        "alertTotals": alert_totals,
    }

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
    else:
        print(json.dumps(out, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
