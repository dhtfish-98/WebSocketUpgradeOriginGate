"""Machine-readable, two-origin weak-baseline/fixed Upgrade experiment."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from websocket_upgrade_origin_gate import GateDecision, GateServer, SessionRegistry, UpgradeGate
from websocket_upgrade_origin_gate.gate import _session_cookie

from lab_support import LoopbackPages, websocket_exchange


class CookieOnlyTestBaseline(UpgradeGate):
    """Deliberately weak local fixture; not part of the shipped package."""

    def authorize(self, headers, expected_host):
        label = self.sessions.label_if_valid(_session_cookie(headers))
        return GateDecision(label is not None, "cookie_only_baseline", label)


def run_case(server: GateServer, *, label: str, origin: str | None, cookie: str | None, host: str | None = None) -> dict[str, object]:
    before = server.snapshot()
    response = websocket_exchange(server.server_port, origin=origin, cookie=cookie, host=host)
    after = server.snapshot()
    return {
        "case": label,
        "request": {
            "origin": origin,
            "cookie_present": cookie is not None,
            "host": host if host is not None else server.expected_host,
            "path": "/socket",
            "version": "13",
        },
        "status": response["status"],
        "upgrade_accepted": response["status"] == 101,
        "ack_received": response["ack"],
        "server_events": after["events"][len(before["events"]):],
        "application_message_delta": after["message_count"] - before["message_count"],
    }


def run() -> dict[str, object]:
    with LoopbackPages() as pages:
        sessions = SessionRegistry()
        valid = sessions.issue("valid_synthetic_session")
        revoked = sessions.issue("revoked_synthetic_session")
        sessions.revoke(revoked)
        valid_cookie = f"lab_session={valid}"
        page_statuses = pages.fetch_both_pages()
        baseline_gate = CookieOnlyTestBaseline(allowed_origin=pages.a_origin, sessions=sessions)
        with GateServer(baseline_gate) as weak:
            weak_case = run_case(
                weak, label="weak_other_origin_valid_cookie", origin=pages.b_origin, cookie=valid_cookie
            )

        fixed_gate = UpgradeGate(allowed_origin=pages.a_origin, sessions=sessions)
        with GateServer(fixed_gate) as fixed:
            cases = [
                run_case(fixed, label="allowed_A_valid", origin=pages.a_origin, cookie=valid_cookie),
                run_case(fixed, label="other_B_valid", origin=pages.b_origin, cookie=valid_cookie),
                run_case(fixed, label="A_forged_cookie", origin=pages.a_origin, cookie="lab_session=forged_synthetic_token"),
                run_case(fixed, label="A_revoked_session", origin=pages.a_origin, cookie=f"lab_session={revoked}"),
                run_case(fixed, label="A_no_cookie", origin=pages.a_origin, cookie=None),
                run_case(fixed, label="missing_origin", origin=None, cookie=valid_cookie),
                run_case(fixed, label="empty_origin", origin="", cookie=valid_cookie),
                run_case(fixed, label="wrong_target_host", origin=pages.a_origin, cookie=valid_cookie, host="127.0.0.1:1"),
            ]
            fixed_snapshot = fixed.snapshot()

        expected_reasons = (
            "allowed", "origin_not_allowed", "session_invalid", "session_invalid",
            "session_invalid", "origin_required", "origin_required", "target_host_mismatch",
        )
        case_events_match = all(
            len(case["server_events"]) == 1
            and case["server_events"][0]["reason"] == expected_reason
            and case["server_events"][0]["status"] == case["status"]
            and case["server_events"][0]["accepted"] == (case["status"] == 101)
            for case, expected_reason in zip(cases, expected_reasons, strict=True)
        )

        checks = {
            "two_local_pages_served": page_statuses == [200, 200] and pages.a_origin != pages.b_origin,
            "weak_baseline_accepts_cross_origin": weak_case["status"] == 101 and weak_case["ack_received"] is True and weak_case["application_message_delta"] == 1,
            "fixed_allowed_origin_and_session_accepts": cases[0]["status"] == 101 and cases[0]["ack_received"] is True and cases[0]["application_message_delta"] == 1,
            "all_unauthorized_rejected_before_upgrade": all(case["status"] == 403 and not case["upgrade_accepted"] and case["application_message_delta"] == 0 for case in cases[1:]),
            "only_one_fixed_application_message": fixed_snapshot["message_count"] == 1,
            "each_fixed_case_has_one_matching_server_event": case_events_match and len(fixed_snapshot["events"]) == len(cases),
            "weak_case_has_one_matching_server_event": len(weak_case["server_events"]) == 1 and weak_case["server_events"][0]["reason"] == "cookie_only_baseline",
        }
        return {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "version": "0.1.1",
            "environment": "A/B HTTP pages plus WebSocket services bound to 127.0.0.1 on ephemeral ports",
            "origins": {"A": pages.a_origin, "B": pages.b_origin},
            "synthetic_session_sha256": hashlib.sha256(valid.encode()).hexdigest(),
            "synthetic_values": "not written into the receipt",
            "page_get_statuses": page_statuses,
            "page_requests": pages.page_requests(),
            "weak_baseline": weak_case,
            "fixed_cases": cases,
            "fixed_final_snapshot": fixed_snapshot,
            "checks": checks,
            "result": "PASS" if all(checks.values()) else "FAIL",
        }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: run_local_experiment.py OUTPUT_JSON")
    path = Path(sys.argv[1]).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    receipt = run()
    path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(receipt["result"], path)
    raise SystemExit(0 if receipt["result"] == "PASS" else 1)
