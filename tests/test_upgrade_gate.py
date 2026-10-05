"""Real loopback WebSocket handshakes and masked-frame authorization tests."""

from __future__ import annotations

import unittest
import socket

from websocket_upgrade_origin_gate import GateDecision, GateServer, SessionRegistry, UpgradeGate
from websocket_upgrade_origin_gate.gate import _session_cookie

from lab_support import LoopbackPages, websocket_exchange


class CookieOnlyTestBaseline(UpgradeGate):
    """Deliberately weak owned fixture, excluded from the runtime wheel."""

    def authorize(self, headers, expected_host):
        label = self.sessions.label_if_valid(_session_cookie(headers))
        return GateDecision(label is not None, "cookie_only_baseline", label)


class UpgradeGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pages = LoopbackPages()
        self.pages.__enter__()
        self.sessions = SessionRegistry()
        self.valid = self.sessions.issue("valid_synthetic_session")
        self.revoked = self.sessions.issue("revoked_synthetic_session")
        self.sessions.revoke(self.revoked)
        self.gate = UpgradeGate(allowed_origin=self.pages.a_origin, sessions=self.sessions)
        self.server = GateServer(self.gate)
        self.server.__enter__()
        self.pages.ws_url = f"ws://127.0.0.1:{self.server.server_port}/socket"

    def tearDown(self) -> None:
        self.server.__exit__(None, None, None)
        self.pages.__exit__(None, None, None)

    def exchange(self, **overrides):
        options = {"origin": self.pages.a_origin, "cookie": f"lab_session={self.valid}"}
        options.update(overrides)
        return websocket_exchange(self.server.server_port, **options)

    def assert_rejected_before_application(self, response, reason: str) -> None:
        self.assertEqual(response["status"], 403)
        self.assertIsNone(response["ack"])
        snapshot = self.server.snapshot()
        self.assertEqual(snapshot["message_count"], 0)
        self.assertEqual(snapshot["events"][-1]["reason"], reason)
        self.assertFalse(snapshot["events"][-1]["accepted"])

    def test_allowed_origin_and_live_session_exchange_ping(self) -> None:
        response = self.exchange()
        self.assertEqual(response["status"], 101)
        self.assertTrue(response["ack"])
        snapshot = self.server.snapshot()
        self.assertEqual(snapshot["message_count"], 1)
        self.assertEqual(snapshot["events"][-1]["session_label"], "valid_synthetic_session")

    def test_other_page_origin_with_valid_cookie_is_rejected(self) -> None:
        self.assert_rejected_before_application(
            self.exchange(origin=self.pages.b_origin), "origin_not_allowed"
        )

    def test_missing_and_empty_origin_are_rejected(self) -> None:
        self.assert_rejected_before_application(self.exchange(origin=None), "origin_required")
        self.assert_rejected_before_application(self.exchange(origin=""), "origin_required")

    def test_forged_and_revoked_cookie_are_rejected(self) -> None:
        self.assert_rejected_before_application(
            self.exchange(cookie="lab_session=forged_synthetic_token"), "session_invalid"
        )
        self.assert_rejected_before_application(
            self.exchange(cookie=f"lab_session={self.revoked}"), "session_invalid"
        )

    def test_missing_and_ambiguous_cookie_are_rejected(self) -> None:
        self.assert_rejected_before_application(self.exchange(cookie=None), "session_invalid")
        self.assert_rejected_before_application(
            self.exchange(cookie=f"lab_session={self.valid}; lab_session={self.valid}"),
            "session_invalid",
        )
        self.assert_rejected_before_application(
            self.exchange(extra_headers=(("Cookie", f"lab_session={self.valid}"),)),
            "session_invalid",
        )

    def test_wrong_target_host_is_rejected(self) -> None:
        self.assert_rejected_before_application(
            self.exchange(host="127.0.0.1:1"), "target_host_mismatch"
        )

    def test_untrusted_origin_and_host_values_never_enter_events(self) -> None:
        self.assertEqual(
            self.exchange(host="127.0.0.1:1-token-" + self.valid)["status"], 403
        )
        self.assertEqual(
            self.exchange(origin=self.pages.a_origin + "/?token=" + self.valid)["status"], 403
        )
        events = self.server.snapshot()["events"]
        self.assertEqual(len(events), 2)
        self.assertIsNone(events[0]["host"])
        self.assertIsNone(events[1]["origin"])
        self.assertNotIn(self.valid, repr(events))
        self.assertEqual(self.server.snapshot()["message_count"], 0)

    def test_incomplete_pre_handshake_request_times_out(self) -> None:
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall(b"GET /socket HTTP/1.1\r\nHost: ")
            self.assertEqual(connection.recv(1), b"")
        self.assertEqual(self.server.snapshot()["message_count"], 0)

    def test_duplicate_origin_is_rejected(self) -> None:
        self.assert_rejected_before_application(
            self.exchange(extra_headers=(("Origin", self.pages.a_origin),)), "origin_required"
        )

    def test_invalid_websocket_key_rejected_before_policy(self) -> None:
        response = self.exchange(key="invalid")
        self.assertEqual(response["status"], 400)
        self.assertEqual(self.server.snapshot()["message_count"], 0)
        self.assertEqual(self.server.snapshot()["events"][-1]["reason"], "upgrade_headers_invalid")

    def test_weak_cookie_only_fixture_accepts_other_origin(self) -> None:
        baseline = CookieOnlyTestBaseline(
            allowed_origin=self.pages.a_origin, sessions=self.sessions
        )
        with GateServer(baseline) as weak_server:
            response = websocket_exchange(
                weak_server.server_port,
                origin=self.pages.b_origin,
                cookie=f"lab_session={self.valid}",
            )
            self.assertEqual(response["status"], 101)
            self.assertTrue(response["ack"])
            self.assertEqual(weak_server.snapshot()["message_count"], 1)

    def test_two_distinct_local_page_origins_are_live(self) -> None:
        self.assertEqual(self.pages.fetch_both_pages(), [200, 200])
        self.assertNotEqual(self.pages.a_origin, self.pages.b_origin)
        self.assertEqual([x["origin"] for x in self.pages.page_requests()], ["A", "B"])

    def test_allowed_page_origin_must_be_an_exact_origin(self) -> None:
        with self.assertRaises(ValueError):
            UpgradeGate(allowed_origin=self.pages.a_origin + "/path", sessions=self.sessions)


if __name__ == "__main__":
    unittest.main()
