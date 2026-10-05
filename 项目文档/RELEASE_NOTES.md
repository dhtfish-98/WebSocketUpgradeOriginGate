# WebSocketUpgradeOriginGate 0.1.2

This patch updates the package version and release attribution to dhtfish98. The WebSocket handshake authorization policy, test-only weak baseline, raw socket cases and real Chrome A/B origin experiment are unchanged from 0.1.1.

The build gate must verify source and installed wheel behavior, sdist and wheel version/author/license metadata, real browser-origin evidence, and the exact release commit. The existing 0.1.1 Release and its wheel and sdist remain historical and are not overwritten. A 0.1.2 Release requires separate GitHub main/tag CI and downloaded asset verification.

The fixed `websockets` reference remains BSD-3-Clause with its original attribution; no upstream code is bundled. This lab does not establish a third-party vulnerability, production session security, or CVP eligibility.
