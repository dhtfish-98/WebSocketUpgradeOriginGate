"""Bounded local WebSocket upgrade authorization experiment."""

from .gate import GateDecision, GateServer, SessionRegistry, UpgradeGate

__version__ = "0.1.0"

__all__ = ["GateDecision", "GateServer", "SessionRegistry", "UpgradeGate", "__version__"]
