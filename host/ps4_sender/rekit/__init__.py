"""Offline, read-only PS4 reverse-engineering helpers.

The package intentionally does not patch firmware, authenticate to PSN,
extract secrets, decrypt SELF containers or send anything over the network.
"""

__all__ = ["binary", "orbis", "nids", "ghidra_bridge", "psf", "symbols", "netmap", "dynlib", "report"]
