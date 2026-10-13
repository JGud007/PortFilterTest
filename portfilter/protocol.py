"""Wire format shared by the listener and the probing client.

The listener answers with a fixed magic token so the checker can prove that the
bytes it received came from *our* responder and not from a captive portal, a
router login page, or a "this port is blocked" page injected by the ISP.

It is deliberately tiny: one line, a magic prefix, a version, and an optional
shared token.
"""

from __future__ import annotations

VERSION = b"1"
MAGIC = b"PORTFILTER-OK"

# Sent by the UDP checker so the listener knows the datagram is a probe.
CHECK_REQUEST = b"PORTFILTER-CHECK\n"


def build_response(token: str | None = None) -> bytes:
    """Bytes the listener sends back to every connection/datagram."""
    line = MAGIC + b" " + VERSION
    if token:
        line += b" " + token.encode("utf-8", "replace")
    return line + b"\n"


def is_valid_response(data: bytes, token: str | None = None) -> bool:
    """True when ``data`` looks like a response from our listener."""
    if not data or MAGIC not in data:
        return False
    if token and token.encode("utf-8", "replace") not in data:
        return False
    return True
