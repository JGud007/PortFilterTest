"""Checker mode: probe a target host from outside the network.

Run this from a machine *outside* the network you are testing (a VPS, another
broadband connection, or a phone on cellular). It points at the public IP of
the connection whose ISP filtering you want to test.

Status meanings:

``open``
    Our listener answered with the magic token. Inbound traffic reaches the
    host: the port is *not* being filtered.
``refused``
    The host responded (TCP RST, or an ICMP port-unreachable for UDP) but no
    listener answered. Traffic still reached the host, so the port is *not*
    filtered -- the listener just was not running on it.
``timeout``
    Nothing came back. The SYN/datagram was most likely dropped, which is what
    ISP filtering looks like. (A silent router/NAT can look the same; use the
    control port to disambiguate.)
``error``
    A network/host error unrelated to filtering.
``skipped``
    A port that cannot be tested (for example, port 0).
"""

from __future__ import annotations

import errno
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Sequence

from .ports import PortSpec
from .protocol import CHECK_REQUEST, is_valid_response

OPEN = "open"
REFUSED = "refused"
TIMEOUT = "timeout"
ERROR = "error"
SKIPPED = "skipped"


@dataclass
class Result:
    port: int
    name: str
    proto: str
    status: str
    detail: str = ""
    control: bool = False


def _probe_tcp(host: str, port: int, timeout: float, token: str | None) -> tuple[str, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
            except socket.timeout:
                return REFUSED, "connected, but no responder payload"
            except OSError as exc:
                return REFUSED, f"connected; read failed: {exc}"
        if is_valid_response(data, token):
            return OPEN, "responder reached"
        return REFUSED, "replied, but not our responder"
    except ConnectionRefusedError:
        return REFUSED, "connection refused (reached host, nothing listening)"
    except socket.timeout:
        return TIMEOUT, "no response (dropped -> possibly filtered)"
    except OSError as exc:
        return ERROR, exc.strerror or str(exc)


def _probe_udp(host: str, port: int, timeout: float, token: str | None) -> tuple[str, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.send(CHECK_REQUEST)
        try:
            data = sock.recv(256)
        except socket.timeout:
            return TIMEOUT, "no reply (no responder, or dropped -> possibly filtered)"
        except ConnectionRefusedError:
            return REFUSED, "ICMP port unreachable (reached host, nothing listening)"
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ECONNREFUSED:
                return REFUSED, "ICMP port unreachable (reached host, nothing listening)"
            return ERROR, exc.strerror or str(exc)
        if is_valid_response(data, token):
            return OPEN, "responder reached"
        return REFUSED, "replied, but not our responder"
    except OSError as exc:
        return ERROR, exc.strerror or str(exc)
    finally:
        sock.close()


def check(
    host: str,
    specs: Sequence[PortSpec],
    timeout: float = 5.0,
    workers: int = 32,
    token: str | None = None,
) -> list[Result]:
    """Probe ``host`` on every active protocol of every spec."""
    jobs: list[tuple[str, PortSpec, str | None]] = []
    for spec in specs:
        if spec.unsupported:
            jobs.append(("skip", spec, None))
        else:
            for proto in spec.protocols:
                jobs.append(("probe", spec, proto))

    def run(job: tuple[str, PortSpec, str | None]) -> Result:
        kind, spec, proto = job
        if kind == "skip":
            return Result(
                spec.port, spec.name, "-", SKIPPED, spec.note or "unsupported", spec.control
            )
        probe = _probe_tcp if proto == "tcp" else _probe_udp
        status, detail = probe(host, spec.port, timeout, token)
        return Result(spec.port, spec.name, proto, status, detail, spec.control)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        return list(executor.map(run, jobs))
