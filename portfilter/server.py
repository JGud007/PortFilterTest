"""Listener mode: bind the ports under test and answer probes.

Run this on the machine behind the ISP. It binds a TCP and/or UDP socket for
every port in the configured set and replies with the magic token from
:mod:`portfilter.protocol`.

Binding privileged ports (<1024) needs elevated privileges on Linux/macOS, and
most of the default list is below 1024 -- so run it with ``sudo`` (or a
capability grant) to test the full list. Ports it cannot bind are reported and
skipped rather than aborting the run.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from typing import Callable, Sequence

from . import report
from .ports import PortSpec
from .protocol import build_response

DEFAULT_BIND = "0.0.0.0"
_POLL_INTERVAL = 1.0  # so loops notice the stop event promptly


def _is_local_peer(peer_ip: str) -> bool:
    """True when the peer is on the same machine/network as the server.

    The external checker always comes from a public IP, so loopback, RFC1918
    private, and link-local source addresses are treated as local noise.
    Unparseable addresses are hidden too rather than risking log spam.
    """
    try:
        addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return True
    return addr.is_loopback or addr.is_private or addr.is_link_local


def _log_line(proto: str, port: int, peer: tuple[str, int], detail: str = "") -> None:
    """Print one request-log line: time, transport, local port, peer."""
    parts = [
        f"[{time.strftime('%H:%M:%S')}]",
        proto,
        f"port {port}",
        f"from {peer[0]}:{peer[1]}",
    ]
    if detail:
        parts.append(detail)
    print(" ".join(parts), flush=True)


def _bind(host: str, port: int, proto: str) -> socket.socket:
    if proto == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(32)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
    sock.settimeout(_POLL_INTERVAL)
    return sock


def _serve_tcp(
    sock: socket.socket, payload: bytes, stop: threading.Event, log: bool, log_local: bool
) -> None:
    while not stop.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        with conn:
            if log and (log_local or not _is_local_peer(addr[0])):
                _log_line("tcp", sock.getsockname()[1], addr)
            conn.settimeout(2.0)
            try:
                conn.sendall(payload)
            except OSError:
                pass


def _serve_udp(
    sock: socket.socket, payload: bytes, stop: threading.Event, log: bool, log_local: bool
) -> None:
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            return
        if not data:
            continue
        if log and (log_local or not _is_local_peer(addr[0])):
            _log_line("udp", sock.getsockname()[1], addr, f"{len(data)} bytes")
        try:
            sock.sendto(payload, addr)
        except OSError:
            pass


def _run_loop(
    fn: Callable[[socket.socket, bytes, threading.Event, bool, bool], None],
    sock: socket.socket,
    payload: bytes,
    stop: threading.Event,
    log: bool,
    log_local: bool,
) -> None:
    try:
        fn(sock, payload, stop, log, log_local)
    except OSError:
        pass


def run_server(
    host: str = DEFAULT_BIND,
    specs: Sequence[PortSpec] = (),
    timeout: float = 5.0,
    token: str | None = None,
    stop: threading.Event | None = None,
    announce: bool = True,
    show_public_ip: bool = False,
    log_requests: bool = True,
    log_local: bool = False,
) -> tuple[list[tuple[PortSpec, str, socket.socket]], list[tuple[PortSpec, str, str]]]:
    """Bind every port and serve until ``stop`` is set.

    Each accepted connection/datagram is logged to the console when
    ``log_requests`` is true. By default peers that are loopback, RFC1918
    private, or link-local are omitted from the log (the checker should always
    be external); set ``log_local`` to include them.

    Returns ``(bound, failures)`` where ``bound`` is a list of
    ``(spec, proto, socket)`` and ``failures`` is a list of
    ``(spec, proto, reason)``.
    """
    stop = stop or threading.Event()
    payload = build_response(token)

    bound: list[tuple[PortSpec, str, socket.socket]] = []
    failures: list[tuple[PortSpec, str, str]] = []

    for spec in specs:
        if spec.unsupported:
            failures.append((spec, "-", spec.note or "unsupported"))
            continue
        for proto in spec.protocols:
            try:
                sock = _bind(host, spec.port, proto)
            except PermissionError:
                failures.append(
                    (spec, proto, "permission denied (need root/sudo for ports <1024)")
                )
                continue
            except OSError as exc:
                reason = exc.strerror or str(exc)
                if getattr(exc, "errno", None) == 98:
                    reason = "address already in use"
                failures.append((spec, proto, reason))
                continue
            bound.append((spec, proto, sock))

    threads: list[threading.Thread] = []
    for spec, proto, sock in bound:
        target = _serve_tcp if proto == "tcp" else _serve_udp
        thread = threading.Thread(
            target=_run_loop,
            args=(target, sock, payload, stop, log_requests, log_local),
            name=f"{proto}:{spec.port}",
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    if announce:
        report.print_server_banner(
            host, bound, failures, token, show_public_ip, log_requests, log_local
        )

    try:
        while not stop.is_set():
            stop.wait(0.5)
    except KeyboardInterrupt:
        stop.set()
    finally:
        for _spec, _proto, sock in bound:
            try:
                sock.close()
            except OSError:
                pass
        for thread in threads:
            thread.join(timeout=2)

    return bound, failures
