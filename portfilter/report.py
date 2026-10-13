"""Human-readable output for both modes."""

from __future__ import annotations

import sys
import time
import urllib.request
from typing import Sequence

from .checker import ERROR, OPEN, REFUSED, SKIPPED, TIMEOUT, Result

_LABELS = {
    OPEN: "OPEN",
    REFUSED: "REACHED",
    TIMEOUT: "TIMEOUT",
    ERROR: "ERROR",
    SKIPPED: "SKIPPED",
}

_COLORS = {
    OPEN: "\033[32m",
    REFUSED: "\033[33m",
    TIMEOUT: "\033[31m",
    ERROR: "\033[35m",
    SKIPPED: "\033[90m",
}
_RESET = "\033[0m"


def _color(text: str, status: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLORS.get(status, '')}{text}{_RESET}"


def fetch_public_ip(timeout: float = 4.0) -> str | None:
    """Best-effort public IP lookup, used only to print a helpful hint."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                ip = resp.read(64).decode("ascii", "ignore").strip()
                if ip:
                    return ip
        except Exception:
            continue
    return None


def print_server_banner(
    host: str,
    bound: Sequence[tuple],
    failures: Sequence[tuple],
    token: str | None,
    show_public_ip: bool,
    log_requests: bool = True,
    log_local: bool = False,
) -> None:
    print("Listening for inbound port-filtering probes")
    print(f"  bind address : {host}")
    print(f"  shared token : {token if token else '(none)'}")
    if show_public_ip:
        ip = fetch_public_ip()
        print(f"  public IP    : {ip or 'unavailable'}")
    if log_requests:
        if log_local:
            print("  request log  : all incoming requests (--log-local)")
        else:
            print("  request log  : external only (loopback/LAN peers omitted)")
    else:
        print("  request log  : disabled (--quiet)")
    print(f"  ports bound  : {len(bound)}")
    for spec, proto, _sock in sorted(bound, key=lambda b: (b[0].port, b[1])):
        print(f"      {proto:<3} {spec.port:<5} {spec.name}")
    if failures:
        print(f"  not bound    : {len(failures)}")
        for spec, proto, reason in failures:
            print(f"      {proto:<3} {spec.port:<5} {spec.name}  -- {reason}")
    print()
    print("Leave this running. From an external machine run:")
    print("      python -m portfilter check <your-public-ip>")
    if token:
        print(f"  (add --token {token})")
    print("Press Ctrl-C to stop.")
    print(flush=True)


def _table(rows: Sequence[tuple[str, str, str, str, str]], color: bool) -> None:
    headers = ("PORT", "SERVICE", "PROTO", "STATUS", "DETAIL")
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * w for w in widths))
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            if i == 3:
                cells.append(_color(cell.ljust(widths[i]), _status_key(cell), color))
            else:
                cells.append(cell.ljust(widths[i]))
        print("  ".join(cells).rstrip())


def _status_key(label: str) -> str:
    for status, text in _LABELS.items():
        if text == label:
            return status
    return ""


def render_results(
    results: Sequence[Result],
    target: str,
    resolved_ip: str,
    timeout: float,
    color: bool,
) -> None:
    shown = " ".join(sorted({r.proto for r in results if r.proto != "-"}))
    print(f"Target   : {target} ({resolved_ip})")
    print(f"Protocols: {shown or 'n/a'}    Timeout: {timeout:g}s")
    print()
    rows = [
        (str(r.port), r.name, r.proto.upper(), _LABELS.get(r.status, r.status.upper()), r.detail)
        for r in results
    ]
    _table(rows, color)
    print()


def render_summary(results: Sequence[Result], color: bool = True) -> None:
    control = [r for r in results if r.control]
    listed = [r for r in results if not r.control]

    def counts(items: Sequence[Result]) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in items:
            out[r.status] = out.get(r.status, 0) + 1
        return out

    print("Summary")
    print("-------")

    control_open = any(r.status == OPEN for r in control)
    control_counts = counts(control)
    if control:
        summary = ", ".join(f"{v} {k}" for k, v in sorted(control_counts.items()))
        print(f"  control port (8080)      : {summary}")
        if control_open:
            print("    -> External path works: inbound traffic reached this host.")
            print("       Results below reflect the ISP filter, not the router/NAT.")
        else:
            print("    -> WARNING: the control port did not answer.")
            print("       Inbound is likely blocked at the router (port forwarding /")
            print("       firewall) or the listener is not running. Listed-port")
            print("       timeouts are INCONCLUSIVE until the control port answers.")
    else:
        print("  control port             : excluded (--no-control)")

    listed_counts = counts(listed)
    reached = listed_counts.get(OPEN, 0) + listed_counts.get(REFUSED, 0)
    timed_out = listed_counts.get(TIMEOUT, 0)
    errored = listed_counts.get(ERROR, 0)
    skipped = listed_counts.get(SKIPPED, 0)

    print(f"  listed ports reachable   : {reached}")
    print(f"  listed ports timed out   : {timed_out}   (candidates for filtering)")
    if errored:
        print(f"  listed ports errored     : {errored}")
    if skipped:
        print(f"  listed ports skipped     : {skipped}")
    print()
    if timed_out == 0:
        print("  No listed port timed out: nothing on the block list appears filtered.")
    else:
        print("  A timeout means the probe got no response at all, which is what")
        print("  filtering looks like. Cross-check with the control port above:")
        print("  if the control port is open, the timed-out ports are filtered.")


def render_loop_round(
    round_no: int,
    interval: float,
    previous: Sequence[Result],
    results: Sequence[Result],
    color: bool,
) -> None:
    """Second and later rounds of --loop: print only what changed."""
    prev_map = {(r.port, r.proto): r.status for r in previous}
    changed = [r for r in results if prev_map.get((r.port, r.proto)) != r.status]

    print()
    print(f"Round {round_no}  [{time.strftime('%H:%M:%S')}]  interval {interval:g}s")
    if not changed:
        print("  no status changes")
        return
    print(f"  {len(changed)} change(s):")
    for r in changed:
        old = prev_map.get((r.port, r.proto), "?")
        old_label = _LABELS.get(old, old.upper())
        new_label = _LABELS.get(r.status, r.status.upper())
        line = (
            f"  {r.port}/{r.proto.upper():<4} "
            f"{_color(old_label, old, color):<9} -> {_color(new_label, r.status, color):<9} "
            f"{r.name}"
        )
        print(line)
