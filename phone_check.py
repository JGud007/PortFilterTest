#!/usr/bin/env python3
"""Standalone inbound port-filtering checker for a phone.

This is a single-file build of ``portfilter check`` with no dependency on the
rest of the project: copy it to your phone (Termux / a-Shell / any Python 3),
then run it from *outside* the network you are testing, e.g.:

    python3 phone_check.py 203.0.113.45
    python3 phone_check.py 203.0.113.45 --token s3cret --timeout 3
    python3 phone_check.py 203.0.113.45 --ports 80,443,8080
    python3 phone_check.py 203.0.113.45 --loop        # re-check every 15s
    python3 phone_check.py 203.0.113.45 --loop 5      # re-check every 5s

Output is one line per port so it reads well on a small screen.
Standard library only.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MAGIC = b"PORTFILTER-OK"
CHECK_REQUEST = b"PORTFILTER-CHECK\n"

# (port, name, tcp, udp, unsupported)
# Well-known service ports ISPs commonly filter + control port, matching portfilter/ports.py
PORTS = [
    (0, "Reserved / invalid destination port", False, False, True),
    (20, "FTP data", True, True, False),
    (21, "FTP control", True, True, False),
    (22, "SSH / SFTP", True, True, False),
    (23, "Telnet", True, True, False),
    (25, "SMTP", True, True, False),
    (53, "DNS", True, True, False),
    (67, "DHCP server / bootstrap", True, True, False),
    (68, "DHCP client / bootstrap", True, True, False),
    (80, "HTTP", True, True, False),
    (110, "POP3", True, True, False),
    (135, "MS RPC", True, True, False),
    (137, "NetBIOS name service", True, True, False),
    (138, "NetBIOS datagram", True, True, False),
    (139, "NetBIOS session", True, True, False),
    (143, "IMAP", True, True, False),
    (161, "SNMP", True, True, False),
    (162, "SNMP trap", True, True, False),
    (443, "HTTPS", True, True, False),
    (547, "DHCPv6 server", True, True, False),
    (593, "HTTP RPC / RPC over HTTP", True, True, False),
    (2049, "NFS", True, True, False),
    (8080, "Control (not in the blocked list)", True, True, False),
]


def probe_tcp(host, port, timeout, token):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
            except socket.timeout:
                return "REACHED", "connected, no responder payload"
            except OSError as exc:
                return "REACHED", "connected; read failed: %s" % exc
        if MAGIC in data and (not token or token.encode() in data):
            return "OPEN", "responder reached"
        return "REACHED", "replied, not our responder"
    except ConnectionRefusedError:
        return "REACHED", "connection refused (reached host, nothing listening)"
    except socket.timeout:
        return "TIMEOUT", "no response (dropped -> possibly filtered)"
    except OSError as exc:
        return "ERROR", exc.strerror or str(exc)


def probe_udp(host, port, timeout, token):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.send(CHECK_REQUEST)
        try:
            data = sock.recv(256)
        except socket.timeout:
            return "TIMEOUT", "no reply (no responder, or dropped -> possibly filtered)"
        except ConnectionRefusedError:
            return "REACHED", "ICMP port unreachable (reached host, nothing listening)"
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ECONNREFUSED:
                return "REACHED", "ICMP port unreachable (reached host, nothing listening)"
            return "ERROR", exc.strerror or str(exc)
        if MAGIC in data and (not token or token.encode() in data):
            return "OPEN", "responder reached"
        return "REACHED", "replied, not our responder"
    except OSError as exc:
        return "ERROR", exc.strerror or str(exc)
    finally:
        sock.close()


def resolve_output(value, loop_mode):
    """Turn the -o value into a filename with extension (mirror of portfilter.cli)."""
    if value is None:
        return None
    ext = ".jsonl" if loop_mode else ".json"
    default_name = "portfilter-%s%s" % (time.strftime("%Y%m%d-%H%M%S"), ext)

    if value == "":
        return unique_default(default_name)

    path = Path(value)
    if path.is_dir() or value.endswith(("/", os.sep)):
        return unique_default(str(path / default_name))

    if path.suffix:
        return value
    return value + ext


def unique_default(path):
    """Return ``path``, or a ``-N`` suffixed variant if the file already exists."""
    base = Path(path)
    counter = 1
    candidate = base
    while candidate.exists():
        candidate = base.with_name("%s-%d%s" % (base.stem, counter, base.suffix))
        counter += 1
    return str(candidate)


def main():
    ap = argparse.ArgumentParser(description="Test inbound port filtering from your phone.")
    ap.add_argument("host", help="public IP of the connection under test")
    ap.add_argument("--token", help="shared token the listener is using")
    ap.add_argument("--timeout", type=float, default=5.0, help="per-probe timeout (default 5)")
    ap.add_argument("--workers", type=int, default=16, help="parallel probes (default 16)")
    ap.add_argument("--ports", help="only these ports, e.g. 80,443,8080")
    ap.add_argument(
        "-o", "--output", nargs="?", const="",
        help=("write results to a JSON file (.json/.jsonl extension added when missing; "
              "empty value/directory picks a timestamped default)"),
    )
    ap.add_argument(
        "--loop",
        nargs="?",
        const=15.0,
        type=float,
        metavar="SECONDS",
        help="re-check every SECONDS (default 15) until Ctrl-C; only changes are shown",
    )
    args = ap.parse_args()

    wanted = None
    if args.ports:
        wanted = set()
        for chunk in args.ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                lo, hi = chunk.split("-", 1)
                wanted.update(range(int(lo), int(hi) + 1))
            else:
                wanted.add(int(chunk))

    try:
        ip = socket.gethostbyname(args.host)
    except OSError as exc:
        raise SystemExit("cannot resolve %r: %s" % (args.host, exc))

    if wanted is None:
        entries = PORTS
    else:
        by_port = {p[0]: p for p in PORTS}
        entries = [by_port.get(p) or (p, "custom", True, True, False) for p in sorted(wanted)]

    jobs = []
    for port, name, tcp, udp, unsupported in entries:
        if unsupported:
            jobs.append((port, name, None, None))
            continue
        if tcp:
            jobs.append((port, name, "tcp", None))
        if udp:
            jobs.append((port, name, "udp", None))

    def run(job):
        port, name, proto, _ = job
        if proto is None:
            return port, name, "-", "SKIPPED", "cannot be tested"
        probe = probe_tcp if proto == "tcp" else probe_udp
        status, detail = probe(ip, port, args.timeout, args.token)
        return port, name, proto, status, detail

    def run_round():
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            return sorted(pool.map(run, jobs), key=lambda r: (r[0], r[2]))

    def print_summary(rows):
        timeouts = [r for r in rows if r[3] == "TIMEOUT"]
        control = [r for r in rows if r[0] == 8080]
        print()
        if control and any(r[3] == "OPEN" for r in control):
            print("Control port 8080 is OPEN: the external path works, so any")
            print("listed TIMEOUT below is most likely ISP filtering.")
        elif control:
            print("WARNING: control port 8080 did not answer. A TIMEOUT may be your")
            print("router/NAT (port forwarding / firewall), not the ISP. Inconclusive.")
        print("%d port/protocol probes timed out." % len(timeouts))

    def print_round(rows):
        print("Target: %s (%s)   timeout %gs" % (args.host, ip, args.timeout))
        print()
        for port, name, proto, status, detail in rows:
            label = "%d/%s" % (port, proto.upper())
            print("%-10s %-8s %s" % (label, status, name))
        print_summary(rows)

    def print_delta(round_no, interval, prev, rows):
        prev_map = {(r[0], r[2]): r[3] for r in prev}
        changed = [r for r in rows if prev_map.get((r[0], r[2])) != r[3]]
        print()
        print("Round %d [%s]  interval %gs" % (round_no, time.strftime("%H:%M:%S"), interval))
        if not changed:
            print("  no status changes")
            return
        print("  %d change(s):" % len(changed))
        for port, name, proto, status, detail in changed:
            old = prev_map.get((port, proto), "?")
            print("  %d/%s  %-8s -> %-8s %s" % (port, proto.upper(), old, status, name))

    def make_round(round_no, rows):
        return {
            "round": round_no,
            "timestamp": time.time(),
            "target": args.host,
            "resolved_ip": ip,
            "timeout": args.timeout,
            "results": [
                {"port": port, "name": name, "proto": proto, "status": status, "detail": detail}
                for port, name, proto, status, detail in rows
            ],
        }

    if args.loop is not None:
        previous = None
        round_no = 0
        outpath = resolve_output(args.output, loop_mode=True)
        outfile = open(outpath, "w", encoding="utf-8") if outpath else None
        if outfile:
            print("Logging each round to %s" % outpath)
        try:
            while True:
                round_no += 1
                rows = run_round()
                if previous is None:
                    print_round(rows)
                else:
                    print_delta(round_no, args.loop, previous, rows)
                if outfile:
                    outfile.write(json.dumps(make_round(round_no, rows), separators=(",", ":")) + "\n")
                    outfile.flush()
                previous = rows
                time.sleep(args.loop)
        except KeyboardInterrupt:
            print("\nLoop stopped (Ctrl-C). Ran %d round(s)." % round_no)
        finally:
            if outfile:
                outfile.close()
                print("Results saved to %s" % outpath)
        return

    rows = run_round()
    print_round(rows)
    outpath = resolve_output(args.output, loop_mode=False)
    if outpath:
        with open(outpath, "w", encoding="utf-8") as outfile:
            outfile.write(json.dumps(make_round(1, rows), indent=2) + "\n")
        print("Wrote results to %s" % outpath)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # Downstream consumer (e.g. `... | head`) closed the pipe.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
