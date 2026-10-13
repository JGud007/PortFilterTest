"""Command-line interface.

    python -m portfilter list                 # show the configured ports
    python -m portfilter server [options]     # run on the machine behind the ISP
    python -m portfilter check HOST [options] # run from outside the network
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Sequence

from . import __version__, report
from .checker import check
from .ports import PortSpec, load_config, select_specs, without_control
from .server import DEFAULT_BIND, run_server


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="JSON config file with the port list (default: built-in port list)",
    )
    parser.add_argument(
        "--ports",
        metavar="SPEC",
        help="only these ports, e.g. '80,443' or '1000-1010'",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="per-probe timeout (default 5)",
    )
    parser.add_argument(
        "--no-control",
        action="store_true",
        help="do not include the control port (8080)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portfilter",
        description="Test whether an ISP is filtering inbound TCP/UDP ports.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="show the configured ports")
    p_list.add_argument("--config", metavar="PATH")
    p_list.add_argument("--json", action="store_true", help="emit JSON")

    p_server = sub.add_parser("server", help="bind the ports and answer probes")
    _add_common(p_server)
    p_server.add_argument(
        "--bind",
        default=DEFAULT_BIND,
        metavar="ADDR",
        help=f"local address to bind (default {DEFAULT_BIND})",
    )
    p_server.add_argument("--token", help="optional shared token required in responses")
    p_server.add_argument(
        "--public-ip",
        action="store_true",
        help="look up and print this host's public IP (best effort)",
    )
    p_server.add_argument(
        "--quiet",
        action="store_true",
        help="do not log each incoming request to the console",
    )
    p_server.add_argument(
        "--log-local",
        action="store_true",
        help=(
            "also log requests from the same machine/network (loopback, private, "
            "link-local peers); they are omitted by default"
        ),
    )

    p_check = sub.add_parser("check", help="probe a target from outside the network")
    _add_common(p_check)
    p_check.add_argument("host", help="public IP (or hostname) of the connection under test")
    p_check.add_argument("--token", help="shared token the listener is using")
    p_check.add_argument(
        "--workers", type=int, default=32, metavar="N", help="parallel probes (default 32)"
    )
    p_check.add_argument(
        "--loop",
        nargs="?",
        const=15.0,
        type=float,
        metavar="SECONDS",
        help=(
            "re-check every SECONDS (default 15) until Ctrl-C; after the first round "
            "only status changes are printed"
        ),
    )
    p_check.add_argument(
        "-o",
        "--output",
        nargs="?",
        const="",
        metavar="PATH",
        help=(
            "write results to a JSON file; a .json/.jsonl extension is added when "
            "missing and an empty value or directory picks a timestamped default, "
            "e.g. portfilter-20261013-213045.json (one JSON object per line in "
            "--loop mode)"
        ),
    )
    p_check.add_argument("--json", action="store_true", help="emit JSON")
    p_check.add_argument("--no-color", action="store_true", help="disable coloured output")

    return parser


def _resolve(args) -> tuple[float, list[PortSpec]]:
    timeout, specs = load_config(args.config)
    if args.timeout is not None:
        timeout = args.timeout
    if args.no_control:
        specs = without_control(specs)
    specs = select_specs(specs, args.ports)
    if not specs:
        raise SystemExit("no ports selected")
    return timeout, specs


def _cmd_list(args) -> int:
    _timeout, specs = load_config(args.config)
    if args.json:
        print(json.dumps(
            [
                {
                    "port": s.port,
                    "name": s.name,
                    "protocols": list(s.protocols),
                    "control": s.control,
                    "unsupported": s.unsupported,
                }
                for s in specs
            ],
            indent=2,
        ))
        return 0
    print(f"{'PORT':<7}{'PROTO':<9}{'NAME'}")
    for spec in specs:
        protos = "+".join(p.upper() for p in spec.protocols) or "-"
        flags = []
        if spec.control:
            flags.append("control")
        if spec.unsupported:
            flags.append("unsupported")
        suffix = f"  [{', '.join(flags)}]" if flags else ""
        print(f"{spec.port:<7}{protos:<9}{spec.name}{suffix}")
    return 0


def _cmd_server(args) -> int:
    timeout, specs = _resolve(args)
    run_server(
        host=args.bind,
        specs=specs,
        timeout=timeout,
        token=args.token,
        announce=True,
        show_public_ip=args.public_ip,
        log_requests=not args.quiet,
        log_local=args.log_local,
    )
    return 0


def _probe(args, resolved_ip: str, specs, timeout: float) -> list:
    return check(
        host=resolved_ip,
        specs=specs,
        timeout=timeout,
        workers=args.workers,
        token=args.token,
    )


def _results_json(results: Sequence) -> list:
    return [
        {
            "port": r.port,
            "name": r.name,
            "proto": r.proto,
            "status": r.status,
            "detail": r.detail,
            "control": r.control,
        }
        for r in results
    ]


def _round_payload(round_no: int, results, host: str, resolved_ip: str, timeout: float) -> dict:
    return {
        "round": round_no,
        "timestamp": time.time(),
        "target": host,
        "resolved_ip": resolved_ip,
        "timeout": timeout,
        "results": _results_json(results),
    }


def _print_json_round(round_no: int, results, host: str, resolved_ip: str, timeout: float) -> None:
    print(json.dumps(
        _round_payload(round_no, results, host, resolved_ip, timeout),
        separators=(",", ":"),
    ), flush=True)


def _write_json_round(
    outfile,
    round_no: int,
    results,
    host: str,
    resolved_ip: str,
    timeout: float,
    pretty: bool = False,
) -> None:
    payload = _round_payload(round_no, results, host, resolved_ip, timeout)
    if pretty:
        outfile.write(json.dumps(payload, indent=2) + "\n")
    else:
        outfile.write(json.dumps(payload, separators=(",", ":")) + "\n")
    outfile.flush()


def _unique_default(path: str | Path) -> str:
    """Return ``path``, or a ``-N`` suffixed variant if the file already exists."""
    base = Path(path)
    counter = 1
    candidate = base
    while candidate.exists():
        candidate = base.with_name(f"{base.stem}-{counter}{base.suffix}")
        counter += 1
    return str(candidate)


def _resolve_output(value: str | None, loop_mode: bool) -> str | None:
    """Turn the --output value into a filename with extension.

    - ``None``            -> not exporting
    - ``""``              -> timestamped default in the current directory
    - directory path      -> timestamped default inside that directory
    - ``name`` (no ext)   -> ``name.json`` / ``name.jsonl``
    - ``name.ext``        -> used unchanged

    Auto-generated default names never overwrite an existing file.
    """
    if value is None:
        return None
    ext = ".jsonl" if loop_mode else ".json"
    default_name = f"portfilter-{time.strftime('%Y%m%d-%H%M%S')}{ext}"

    if value == "":
        return _unique_default(default_name)

    path = Path(value)
    if path.is_dir() or value.endswith(("/", os.sep)):
        return _unique_default(path / default_name)

    if path.suffix:
        return value
    return value + ext


def _render_once(host: str, resolved_ip: str, results, timeout: float, color: bool, is_private: bool) -> None:
    report.render_results(results, host, resolved_ip, timeout, color)
    if is_private:
        print("NOTE: the target resolves to a private address, so this probe does not")
        print("      leave your network. Run the checker from an external machine for a")
        print("      valid result.\n")
    report.render_summary(results, color)


def _cmd_check_loop(args, specs, timeout: float, color: bool, resolved_ip: str, is_private: bool) -> int:
    interval = args.loop
    previous = None
    round_no = 0
    outpath = _resolve_output(args.output, loop_mode=True)
    outfile = open(outpath, "w", encoding="utf-8") if outpath else None
    if outfile:
        print(f"Logging each round to {outpath}")
    try:
        while True:
            round_no += 1
            results = _probe(args, resolved_ip, specs, timeout)
            if args.json:
                _print_json_round(round_no, results, args.host, resolved_ip, timeout)
            elif round_no == 1:
                print(f"Round {round_no}  [{time.strftime('%H:%M:%S')}]  interval {interval:g}s")
                _render_once(args.host, resolved_ip, results, timeout, color, is_private)
            else:
                report.render_loop_round(round_no, interval, previous, results, color)
            if outfile:
                _write_json_round(outfile, round_no, results, args.host, resolved_ip, timeout)
            previous = results
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\nLoop stopped (Ctrl-C). Ran {round_no} round(s).")
    finally:
        if outfile:
            outfile.close()
            print(f"Results saved to {outpath}")
    return 0


def _cmd_check(args) -> int:
    timeout, specs = _resolve(args)
    color = sys.stdout.isatty() and not args.no_color and not args.json

    try:
        resolved_ip = socket.gethostbyname(args.host)
    except OSError as exc:
        raise SystemExit(f"cannot resolve {args.host!r}: {exc}")

    try:
        is_private = ipaddress.ip_address(resolved_ip).is_private
    except ValueError:
        is_private = False

    if args.loop is not None:
        return _cmd_check_loop(args, specs, timeout, color, resolved_ip, is_private)

    results = _probe(args, resolved_ip, specs, timeout)

    if args.json:
        _print_json_round(1, results, args.host, resolved_ip, timeout)

    _render_once(args.host, resolved_ip, results, timeout, color, is_private)

    outpath = _resolve_output(args.output, loop_mode=False)
    if outpath:
        with open(outpath, "w", encoding="utf-8") as outfile:
            _write_json_round(outfile, 1, results, args.host, resolved_ip, timeout, pretty=True)
        print(f"Wrote results to {outpath}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _main(argv)
    except BrokenPipeError:
        # Downstream consumer (e.g. `... | head`) closed the pipe.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 1


def _main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "list":
        return _cmd_list(args)
    if args.command == "server":
        return _cmd_server(args)
    if args.command == "check":
        return _cmd_check(args)
    parser.error("unknown command")
    return 2
