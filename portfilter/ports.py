"""Port definitions and configuration loading.

The default list covers well-known service ports that ISPs commonly filter for
inbound TCP/UDP traffic. Edit ``ports.json`` (or ``--config`` / ``--ports``) to
match your own ISP.

A control port (8080) is added by default. It is *not* on the block list and
exists to prove the whole path works: public IP -> ISP -> router -> host. If the
control port is reachable but a listed port is not, the listed port is very
likely filtered. If even the control port is unreachable, the problem is
probably the router/NAT rather than the ISP filter.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Sequence


@dataclass(frozen=True)
class PortSpec:
    """A single port under test."""

    port: int
    name: str
    tcp: bool = True
    udp: bool = True
    control: bool = False
    unsupported: bool = False
    note: str = ""

    @property
    def protocols(self) -> tuple[str, ...]:
        protos: list[str] = []
        if self.tcp:
            protos.append("tcp")
        if self.udp:
            protos.append("udp")
        return tuple(protos)


# Well-known service ports that ISPs commonly filter for inbound TCP/UDP traffic.
BLOCKED_PORTS: tuple[PortSpec, ...] = (
    PortSpec(
        0,
        "Reserved / invalid destination port",
        tcp=False,
        udp=False,
        unsupported=True,
        note="Port 0 is not a real destination port; it cannot be bound or probed.",
    ),
    PortSpec(20, "FTP data"),
    PortSpec(21, "FTP control"),
    PortSpec(22, "SSH / SFTP"),
    PortSpec(23, "Telnet"),
    PortSpec(25, "SMTP"),
    PortSpec(53, "DNS"),
    PortSpec(67, "DHCP server / bootstrap"),
    PortSpec(68, "DHCP client / bootstrap"),
    PortSpec(80, "HTTP"),
    PortSpec(110, "POP3"),
    PortSpec(135, "MS RPC"),
    PortSpec(137, "NetBIOS name service"),
    PortSpec(138, "NetBIOS datagram"),
    PortSpec(139, "NetBIOS session"),
    PortSpec(143, "IMAP"),
    PortSpec(161, "SNMP"),
    PortSpec(162, "SNMP trap"),
    PortSpec(443, "HTTPS"),
    PortSpec(547, "DHCPv6 server"),
    PortSpec(593, "HTTP RPC / RPC over HTTP"),
    PortSpec(2049, "NFS"),
)

# A port that is not on the block list, used as a control to prove the external
# path (public IP -> ISP -> router -> host) actually works.
CONTROL_PORT = PortSpec(8080, "Control (not in the blocked list)", control=True)


def all_specs(include_control: bool = True) -> list[PortSpec]:
    """The full default port set, optionally without the control port."""
    specs = list(BLOCKED_PORTS)
    if include_control:
        specs.append(CONTROL_PORT)
    return specs


def _spec_from_dict(raw: dict) -> PortSpec:
    allowed = {"port", "name", "tcp", "udp", "control", "unsupported", "note"}
    kwargs = {k: v for k, v in raw.items() if k in allowed}
    if "port" not in kwargs:
        raise ValueError(f"port entry is missing 'port': {raw!r}")
    kwargs.setdefault("name", f"port {kwargs['port']}")
    return PortSpec(**kwargs)


def load_config(path: str | Path | None = None) -> tuple[float, list[PortSpec]]:
    """Return ``(timeout, specs)``.

    With no ``path`` the built-in defaults are used. Otherwise the given JSON
    file is read; see ``ports.json`` in the repository for the format.
    """
    if not path:
        return 5.0, all_specs()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    timeout = float(data.get("timeout", 5.0))
    entries = data.get("ports")
    if not entries:
        raise ValueError(f"{path}: config must contain a non-empty 'ports' list")
    return timeout, [_spec_from_dict(entry) for entry in entries]


def parse_port_ranges(text: str) -> set[int]:
    """Parse ``"80,443,1000-1010"`` into a set of integer ports."""
    ports: set[int] = set()
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(chunk))
    return ports


def select_specs(specs: Sequence[PortSpec], spec_string: str | None) -> list[PortSpec]:
    """Restrict ``specs`` to the ports named in ``spec_string``.

    Ports that are not part of ``specs`` are synthesised as generic ``custom``
    entries so ``--ports`` also works for arbitrary ports.
    """
    if not spec_string:
        return list(specs)
    wanted = parse_port_ranges(spec_string)
    known = {spec.port: spec for spec in specs}
    selected: list[PortSpec] = []
    for port in sorted(wanted):
        selected.append(known.get(port) or PortSpec(port, "custom"))
    return selected


def without_control(specs: Iterable[PortSpec]) -> list[PortSpec]:
    return [spec for spec in specs if not spec.control]
