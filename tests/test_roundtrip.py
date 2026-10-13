"""End-to-end tests: start the listener, probe it over loopback."""

from __future__ import annotations

import socket
import threading
import time
import unittest

from portfilter.checker import OPEN, REFUSED, TIMEOUT, ERROR, check
from portfilter.ports import PortSpec
from portfilter.server import _is_local_peer, run_server


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RoundTripTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stop = threading.Event()
        self.specs = [
            PortSpec(free_port(), "tcp+udp", tcp=True, udp=True),
            PortSpec(free_port(), "tcp only", tcp=True, udp=False),
        ]
        self.thread = threading.Thread(
            target=run_server,
            kwargs={
                "host": "127.0.0.1",
                "specs": self.specs,
                "timeout": 1.0,
                "token": None,
                "stop": self.stop,
                "announce": False,
                "log_requests": False,
            },
            daemon=True,
        )
        self.thread.start()
        time.sleep(0.4)

    def tearDown(self) -> None:
        self.stop.set()
        self.thread.join(timeout=5)

    def test_listener_answers_every_protocol(self) -> None:
        results = check("127.0.0.1", self.specs, timeout=1.0, workers=4)
        statuses = {(r.port, r.proto): r.status for r in results}
        self.assertEqual(statuses[(self.specs[0].port, "tcp")], OPEN)
        self.assertEqual(statuses[(self.specs[0].port, "udp")], OPEN)
        self.assertEqual(statuses[(self.specs[1].port, "tcp")], OPEN)
        self.assertNotIn((self.specs[1].port, "udp"), statuses)

    def test_token_is_required_when_set(self) -> None:
        stop = threading.Event()
        port = free_port()
        specs = [PortSpec(port, "tok", tcp=True, udp=False)]
        thread = threading.Thread(
            target=run_server,
            kwargs={
                "host": "127.0.0.1",
                "specs": specs,
                "timeout": 1.0,
                "token": "s3cret",
                "stop": stop,
                "announce": False,
                "log_requests": False,
            },
            daemon=True,
        )
        thread.start()
        time.sleep(0.4)
        try:
            with_token = check("127.0.0.1", specs, timeout=1.0, workers=1, token="s3cret")
            self.assertEqual(with_token[0].status, OPEN)
            wrong_token = check("127.0.0.1", specs, timeout=1.0, workers=1, token="nope")
            self.assertEqual(wrong_token[0].status, REFUSED)
        finally:
            stop.set()
            thread.join(timeout=5)

    def test_unsupported_port_is_skipped(self) -> None:
        specs = [PortSpec(0, "port zero", tcp=False, udp=False, unsupported=True)]
        results = check("127.0.0.1", specs, timeout=0.2, workers=1)
        self.assertEqual(results[0].status, "skipped")


class LocalPeerTest(unittest.TestCase):
    """The request log omits same-machine/LAN peers."""

    def test_loopback_private_and_link_local_are_local(self) -> None:
        local = ["127.0.0.1", "::1", "10.0.0.5", "172.16.0.5", "192.168.1.50",
                 "169.254.10.10", "fd00::1"]
        for ip in local:
            self.assertTrue(_is_local_peer(ip), ip)

    def test_global_addresses_are_external(self) -> None:
        external = ["8.8.8.8", "1.1.1.1", "2606:4700::1111"]
        for ip in external:
            self.assertFalse(_is_local_peer(ip), ip)

    def test_unparseable_is_hidden(self) -> None:
        self.assertTrue(_is_local_peer("not-an-ip"))


class NoListenerTest(unittest.TestCase):
    def test_closed_port_is_not_open(self) -> None:
        port = free_port()
        specs = [PortSpec(port, "closed", tcp=True, udp=True)]
        results = check("127.0.0.1", specs, timeout=0.5, workers=2)
        for result in results:
            self.assertIn(result.status, {REFUSED, TIMEOUT, ERROR})
            self.assertNotEqual(result.status, OPEN)


if __name__ == "__main__":
    unittest.main()
