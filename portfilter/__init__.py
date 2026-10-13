"""Test whether an ISP is filtering inbound traffic on specific ports.

The package has two roles:

* ``server`` -- a listener that runs on the machine behind the ISP. It binds
  every port under test and replies with a magic token so a remote probe can
  tell "reachable" apart from "blocked". See :mod:`portfilter.server`.
* ``check`` -- a probe that runs from *outside* the network (a VPS, another
  network, or a phone on cellular). See :mod:`portfilter.checker`.

The default port set covers well-known service ports that ISPs commonly filter
for inbound traffic. Edit ``ports.json`` (or pass ``--ports``) to match your
ISP's specific list.
"""

__version__ = "1.0.0"
