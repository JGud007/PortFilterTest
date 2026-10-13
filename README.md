# PortFilterTest

[![CI](https://github.com/JGud007/PortFilterTest/actions/workflows/ci.yml/badge.svg)](https://github.com/JGud007/PortFilterTest/actions/workflows/ci.yml)

Test whether your ISP is filtering **inbound** TCP/UDP connections on specific
ports. The default port list is a set of well-known service ports that ISPs
commonly filter:

`0, 20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 135, 137, 138, 139, 143, 161, 162, 443, 547, 593, 2049`

Edit `ports.json` (or pass `--ports`) to match your ISP's list.

Pure Python 3 (3.9+), standard library only.

## How it works

Proving that inbound traffic is filtered needs **two vantage points**:

```
   [ external checker ]  --->  Internet  --->  ISP  --->  router/NAT  --->  [ listener ]
        portfilter check                              (port filtering)     portfilter server
```

* **`server`** runs on the machine behind the ISP. It binds a TCP and/or UDP
  socket on every port under test and answers with a magic token
  (`PORTFILTER-OK`). It tells a real responder apart from a captive portal or an
  ISP-injected page.
* **`check`** runs from *outside* the network — a VPS, a second broadband
  connection, or a phone on cellular. It points at your public IP and reports,
  per port and protocol, whether a connection could be made.

> A probe run from the same machine (or the same LAN) proves nothing about
> inbound filtering. The checker even warns you when the target resolves to a
> private IP.

## ⚠️ Read this before trusting a "timeout"

There are **two** things between the Internet and your listener: your ISP's
filter **and** your own router's NAT/firewall. A closed-looking port could be
either one.

* Most home routers silently drop unsolicited inbound traffic unless you
  configured **port forwarding** or put the listener host in the **DMZ**.
* So to test the ISP filter specifically, forward the test ports (or DMZ the
  host) **first**, then run the test.

To make this obvious, the tool always includes a **control port 8080**, which is
*not* on the block list:

| Control port 8080 | Listed port | Meaning |
| --- | --- | --- |
| OPEN | OPEN/REACHED | Works. Not filtered. |
| OPEN | TIMEOUT | Almost certainly filtered by the ISP. |
| TIMEOUT | TIMEOUT | Your router/NAT is the problem — results are inconclusive. |

Forward the control port along with the others (or DMZ the host) so it can do
its job.

Note: some ISPs do not apply port filtering to wireless/fixed-wireless
broadband connections, only to fibre/copper. If results look unexpected, check
whether that applies to your connection.

## Quick start

### 1. On the machine behind the ISP (the listener)

```bash
# Bind privileged ports (<1024) — most of the list — so use sudo.
sudo python3 -m portfilter server --public-ip
```

It prints the ports it bound and this host's public IP (with `--public-ip`).
Leave it running.

If you can't use `sudo`, test a subset of unprivileged ports (e.g. 2049, 8080):

```bash
python3 -m portfilter server --ports 2049,8080
```

### 2. From an external machine (the checker)

Use a VPS, another network, or a phone on cellular. Replace the IP with the one
printed in step 1:

```bash
python3 -m portfilter check 203.0.113.45
```

Example output:

```
Target   : 203.0.113.45 (203.0.113.45)
Protocols: tcp udp    Timeout: 5s

PORT   SERVICE                     PROTO  STATUS   DETAIL
-----  --------------------------  -----  -------  ------------------------------------
8080   Control (not on the list)   TCP    OPEN     responder reached
8080   Control (not on the list)   UDP    OPEN     responder reached
20     FTP data                    TCP    TIMEOUT  no response (dropped -> possibly filtered)
20     FTP data                    UDP    TIMEOUT  no response (dropped -> possibly filtered)
22     SSH / SFTP                  TCP    OPEN     responder reached
...
```

## Reading the results

| Status | Meaning |
| --- | --- |
| `OPEN` | Our listener answered. Inbound reaches the host — **not filtered**. |
| `REACHED` | The host replied (TCP RST / ICMP port-unreachable) but our listener didn't. Traffic still reached the host, so it's **not filtered**; the listener just wasn't bound on that port. |
| `TIMEOUT` | No response at all — the signature of filtering (or a silent router/NAT). |
| `ERROR` | A network/host error unrelated to filtering. |
| `SKIPPED` | Cannot be tested, e.g. port 0. |

The summary cross-checks the control port and tells you whether a timeout is
attributable to the ISP or to your own router.

## Install (optional)

No installation is required — `python3 -m portfilter ...` works from the repo
root. To get a `portfilter` command on your `PATH`, clone and install:

```bash
git clone https://github.com/JGud007/PortFilterTest.git
cd PortFilterTest
pip install -e .
```

## Run the checker from your phone

> The phone must be on a **different network** than the listener — cellular
> data with Wi-Fi **off** is the usual choice. Same-Wi-Fi proves nothing.

### Option A — a web port checker (zero install, easiest)

Open a site such as <https://canyouseeme.org> or <https://portchecker.co> in the
phone browser, enter your public IP and a port, and read the result. This
answers the "is this port reachable from the Internet" question without
installing anything.

Trade-offs versus this tool: you can't use the magic token, there's no UDP
testing, and you expose your IP to a third party. For a quick yes/no on a
handful of ports it is usually enough.

### Option B — `phone_check.py` (uses this tool's protocol, TCP + UDP)

`phone_check.py` in this repo is a single self-contained file (stdlib only,
~200 lines). Get it onto the phone, install Python, and run it.

**Android (Termux):**

```bash
pkg install python
# then put phone_check.py in your home dir, e.g.:
curl -O https://raw.githubusercontent.com/JGud007/PortFilterTest/main/phone_check.py
python3 phone_check.py 203.0.113.45 --token s3cret
```

**iOS (a-Shell):** install the free **a-Shell** app, put `phone_check.py` in
its documents folder (Files app), then:

```text
python3 phone_check.py 203.0.113.45
```

No hosting? Just copy the file over by email, a cloud drive, `scp`, or USB —
it's one file. The output is one line per port, sized for a small screen:

```
Target: 203.0.113.45 (203.0.113.45)   timeout 5s

20/TCP     TIMEOUT   FTP data
20/UDP     TIMEOUT   FTP data
22/TCP     OPEN      SSH / SFTP
...
8080/TCP   OPEN      Control (not in the blocked list)
8080/UDP   OPEN      Control (not in the blocked list)

Control port 8080 is OPEN: the external path works, so any
listed TIMEOUT below is most likely ISP filtering.
3 port/protocol probes timed out.
```

`phone_check.py` accepts `HOST`, `--token`, `--timeout`, `--workers`, `--loop`,
`-o/--output`, and `--ports "80,443,8080"`. It prints the same control-port
verdict as the full checker.

### Watching ports flip while you toggle the setting

Both checkers support `--loop [SECONDS]` (default 15). The first round prints
the full table; later rounds print only status changes, so the deltas stand out
on a screen full of scroll:

```
Round 7  [21:39:51]  interval 2s
  4 change(s):
  22/TCP   OPEN      -> TIMEOUT
  22/UDP   OPEN      -> TIMEOUT
  80/TCP   OPEN      -> TIMEOUT
  8080/UDP OPEN      -> TIMEOUT
```

Start the checker with `--loop`, then flip your ISP's port-filtering setting and
watch the arrows appear. `--json` in loop mode prints one JSON object per round
(one line each), so you can tee it to a file for a record:

```bash
python3 -m portfilter check 203.0.113.45 --loop 10 --json | tee porttest.jsonl
```

## Command reference

```
python -m portfilter list [--config PATH] [--json]

python -m portfilter server
    [--bind ADDR] [--ports SPEC] [--timeout SECONDS] [--no-control]
    [--token STR] [--public-ip] [--quiet] [--log-local] [--config PATH]

python -m portfilter check HOST
    [--ports SPEC] [--timeout SECONDS] [--no-control] [--token STR]
    [--workers N] [--loop [SECONDS]] [-o [PATH]] [--json] [--no-color]
    [--config PATH]
```

* `--ports "80,443,1000-1010"` — restrict the run to a subset (ranges allowed).
  Ports not in the built-in list are accepted as custom ports.
* `--token STR` — an optional shared secret. When set on the listener, the
  checker must use the same value, and responses that lack it are reported as
  `REACHED` rather than `OPEN`.
* `--no-control` — exclude the control port 8080.
* `--loop [SECONDS]` — re-check continuously every `SECONDS` (default 15) until
  Ctrl-C. The first round shows the full table; later rounds print only status
  changes. Combine with `--json` to get one JSON object per round.
* `-o [PATH]` / `--output [PATH]` — write the results to a JSON **file**. The
  name is optional: with no value (or a directory) a timestamped default is
  generated, e.g. `portfilter-20261013-213045.json`, and it never overwrites an
  existing file (it adds `-1`, `-2`, … instead). Missing extensions are added:
  `.json` for a single run, `.jsonl` for loop mode. A single run writes one
  pretty-printed document; loop mode appends one compact JSON object per line
  (JSONL). Console output is still printed; use `--json` only if you also want
  JSON on stdout.
  ```bash
  python -m portfilter check 203.0.113.45 -o                 # default: portfilter-<timestamp>.json
  python -m portfilter check 203.0.113.45 -o results         # results.json
  python -m portfilter check 203.0.113.45 --loop 10 -o watch # watch.jsonl
  python -m portfilter check 203.0.113.45 -o Downloads/      # timestamped file in Downloads/
  # parse later: python -c "import json; [print(r['status']) for l in open('watch.jsonl') for r in json.loads(l)['results']]"
  ```
* `--json` — machine-readable output (for `list` and `check`).
* `--timeout` — per-probe timeout in seconds (default 5). Raise it on slow
  links; lower it to scan faster.
* `--quiet` (server) — do not log any incoming requests.
* `--log-local` (server) — include requests from the same machine/network in the
  log (loopback, RFC1918 private, link-local, IPv6 ULA). They are omitted by
  default because the checker should always come from an external network; see
  below.

### Server request log

The listener logs every probe it answers, so you can watch inbound traffic land
on each port as the external checker runs (and see would-be scanners):

```
[22:10:41] tcp port 80 from 118.149.3.89:52341
[22:10:41] udp port 67 from 118.149.3.89:54678 13 bytes
```

Each line shows the time, transport, local port, the peer's IP:port, and (for
UDP) the size of the datagram received.

To keep the console meaningful, only peers with a **public source IP** are logged
by default. Loopback (`127.0.0.0/8`, `::1`), RFC1918 private (`10/8`,
`172.16/12`, `192.168/16`), link-local (`169.254/16`), IPv6 ULA (`fd00::/8`),
and documentation ranges (`203.0.113.x`, `192.0.2.x`, …) count as local and are
suppressed — an external checker never has one of those as its source address.
Add `--log-local` to see everything, or `--quiet` for nothing. If a listed port
reports `OPEN` on the checker but has no corresponding log line here, the
traffic is coming from elsewhere — worth investigating.

## Custom port list

Edit `ports.json` and pass it with `--config ports.json`:

```json
{
  "timeout": 5.0,
  "ports": [
    { "port": 21, "name": "FTP control" },
    { "port": 53, "name": "DNS" },
    { "port": 25565, "name": "Minecraft", "control": true }
  ]
}
```

Keys per port: `port` (required), `name`, `tcp`, `udp` (default `true`),
`control` (marks it as a control port), `unsupported`, `note`.

## Notes and limitations

* **Protocols.** Each port is tested over TCP and UDP by default, because ISPs
  typically filter both. Some ports are UDP-centric (53, 67, 68, 161, 162, 547);
  binding TCP there is harmless and still reveals port-level filtering.
* **Port 0** cannot be bound or probed (it is not a real destination port), so
  it is reported as `SKIPPED`.
* **UDP is connectionless.** A silence can mean "filtered" or "no responder". A
  `REACHED` from UDP means the host actively signalled the port is closed
  (ICMP port-unreachable), which proves reachability. `OPEN` is authoritative.
  A UDP `TIMEOUT` is weaker evidence than a TCP `TIMEOUT`.
* **Privileged ports.** Ports below 1024 require root (or `CAP_NET_BIND_SERVICE`).
  The listener reports `permission denied` for those and keeps going.
* **Port already in use.** A service already using a port (e.g. a local DNS
  resolver on 53) causes the listener to report `address already in use` for
  that port; stop the service or test on another host.
* **IPv4.** Probing uses IPv4 (`AF_INET`). The checker resolves the host to an
  IPv4 address.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests start the listener on loopback and verify the round trip for TCP and
UDP, token enforcement, and skipped ports.

## License

MIT © 2026 [JGud007](https://github.com/JGud007) — see [LICENSE](LICENSE).
Repository: <https://github.com/JGud007/PortFilterTest>
