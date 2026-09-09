"""What isolation did this run actually have? (stage 3)

An evidence artifact that says "no network egress" because the harness passed
--network none is not evidence. It is a claim about a flag. If the flag were
dropped, mistyped, or overridden by a daemon default, the artifact would still
say the same thing and would now be lying.

So the container measures its own isolation from the inside, before it scores
anything, and the measurement travels with the result. Three things are
recorded:

  interfaces      every interface the container can see
  default_route   whether a route off this subnet exists at all
  probes          real connection attempts to real addresses off-host

The probes are the part that cannot be faked by configuration. If any of them
connects, this container had egress, whatever the flags said, and the caller
turns that into INSUFFICIENT EVIDENCE rather than a verdict.

Deliberately stdlib only. The scoring image carries the pinned experiment
dependencies and nothing else, so there is no curl, no nc and no ip to lean
on, and adding them to reach for them here would widen the image for no gain.

Observed modes, named for what was measured rather than what was requested:

  network-none          loopback only, no other interface exists
  internal-no-gateway   another interface exists, but no default route
  routed                a default route exists, egress is probably reachable
"""

import json
import socket
import struct

# Addresses chosen because they are globally routed, answer on these ports,
# and are not operated by us. A probe that reaches any of them is egress.
TCP_PROBES = [
    ("1.1.1.1", 443),
    ("8.8.8.8", 53),
    ("9.9.9.9", 443),
]
DNS_PROBE = "example.com"
PROBE_TIMEOUT = 3.0


def interfaces():
    """Every interface index and name the container can see."""
    try:
        return sorted(name for _, name in socket.if_nameindex())
    except Exception:
        return []


def has_default_route():
    """True if /proc/net/route carries a 0.0.0.0 destination.

    This is the kernel's own answer, read directly rather than asked of a
    tool that may not be installed. A container on an --internal network has
    an interface and an address but no line like this, which is precisely why
    it cannot reach off its own subnet.
    """
    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            lines = f.read().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        parts = line.split()
        if len(parts) > 2 and parts[1] == "00000000":
            return True
    return False


def _tcp_probe(host, port):
    """Try to open a real TCP connection. True means egress exists."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(PROBE_TIMEOUT)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def _dns_probe(name):
    try:
        socket.setdefaulttimeout(PROBE_TIMEOUT)
        socket.getaddrinfo(name, 80)
        return True
    except Exception:
        return False


def measure(requested_mode=None):
    """Measure this container's isolation. Returns the record for the artifact.

    requested_mode is what the caller asked docker for. It is recorded beside
    the measurement so the two can be compared, never instead of it.
    """
    ifaces = interfaces()
    default_route = has_default_route()
    non_loopback = [i for i in ifaces if i != "lo"]

    probes = []
    for host, port in TCP_PROBES:
        probes.append({"kind": "tcp", "target": "%s:%d" % (host, port),
                       "connected": _tcp_probe(host, port)})
    probes.append({"kind": "dns", "target": DNS_PROBE,
                   "connected": _dns_probe(DNS_PROBE)})

    reached = [p["target"] for p in probes if p["connected"]]

    if not non_loopback:
        observed = "network-none"
    elif not default_route:
        observed = "internal-no-gateway"
    else:
        observed = "routed"

    return {
        "requested_mode": requested_mode,
        "observed_mode": observed,
        "egress_blocked": not reached,
        "interfaces": ifaces,
        "default_route": default_route,
        "probes": probes,
        "reached": reached,
    }


def main():
    print(json.dumps(measure(), indent=2))


if __name__ == "__main__":
    main()
