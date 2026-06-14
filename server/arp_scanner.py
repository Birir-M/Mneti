"""
Mneti - Server-side ARP/ping sweep for unmanaged device discovery.

Runs ONLY on the server. Replaces the per-agent ARP scan that used to run
inside Invoke-SubnetRelay on relay-capable agents. Centralising this here:

  - Avoids needing every relay-capable agent to have a second NIC into
    each subnet just to ARP-scan it.
  - Produces one ping sweep + ARP read per subnet per discovery run,
    instead of N agents each doing their own sweep.
  - Lets the dashboard's custom broadcast ranges (e.g. 10.51.144.0/22)
    double as the scan ranges for unmanaged-device discovery.

Devices found here are reported with type="unmanaged". If a managed or
relayed report for the same MAC arrives (from the agent itself), the
result_store upgrade logic replaces the unmanaged entry — so a device
never shows up twice.
"""

import subprocess
import re
import ipaddress
import logging
import platform
import concurrent.futures

log = logging.getLogger("mneti.arpscan")

_ARP_LINE_RE_WIN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'
    r'(?P<mac>[\da-fA-F]{2}(?:[:\-][\da-fA-F]{2}){5})\s+dynamic',
    re.IGNORECASE,
)


def _ping(ip: str, timeout_ms: int = 200):
    """Fire a single ICMP ping to populate the ARP/neighbour cache.
    The result is ignored — we only care about the side effect on the
    ARP table.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_s = max(1, round(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        subprocess.run(cmd, capture_output=True, timeout=2)
    except Exception:
        pass


def _read_arp_table() -> dict[str, str]:
    """Return {ip: mac} from the OS ARP/neighbour cache."""
    result: dict[str, str] = {}
    system = platform.system().lower()

    try:
        if system == "windows":
            out = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=10
            ).stdout
            for line in out.splitlines():
                m = _ARP_LINE_RE_WIN.search(line)
                if m:
                    result[m.group("ip")] = m.group("mac").upper().replace("-", ":")
        else:
            # Prefer `ip neigh` (modern Linux), fall back to /proc/net/arp
            try:
                out = subprocess.run(
                    ["ip", "neigh"], capture_output=True, text=True, timeout=10
                ).stdout
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and "lladdr" in parts:
                        ip = parts[0]
                        mac = parts[parts.index("lladdr") + 1].upper()
                        if re.match(r'^[0-9A-F:]{17}$', mac):
                            result[ip] = mac
            except Exception:
                pass

            if not result:
                try:
                    with open("/proc/net/arp", encoding="utf-8") as f:
                        next(f)  # skip header
                        for line in f:
                            parts = line.split()
                            if len(parts) >= 4:
                                ip, mac = parts[0], parts[3].upper()
                                if mac != "00:00:00:00:00:00" and re.match(
                                    r'^[0-9A-F:]{17}$', mac
                                ):
                                    result[ip] = mac
                except Exception as e:
                    log.warning("Failed to read /proc/net/arp: %s", e)
    except Exception as e:
        log.warning("ARP table read failed: %s", e)

    return result


def scan_subnet(
    network: ipaddress.IPv4Network,
    exclude_ips: set[str] | None = None,
    max_workers: int = 32,
) -> dict[str, str]:
    """
    Ping-sweep every host in `network` in parallel to populate the ARP
    cache, then read it back.

    Returns {ip: mac} for hosts that responded / appeared in the ARP
    table within this network.
    """
    exclude_ips = exclude_ips or set()

    try:
        hosts = [str(h) for h in network.hosts() if str(h) not in exclude_ips]
    except Exception as e:
        log.warning("scan_subnet: cannot enumerate hosts for %s: %s", network, e)
        return {}

    if not hosts:
        return {}

    log.info("ARP scan: sweeping %d host(s) in %s", len(hosts), network)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(_ping, hosts))

    arp_table = _read_arp_table()
    host_set = set(hosts)

    found = {ip: mac for ip, mac in arp_table.items() if ip in host_set}

    log.info("ARP scan: %d device(s) responded in %s", len(found), network)
    return found