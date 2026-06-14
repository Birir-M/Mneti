"""
Mneti - UDP Discovery Broadcaster
Sends signed broadcast packets to trigger client-side discovery.

Broadcasts on:
  1. ALL attached local private interfaces (original behaviour, unchanged).
  2. Any user-defined custom IP ranges / subnet masks configured via the
     dashboard — these are sent as directed unicast packets to every host
     in the range, or as a subnet-directed broadcast to the broadcast
     address of the user-supplied CIDR.

Custom range formats accepted (all equivalent examples):
  • CIDR notation        : "10.51.144.0/22"   → broadcasts to 10.51.147.255
  • Dash range           : "10.51.144.1-254"   → sends to every .1–.254 in that /24
  • Multi-octet dash     : "10.51.144.1-10.51.147.254"
  • Subnet + mask pair   : "10.51.144.0/255.255.252.0"

Custom ranges entered via the dashboard are persisted to a JSON file on
disk (server/data/ranges.json by default) so they survive server restarts.
"""

import os
import json
import hmac
import hashlib
import socket
import ipaddress
import logging
import threading
import struct
from datetime import datetime, timezone

log = logging.getLogger("mneti.broadcaster")

# Default location: <server>/data/ranges.json
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_RANGES_FILE = os.path.join(_DATA_DIR, "ranges.json")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sign_payload(payload: bytes, secret: str) -> str:
    """HMAC-SHA256 signature over the raw JSON payload bytes."""
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _get_all_local_interfaces() -> list[dict]:
    """
    Return a list of dicts for every active local IPv4 interface.

    Each entry:
        {
            "ip":        "10.51.144.14",
            "broadcast": "10.51.144.255",
        }

    Loopback (127.x) and APIPA (169.254.x) addresses are excluded.
    Only RFC-1918 private addresses are included so we never accidentally
    broadcast on a public interface.
    """
    private_nets = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]

    interfaces = []
    try:
        hostname = socket.gethostname()
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        for ip_str in ip_list:
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.is_loopback or addr.is_link_local:
                    continue
                in_private = any(addr in net for net in private_nets)
                if not in_private:
                    continue
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((ip_str, 0))
                network = ipaddress.ip_interface(f"{ip_str}/24").network
                broadcast = str(network.broadcast_address)
                sock.close()
                interfaces.append({"ip": ip_str, "broadcast": broadcast})
            except Exception:
                continue
    except Exception as e:
        log.warning("Interface enumeration error: %s", e)

    # Prefer netifaces for accurate netmask data if available
    try:
        import netifaces
        interfaces = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in addrs:
                continue
            for entry in addrs[netifaces.AF_INET]:
                ip_str    = entry.get("addr", "")
                broadcast = entry.get("broadcast", "")
                if not ip_str or not broadcast:
                    continue
                try:
                    addr = ipaddress.ip_address(ip_str)
                    if addr.is_loopback or addr.is_link_local:
                        continue
                    in_private = any(addr in net for net in private_nets)
                    if not in_private:
                        continue
                    interfaces.append({"ip": ip_str, "broadcast": broadcast})
                except Exception:
                    continue
    except ImportError:
        pass

    if not interfaces:
        interfaces = [{"ip": "0.0.0.0", "broadcast": "255.255.255.255"}]

    return interfaces


# ── Custom range parsing ──────────────────────────────────────────────────────

class ParsedRange:
    """
    Represents a user-defined broadcast range.

    Attributes:
        network   : ipaddress.IPv4Network  (the canonical network object)
        broadcast : str                    (broadcast address for this network)
        label     : str                    (human-readable, echoed back to UI)
        host_count: int                    (number of usable host addresses)
    """

    def __init__(self, network: ipaddress.IPv4Network, label: str):
        self.network    = network
        self.broadcast  = str(network.broadcast_address)
        self.label      = label
        # exclude network address and broadcast address
        self.host_count = network.num_addresses - 2

    def __repr__(self):
        return f"<ParsedRange {self.label} → {self.network}>"


def parse_custom_range(raw: str) -> ParsedRange | None:
    """
    Parse a user-supplied range string into a ParsedRange.

    Supported formats
    ─────────────────
    1. CIDR                  : "10.51.144.0/22"
    2. Dotted-decimal mask   : "10.51.144.0/255.255.252.0"
    3. Short dash range      : "10.51.144.1-254"
       (last octet range within the same /24-equivalent prefix)
    4. Full dash range       : "10.51.144.1-10.51.147.254"
       (produces the smallest CIDR that covers both endpoints)

    Returns None and logs a warning on any parse error.
    """
    raw = raw.strip()
    if not raw:
        return None

    # ── Format 3 & 4: dash range ─────────────────────────────────────────────
    if "-" in raw and "/" not in raw:
        parts = raw.split("-", 1)
        start_str = parts[0].strip()
        end_str   = parts[1].strip()

        # Format 3: "10.51.144.1-254"  (end is just the last octet)
        if "." not in end_str:
            prefix_octets = start_str.rsplit(".", 1)[0]  # "10.51.144"
            end_str       = f"{prefix_octets}.{end_str}"

        try:
            start_ip = ipaddress.ip_address(start_str)
            end_ip   = ipaddress.ip_address(end_str)
        except ValueError as exc:
            log.warning("parse_custom_range: bad IP in dash range %r: %s", raw, exc)
            return None

        if start_ip > end_ip:
            start_ip, end_ip = end_ip, start_ip

        # Find the smallest supernet covering [start_ip, end_ip]
        nets = list(ipaddress.summarize_address_range(start_ip, end_ip))
        if len(nets) == 1:
            network = nets[0]
        else:
            # Multiple CIDRs needed; use the supernet that covers all of them
            # (collapse to the smallest single CIDR by expanding prefix length)
            network = nets[0].supernet(new_prefix=nets[0].prefixlen)
            for n in nets[1:]:
                while not n.subnet_of(network):
                    network = network.supernet()

        return ParsedRange(network, raw)

    # ── Format 1 (CIDR) and Format 2 (dotted mask) ───────────────────────────
    if "/" in raw:
        parts = raw.split("/", 1)
        ip_str   = parts[0].strip()
        mask_str = parts[1].strip()

        # Format 2: dotted-decimal mask → convert to prefix length
        if "." in mask_str:
            try:
                mask_int   = struct.unpack("!I", socket.inet_aton(mask_str))[0]
                prefix_len = bin(mask_int).count("1")
                raw_cidr   = f"{ip_str}/{prefix_len}"
            except Exception as exc:
                log.warning(
                    "parse_custom_range: bad dotted mask in %r: %s", raw, exc
                )
                return None
        else:
            raw_cidr = raw

        try:
            network = ipaddress.ip_network(raw_cidr, strict=False)
            return ParsedRange(network, raw)
        except ValueError as exc:
            log.warning("parse_custom_range: invalid CIDR %r: %s", raw, exc)
            return None

    # ── Single IP ─────────────────────────────────────────────────────────────
    try:
        network = ipaddress.ip_network(f"{raw}/32", strict=False)
        return ParsedRange(network, raw)
    except ValueError as exc:
        log.warning("parse_custom_range: cannot parse %r: %s", raw, exc)
        return None


def parse_custom_ranges(raw_list: list[str]) -> list[ParsedRange]:
    """Parse a list of raw range strings, silently dropping invalid entries."""
    results = []
    for raw in raw_list:
        pr = parse_custom_range(raw)
        if pr is not None:
            results.append(pr)
    return results


def describe_range(pr: ParsedRange) -> dict:
    """
    Return a JSON-serialisable dict describing a ParsedRange.
    This is what the /api/ranges endpoint returns to the dashboard.
    """
    network = pr.network
    return {
        "label":       pr.label,
        "network":     str(network),
        "broadcast":   pr.broadcast,
        "first_host":  str(network.network_address + 1),
        "last_host":   str(network.broadcast_address - 1),
        "host_count":  pr.host_count,
        "prefix_len":  network.prefixlen,
        "netmask":     str(network.netmask),
    }


# ── Broadcaster ───────────────────────────────────────────────────────────────

class DiscoveryBroadcaster:
    def __init__(self, config, store, ranges_file: str = _RANGES_FILE):
        self.config = config
        self.store  = store

        self._ranges_lock = threading.Lock()
        self._ranges_file = ranges_file

        # Load any previously saved custom ranges from disk.
        saved_raw = self._load_ranges()
        self._custom_ranges: list[ParsedRange] = parse_custom_ranges(saved_raw)
        if saved_raw:
            log.info(
                "Loaded %d custom range(s) from %s (%d valid)",
                len(saved_raw), self._ranges_file, len(self._custom_ranges)
            )

    # ── Persistence ────────────────────────────────────────────────────────────

    def _load_ranges(self) -> list[str]:
        """Load previously saved raw range strings from disk, if present."""
        try:
            if os.path.exists(self._ranges_file):
                with open(self._ranges_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return [str(x).strip() for x in data if str(x).strip()]
                log.warning(
                    "Ranges file %s did not contain a list — ignoring",
                    self._ranges_file
                )
        except Exception as e:
            log.warning("Failed to load ranges file %s: %s", self._ranges_file, e)
        return []

    def _save_ranges_locked(self, raw_list: list[str]):
        """Write raw range strings to disk. Caller must hold self._ranges_lock."""
        try:
            os.makedirs(os.path.dirname(self._ranges_file), exist_ok=True)
            tmp_path = self._ranges_file + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(raw_list, f, indent=2)
            os.replace(tmp_path, self._ranges_file)
        except Exception as e:
            log.warning("Failed to save ranges file %s: %s", self._ranges_file, e)

    # ── Custom range management ───────────────────────────────────────────────

    def set_custom_ranges(self, raw_list: list[str]) -> list[dict]:
        """
        Replace the current custom range list.

        `raw_list` is persisted to disk as-is (including any entries that
        fail to parse) so that the user's input is preserved across
        restarts. Invalid entries are simply dropped again on the next
        load, same as they are dropped here.

        Returns the parsed descriptions so the API can echo them back.
        """
        parsed = parse_custom_ranges(raw_list)
        with self._ranges_lock:
            self._custom_ranges = parsed
            self._save_ranges_locked(raw_list)
        log.info(
            "Custom ranges updated: %d valid range(s) from %d input(s)",
            len(parsed), len(raw_list)
        )
        return [describe_range(pr) for pr in parsed]

    def get_custom_ranges(self) -> list[dict]:
        """Return JSON-serialisable descriptions of all current custom ranges."""
        with self._ranges_lock:
            return [describe_range(pr) for pr in self._custom_ranges]

    def _snapshot_custom_ranges(self) -> list[ParsedRange]:
        """Thread-safe snapshot of current custom ranges for a broadcast run."""
        with self._ranges_lock:
            return list(self._custom_ranges)

    # ── Callback URL helpers ──────────────────────────────────────────────────

    def _callback_url_for(self, local_ip: str) -> str:
        if local_ip == "0.0.0.0":
            from config import get_lan_ip
            local_ip = get_lan_ip()
        return f"http://{local_ip}:{self.config.HTTP_PORT}/api/report"

    def _primary_callback_url(self) -> str:
        """Callback URL built from the server's primary LAN IP."""
        from config import get_lan_ip
        return self._callback_url_for(get_lan_ip())

    # ── Packet builder ────────────────────────────────────────────────────────

    def _build_packet(
        self,
        request_id: str,
        mode: str,
        target: str,
        callback_url: str,
        relay_depth: int = 0,
    ) -> bytes:
        """
        Build a signed discovery envelope.
        Key order MUST match the PowerShell HMAC reconstruction exactly.
        """
        packet = {
            "request_id":   request_id,
            "mode":         mode,
            "target":       target,
            "token":        self.config.SHARED_TOKEN,
            "callback_url": callback_url,
            "timestamp":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "relay_depth":  relay_depth,
        }
        payload_json = json.dumps(packet, separators=(",", ":")).encode()
        sig          = _sign_payload(payload_json, self.config.SHARED_TOKEN)
        envelope     = {"payload": packet, "sig": sig}
        return json.dumps(envelope, separators=(",", ":")).encode()

    # ── Low-level send helpers ────────────────────────────────────────────────

    def _send_udp(self, data: bytes, dest_ip: str, bind_ip: str | None = None):
        """Send a single UDP packet. bind_ip is optional interface binding."""
        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
            )
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(2)
            if bind_ip and bind_ip != "0.0.0.0":
                sock.bind((bind_ip, 0))
            sock.sendto(data, (dest_ip, self.config.UDP_PORT))
            sock.close()
        except OSError as exc:
            log.error("UDP send failed to %s: %s", dest_ip, exc)

    def _broadcast_on_interface(
        self,
        iface: dict,
        request_id: str,
        mode: str,
        target: str,
        relay_depth: int,
    ):
        """Send one signed broadcast packet out of a specific local interface."""
        callback_url = self._callback_url_for(iface["ip"])
        data         = self._build_packet(
            request_id, mode, target, callback_url, relay_depth
        )
        log.info(
            "Broadcast sent (%d bytes) iface=%s -> %s:%d callback=%s",
            len(data),
            iface["ip"],
            iface["broadcast"],
            self.config.UDP_PORT,
            callback_url,
        )
        self._send_udp(data, iface["broadcast"], bind_ip=iface["ip"])

    def _broadcast_custom_range(
        self,
        pr: ParsedRange,
        request_id: str,
        mode: str,
        target: str,
        relay_depth: int,
    ):
        """
        Broadcast into a user-defined custom range.

        Strategy:
          • Always send a subnet-directed broadcast to pr.broadcast.
          • For targeted mode we send only to the broadcast address
            (agents will still only respond if they are the target —
            this is enforced on the client side).
          • We use the server's primary LAN IP as the callback URL
            because we may not have a local address on the remote subnet.
        """
        callback_url = self._primary_callback_url()
        data = self._build_packet(
            request_id, mode, target, callback_url, relay_depth
        )

        log.info(
            "Custom-range broadcast (%s) → %s:%d",
            pr.label,
            pr.broadcast,
            self.config.UDP_PORT,
        )
        self._send_udp(data, pr.broadcast)

        # For full-discovery also send to the global broadcast in case
        # subnet-directed broadcast is filtered on some network segments.
        # Skip for targeted mode to avoid unnecessary noise.
        #if mode == "full":
        #    self._send_udp(data, "255.255.255.255")

    # ── Orchestration ─────────────────────────────────────────────────────────

    def _broadcast_all(
        self,
        request_id: str,
        mode: str,
        target: str,
        relay_depth: int,
    ):
        """
        Broadcast on:
          1. Every attached private local interface.
          2. Every user-configured custom range.
        All sends run in parallel.
        """
        interfaces    = _get_all_local_interfaces()
        custom_ranges = self._snapshot_custom_ranges()

        log.info(
            "Broadcasting on %d local interface(s) + %d custom range(s): ifaces=%s",
            len(interfaces),
            len(custom_ranges),
            [i["ip"] for i in interfaces],
        )

        threads: list[threading.Thread] = []

        # Local interface broadcasts (original behaviour)
        for iface in interfaces:
            t = threading.Thread(
                target=self._broadcast_on_interface,
                args=(iface, request_id, mode, target, relay_depth),
                daemon=True,
            )
            t.start()
            threads.append(t)

        # Custom range broadcasts (new)
        for pr in custom_ranges:
            t = threading.Thread(
                target=self._broadcast_custom_range,
                args=(pr, request_id, mode, target, relay_depth),
                daemon=True,
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=3)

    # ── Public API ────────────────────────────────────────────────────────────

    def send_targeted(self, request_id: str, target: str, mode: str):
        t = threading.Thread(
            target=self._broadcast_all,
            args=(request_id, f"targeted_{mode}", target, 0),
            daemon=True,
        )
        t.start()

    def send_full_discovery(self, request_id: str):
        t = threading.Thread(
            target=self._broadcast_all,
            args=(request_id, "full", "", 0),
            daemon=True,
        )
        t.start()