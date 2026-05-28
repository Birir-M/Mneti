"""
Mneti - UDP Discovery Broadcaster
Sends signed broadcast packets to trigger client-side discovery.
Broadcasts on ALL attached local interfaces so devices on every
subnet the server is connected to receive the discovery packet.
"""

import json
import hmac
import hashlib
import socket
import struct
import logging
import threading
import ipaddress
from datetime import datetime, timezone

log = logging.getLogger("mneti.broadcaster")


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
            "netmask":   "255.255.255.0",
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
        import socket as _s
        # getaddrinfo gives us all bound addresses; use gethostbyname_ex for
        # a quick list then fall back to a platform-specific approach.
        hostname = _s.gethostname()
        _, _, ip_list = _s.gethostbyname_ex(hostname)
        for ip_str in ip_list:
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.is_loopback or addr.is_link_local:
                    continue
                in_private = any(addr in net for net in private_nets)
                if not in_private:
                    continue
                # Determine broadcast via a connected UDP socket trick
                sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
                sock.bind((ip_str, 0))
                # Use /24 as a safe default; refine below if we can get netmask
                network = ipaddress.ip_interface(f"{ip_str}/24").network
                broadcast = str(network.broadcast_address)
                sock.close()
                interfaces.append({
                    "ip": ip_str,
                    "broadcast": broadcast,
                })
            except Exception:
                continue
    except Exception as e:
        log.warning("Interface enumeration error: %s", e)

    # Prefer a more accurate approach using netifaces if available,
    # otherwise fall back to the /24 approximation above.
    try:
        import netifaces
        interfaces = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in addrs:
                continue
            for entry in addrs[netifaces.AF_INET]:
                ip_str = entry.get("addr", "")
                netmask = entry.get("netmask", "255.255.255.0")
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
                    interfaces.append({
                        "ip": ip_str,
                        "broadcast": broadcast,
                    })
                except Exception:
                    continue
    except ImportError:
        pass  # netifaces not installed; use the approximation above

    if not interfaces:
        # Last resort: fall back to a single global broadcast
        interfaces = [{"ip": "0.0.0.0", "broadcast": "255.255.255.255"}]

    return interfaces


# ── Broadcaster ───────────────────────────────────────────────────────────────

class DiscoveryBroadcaster:
    def __init__(self, config, store):
        self.config = config
        self.store = store

    def _callback_url_for(self, local_ip: str) -> str:
        """Build the callback URL using the interface IP that sent the broadcast."""
        if local_ip == "0.0.0.0":
            # Fall back to primary LAN IP
            from config import get_lan_ip
            local_ip = get_lan_ip()
        return f"http://{local_ip}:{self.config.HTTP_PORT}/api/report"

    def _build_packet(self, request_id: str, mode: str, target: str,
                      callback_url: str, relay_depth: int = 0) -> bytes:
        """
        Build a signed discovery envelope.
        Key order MUST match the PowerShell HMAC reconstruction exactly.
        """
        packet = {
            "request_id":  request_id,
            "mode":        mode,
            "target":      target,
            "token":       self.config.SHARED_TOKEN,
            "callback_url": callback_url,
            "timestamp":   datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "relay_depth": relay_depth,
        }
        payload_json = json.dumps(packet, separators=(",", ":")).encode()
        sig = _sign_payload(payload_json, self.config.SHARED_TOKEN)
        envelope = {"payload": packet, "sig": sig}
        return json.dumps(envelope, separators=(",", ":")).encode()

    def _broadcast_on_interface(self, iface: dict, request_id: str,
                                 mode: str, target: str, relay_depth: int):
        """Send one signed broadcast packet out of a specific interface."""
        callback_url = self._callback_url_for(iface["ip"])
        data = self._build_packet(request_id, mode, target, callback_url, relay_depth)
        broadcast_addr = iface["broadcast"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(2)
            # Bind to the specific interface so the OS routes correctly
            if iface["ip"] != "0.0.0.0":
                sock.bind((iface["ip"], 0))
            sock.sendto(data, (broadcast_addr, self.config.UDP_PORT))
            sock.close()
            log.info(
                "Broadcast sent (%d bytes) iface=%s -> %s:%d callback=%s",
                len(data), iface["ip"], broadcast_addr,
                self.config.UDP_PORT, callback_url,
            )
        except OSError as e:
            log.error("Broadcast failed on iface %s: %s", iface["ip"], e)

    def _broadcast_all(self, request_id: str, mode: str,
                        target: str, relay_depth: int):
        """Broadcast on every attached private interface in parallel."""
        interfaces = _get_all_local_interfaces()
        log.info("Broadcasting on %d interface(s): %s",
                 len(interfaces), [i["ip"] for i in interfaces])
        threads = []
        for iface in interfaces:
            t = threading.Thread(
                target=self._broadcast_on_interface,
                args=(iface, request_id, mode, target, relay_depth),
                daemon=True,
            )
            t.start()
            threads.append(t)
        # Wait briefly so callers get predictable timing
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