import os
import sys
import json
import uuid
import hmac
import hashlib
import socket
import struct
import threading
import time
import ipaddress
import logging
from datetime import datetime, timezone
import psutil
import psutil
import concurrent.futures
import platform
import subprocess
import re

log = logging.getLogger("mneti.logic")

def parse_custom_range(raw: str) -> "ParsedRange | None":
    raw = raw.strip()
    if not raw: return None
    if "-" in raw and "/" not in raw:
        parts = raw.split("-", 1)
        start_str = parts[0].strip()
        end_str = parts[1].strip()
        if "." not in end_str:
            prefix = start_str.rsplit(".", 1)[0]
            end_str = f"{prefix}.{end_str}"
        try:
            start_ip = ipaddress.ip_address(start_str)
            end_ip = ipaddress.ip_address(end_str)
            if start_ip > end_ip: start_ip, end_ip = end_ip, start_ip
            nets = list(ipaddress.summarize_address_range(start_ip, end_ip))
            if not nets: return None
            network = nets[0]
            if len(nets) > 1:
                network = nets[0].supernet(new_prefix=nets[0].prefixlen)
                for n in nets[1:]:
                    while not n.subnet_of(network): network = network.supernet()
            return ParsedRange(network, raw)
        except Exception: return None
    if "/" in raw:
        try:
            val = raw
            if "." in raw.split("/")[1]:
                ip_str, mask_str = raw.split("/")
                mask_int = struct.unpack("!I", socket.inet_aton(mask_str.strip()))[0]
                prefix = bin(mask_int).count("1")
                val = f"{ip_str.strip()}/{prefix}"
            return ParsedRange(ipaddress.ip_network(val, strict=False), raw)
        except Exception: return None
    try:
        return ParsedRange(ipaddress.ip_network(f"{raw}/32", strict=False), raw)
    except Exception: return None

# ── Config ───────────────────────────────────────────────────────────────────

def get_lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

class Config:
    SHARED_TOKEN = os.environ.get("MNETI_TOKEN", "CHANGE_ME_USE_A_LONG_RANDOM_SECRET_AT_LEAST_32_CHARS")
    UDP_PORT = 5000
    HTTP_PORT = 5001
    DISCOVERY_TIMEOUT = 5
    RESULT_TTL = 3600
    TRUSTED_NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
    UDP_BROADCAST_ADDR = "255.255.255.255"
    UDP_TTL = 4
    BASE_DIR = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, "qt_data")
    
    # Secure Token Loading (matches Flask server)
    SHARED_TOKEN = "Markcheruiyot"
    _env_path = os.path.join(BASE_DIR, ".env")
    if os.path.exists(_env_path):
        try:
            with open(_env_path, 'r') as f:
                for line in f:
                    if line.startswith("MNETI_TOKEN="):
                        SHARED_TOKEN = line.split("=", 1)[1].strip()
        except Exception: pass
    
    # Override with env var if present
    SHARED_TOKEN = os.environ.get("MNETI_TOKEN", SHARED_TOKEN)

# ── MAC Vendor Lookup ────────────────────────────────────────────────────────

try:
    from manuf import manuf
    _mac_parser = manuf.MacParser(update=False)
    MANUF_AVAILABLE = True
except Exception:
    _mac_parser = None
    MANUF_AVAILABLE = False

def lookup_vendor(mac: str) -> str:
    if not mac or not MANUF_AVAILABLE:
        return ""
    try:
        mac = str(mac).replace("-", ":").upper().strip()
        vendor = _mac_parser.get_manuf(mac)
        return str(vendor)[:64] if vendor else ""
    except Exception:
        return ""

# ── ARP Scanner ─────────────────────────────────────────────────────────────

_ARP_LINE_RE_WIN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'
    r'(?P<mac>[\da-fA-F]{2}(?:[:\-][\da-fA-F]{2}){5})\s+dynamic',
    re.IGNORECASE,
)

# On Windows, suppress the console window that subprocess would otherwise
# open for every ping/arp call. This is what was causing many foreground
# command-prompt tabs to appear when running as a .exe.
_CREATE_NO_WINDOW = 0x08000000 if platform.system().lower() == "windows" else 0

def _ping(ip: str, timeout_ms: int = 200):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_s = max(1, round(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            timeout=2,
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception: pass

def _read_arp_table() -> dict:
    result = {}
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            ).stdout
            for line in out.splitlines():
                m = _ARP_LINE_RE_WIN.search(line)
                if m: result[m.group("ip")] = m.group("mac").upper().replace("-", ":")
    except Exception: pass
    return result

def scan_subnet(network: ipaddress.IPv4Network, timeout: int = 2, max_workers: int = 16) -> dict:
    """Scan a subnet using ping sweep + ARP table read (robust on Windows)."""
    try:
        hosts = [str(h) for h in network.hosts()]
        if not hosts: return {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            list(ex.map(_ping, hosts))
        
        arp_table = _read_arp_table()
        host_set = set(hosts)
        return {ip: mac for ip, mac in arp_table.items() if ip in host_set}
    except Exception as e:
        log.error(f"Scan failed: {e}")
        return {}

# ── Result Store ────────────────────────────────────────────────────────────

_TYPE_PRIORITY = {"unmanaged": 0, "relayed": 1, "managed": 2}

class ResultStore:
    def __init__(self, ttl: int = Config.RESULT_TTL):
        self._ttl = ttl
        self._lock = threading.Lock()
        self._sessions = {}
        self._data_dir = Config.DATA_DIR
        os.makedirs(self._data_dir, exist_ok=True)
        self._history_file = os.path.join(self._data_dir, "history.json")
        self._history = self._load_history()
        threading.Thread(target=self._reap, daemon=True).start()

    def _load_history(self) -> list:
        try:
            if os.path.exists(self._history_file):
                with open(self._history_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []
        return []

    def _save_history_locked(self):
        try:
            with open(self._history_file, "w", encoding="utf-8") as f:
                json.dump(self._history[-200:], f, indent=2)
        except Exception as e:
            log.warning(f"Failed to save history: {e}")

    def init_session(self, request_id: str, discovery_type: str):
        now = time.monotonic()
        with self._lock:
            session = {
                "request_id": request_id,
                "type": discovery_type,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "devices": [],
                "expires_at": now + self._ttl,
                "last_activity": now,
            }
            self._sessions[request_id] = session
            self._history.append(session)
            self._save_history_locked()

    def session_exists(self, request_id: str) -> bool:
        return request_id in self._sessions

    def add_result(self, request_id: str, device: dict):
        with self._lock:
            session = self._sessions.get(request_id)
            if not session: return

            mac = device.get("mac", "").strip().lower()
            if mac:
                for i, existing in enumerate(session["devices"]):
                    if existing.get("mac", "").strip().lower() == mac:
                        if _TYPE_PRIORITY.get(device["type"], 0) > _TYPE_PRIORITY.get(existing["type"], 0):
                            session["devices"][i] = device
                            session["last_activity"] = time.monotonic()
                            self._update_history_locked(session)
                        return

            session["devices"].append(device)
            session["last_activity"] = time.monotonic()
            self._update_history_locked(session)

    def _update_history_locked(self, session):
        for i, h in enumerate(self._history):
            if h.get("request_id") == session["request_id"]:
                self._history[i] = session
                self._save_history_locked()
                break

    def get_session(self, request_id: str) -> dict | None:
        with self._lock:
            if request_id in self._sessions:
                return dict(self._sessions[request_id])
            for h in reversed(self._history):
                if h.get("request_id") == request_id:
                    return dict(h)
        return None

    def get_history(self) -> list:
        with self._lock:
            return [{
                "request_id": h["request_id"],
                "type": h["type"],
                "started_at": h["started_at"],
                "device_count": len(h["devices"])
            } for h in self._history]

    def _reap(self):
        while True:
            time.sleep(60)
            now = time.monotonic()
            with self._lock:
                expired = [rid for rid, s in self._sessions.items() if s["expires_at"] < now]
                for rid in expired:
                    self._sessions.pop(rid)

# ── Broadcaster ─────────────────────────────────────────────────────────────

class ParsedRange:
    def __init__(self, network: ipaddress.IPv4Network, label: str, is_primary: bool = False):
        self.network = network
        self.broadcast = str(network.broadcast_address)
        self.label = label
        self.host_count = network.num_addresses - 2
        self.is_primary = is_primary

class DiscoveryBroadcaster:
    def __init__(self, store):
        self.store = store
        self.data_dir = Config.DATA_DIR
        self.ranges_file = os.path.join(self.data_dir, "ranges.json")
        self._custom_ranges = self._load_ranges()

    def _load_ranges(self) -> list:
        try:
            if os.path.exists(self.ranges_file):
                with open(self.ranges_file, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                return [ParsedRange(ipaddress.ip_network(r["network"]), r["label"], r.get("is_primary", False)) for r in raw]
        except Exception:
            return []
        return []

    def _save_ranges(self):
        try:
            data = [{"network": str(r.network), "label": r.label, "is_primary": r.is_primary} for r in self._custom_ranges]
            with open(self.ranges_file, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception as e:
            log.error(f"Failed to save ranges: {e}")

    def add_range(self, raw_cidr: str, label: str, is_primary: bool = False):
        try:
            net = ipaddress.ip_network(raw_cidr, strict=False)
            self._custom_ranges.append(ParsedRange(net, label, is_primary))
            self._save_ranges()
            return True
        except Exception:
            return False

    def remove_range(self, index: int):
        if 0 <= index < len(self._custom_ranges):
            self._custom_ranges.pop(index)
            self._save_ranges()

    def get_ranges(self) -> list:
        return self._custom_ranges

    def _get_local_interfaces(self):
        interfaces = []
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    try:
                        net = ipaddress.IPv4Interface(f"{addr.address}/{addr.netmask}")
                        interfaces.append({"ip": addr.address, "broadcast": str(net.network.broadcast_address)})
                    except Exception: continue
        return interfaces

    def _send_udp(self, data: bytes, dest_ip: str, bind_ip: str = None):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if bind_ip: sock.bind((bind_ip, 0))
            sock.sendto(data, (dest_ip, Config.UDP_PORT))
            sock.close()
        except Exception: pass

    def _broadcast_custom_range(self, pr, request_id: str, mode: str, target: str, relay_depth: int):
        callback_url = f"http://{get_lan_ip()}:{Config.HTTP_PORT}/api/report"
        data = self._build_packet(request_id, mode, target, callback_url, pr.is_primary)
        self._send_udp(data, pr.broadcast)

    def _build_packet(self, request_id: str, mode: str, target: str, callback_url: str, is_primary: bool = False):
        packet = {
            "request_id": request_id,
            "mode": mode,
            "target": target,
            "token": Config.SHARED_TOKEN,
            "callback_url": callback_url,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "relay_depth": 0,
            "is_primary": is_primary,
        }
        payload = json.dumps(packet, separators=(",", ":")).encode()
        sig = hmac.new(Config.SHARED_TOKEN.encode(), payload, hashlib.sha256).hexdigest()
        return json.dumps({"payload": packet, "sig": sig}, separators=(",", ":")).encode()

    def send_range_discovery(self, request_id: str, raw_range: str):
        pr = parse_custom_range(raw_range)
        if pr:
            t = threading.Thread(
                target=self._broadcast_custom_range,
                args=(pr, request_id, "full", "", 0),
                daemon=True
            )
            t.start()
            return True
        return False

    def broadcast(self, request_id: str, mode="full", target: str = ""):
        ifaces = self._get_local_interfaces()
        
        # Determine networks to broadcast to
        active_ranges = list(self._custom_ranges)
        
        # If no custom ranges, add /25 of each interface as a fallback range
        if not active_ranges and mode == "full":
            for iface in ifaces:
                try:
                    # Get the /25 network containing this interface IP
                    iface_net = ipaddress.IPv4Interface(f"{iface['ip']}/25").network
                    active_ranges.append(ParsedRange(iface_net, f"Auto /25 ({iface['ip']})"))
                except Exception: continue

        # Send to local interface broadcasts
        for iface in ifaces:
            data = self._build_packet(request_id, mode, target, f"http://{iface['ip']}:{Config.HTTP_PORT}/api/report", False)
            self._send_udp(data, iface["broadcast"], bind_ip=iface["ip"])
        
        # Send to custom (or fallback) ranges
        for r in active_ranges:
            data = self._build_packet(request_id, mode, target, f"http://{get_lan_ip()}:{Config.HTTP_PORT}/api/report", r.is_primary)
            self._send_udp(data, r.broadcast)

    def get_scan_networks(self):
        """Returns list of ipaddress.IPv4Network objects to be used for ARP scanning."""
        ifaces = self._get_local_interfaces()
        networks = []
        
        # Add interface networks (using their actual mask)
        for iface in ifaces:
            try:
                # Try to derive the network
                net = ipaddress.IPv4Interface(f"{iface['ip']}/24").network # Default to /24 for scan if unclear
                networks.append(net)
            except Exception: continue
            
        # Add custom ranges
        for r in self._custom_ranges:
            networks.append(r.network)
            
        # If no custom ranges, ensure we have the /25 fallbacks for scanning too
        if not self._custom_ranges:
            for iface in ifaces:
                try:
                    net = ipaddress.IPv4Interface(f"{iface['ip']}/25").network
                    if net not in networks: networks.append(net)
                except Exception: continue
                
        return networks
