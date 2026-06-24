"""
Mneti Server - Flask-based device discovery server
Secure, lightweight, event-driven network device location system
"""

import os
import json
import uuid
import hmac
import hashlib
import socket
import struct
import threading
import time
import csv
import io
import logging
import ipaddress
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, send_file, abort, redirect, url_for, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from discovery import DiscoveryBroadcaster, _get_all_local_interfaces
from result_store import ResultStore
from arp_scanner import scan_subnet

# ── MAC Vendor Lookup Library ────────────────────────────────────────────────
try:
    from manuf import manuf
    _mac_parser = manuf.MacParser(update=False)
    MANUF_AVAILABLE = True
except Exception:
    _mac_parser = None
    MANUF_AVAILABLE = False

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("locator_server.log"),
        logging.StreamHandler(),
    ],
)

log = logging.getLogger("Mneti.server")

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", Config.FLASK_SECRET)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://",
)

store       = ResultStore()
broadcaster = DiscoveryBroadcaster(Config, store)

# How long to wait after sending the discovery broadcast before running
# the server-side ARP scan. This gives managed/relayed agents a head
# start to report themselves, so the upgrade-on-conflict logic in
# ResultStore has less work to do (though it handles either order
# correctly regardless).
ARP_SCAN_DELAY_SECONDS = 8

# Max concurrent ping workers per subnet during the ARP sweep.
# Reduced to 16 to prevent Windows process scheduler exhaustion.
ARP_SCAN_MAX_WORKERS = 16


# ── Security helpers ──────────────────────────────────────────────────────────

def validate_token(token: str) -> bool:
    return hmac.compare_digest(
        token.encode(),
        Config.SHARED_TOKEN.encode()
    )


def verify_hmac(payload: bytes, sig: str) -> bool:
    expected = hmac.new(
        Config.SHARED_TOKEN.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


def internal_only(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        try:
            addr = ipaddress.ip_address(client_ip)
            for net in Config.TRUSTED_NETWORKS:
                if addr in ipaddress.ip_network(net, strict=False):
                    return f(*args, **kwargs)
        except ValueError:
            pass
        log.warning("Rejected request from untrusted IP: %s", client_ip)
        abort(403)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated


# ── Vendor Lookup ─────────────────────────────────────────────────────────────

def lookup_vendor(mac: str) -> str:
    if not mac:
        return ""
    try:
        mac = str(mac).replace("-", ":").upper().strip()
        if not MANUF_AVAILABLE:
            return ""
        vendor = _mac_parser.get_manuf(mac)
        if vendor:
            return str(vendor)[:64]
    except Exception as e:
        log.debug("Vendor lookup failed for MAC %s: %s", mac, e)
    return ""


# ── Server-side ARP scan ──────────────────────────────────────────────────────

def _scan_networks_for_session() -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []

    for iface in _get_all_local_interfaces():
        try:
            # Derive the network from the actual broadcast address
            # rather than forcing /24
            ip = iface["ip"]
            broadcast = iface["broadcast"]
            # Find the prefix by checking which network contains both
            for prefix in range(32, 7, -1):
                net = ipaddress.ip_interface(f"{ip}/{prefix}").network
                if str(net.broadcast_address) == broadcast:
                    networks.append(net)
                    break
            else:
                # fallback
                networks.append(ipaddress.ip_interface(f"{ip}/24").network)
        except Exception:
            continue

    # Custom ranges (unchanged)
    for pr in broadcaster.get_custom_ranges():
        try:
            networks.append(ipaddress.ip_network(pr["network"]))
        except Exception:
            continue

    seen = set()
    unique_networks = []
    for net in networks:
        key = str(net)
        if key not in seen:
            seen.add(key)
            unique_networks.append(net)

    return unique_networks


def run_arp_scan_for_session(request_id: str):
    """
    Server-side ARP/ping sweep for unmanaged-device discovery.

    Runs after a short delay (ARP_SCAN_DELAY_SECONDS) so managed/relayed
    agents have a chance to report first — though correctness does not
    depend on this ordering: ResultStore.add_result() upgrades any
    "unmanaged" entry in place if a higher-priority managed/relayed
    report for the same MAC arrives later.

    Devices found in the ARP table that aren't already known for this
    session (by MAC) are reported as type="unmanaged".
    """
    try:
        sess = store.get(request_id)
        if sess is None:
            log.warning("ARP scan: session %s no longer exists — skipping", request_id)
            return

        already_macs = {
            d.get("mac", "").strip().upper()
            for d in sess.get("devices", [])
            if d.get("mac", "").strip()
        }

        networks = _scan_networks_for_session()
        log.info(
            "ARP scan starting for session %s across %d network(s): %s",
            request_id, len(networks), [str(n) for n in networks]
        )

        for net in networks:
            # SAFETY CHECK: Do not ARP-scan networks larger than /22 (1024 hosts)
            # Scanning 1000+ IPs individually is too heavy for a single Windows machine.
            if net.num_addresses > 1024:
                log.warning("ARP scan: Skipping %s (too large: %d hosts). Limit is 1024.", net, net.num_addresses)
                continue

            try:
                found = scan_subnet(net, max_workers=ARP_SCAN_MAX_WORKERS)
            except Exception as e:
                log.warning("ARP scan failed for %s: %s", net, e)
                continue

            for ip, mac in found.items():
                mac_norm = mac.upper()
                if mac_norm in already_macs:
                    continue

                device = {
                    "hostname":       f"Unmanaged-{ip}",
                    "mac":            mac_norm,
                    "ip":             ip,
                    "username":       "",
                    "building":       "",
                    "room":           "",
                    "timestamp":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "type":           "unmanaged",
                    "relay_host":     "",
                    "relay_building": "",
                    "relay_room":     "",
                    "vendor":         lookup_vendor(mac_norm),
                    "received_at":    datetime.now(timezone.utc).isoformat(),
                    "reporter_ip":    "server-arp-scan",
                }

                store.add_result(request_id, device)
                already_macs.add(mac_norm)

                log.info(
                    "ARP scan: unmanaged device %s (%s) in %s — id=%s",
                    ip, mac_norm, net, request_id
                )

        log.info("ARP scan complete for session %s", request_id)
    except Exception:
        log.exception("ARP scan crashed for session %s", request_id)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/")
@admin_required
def dashboard():
    from config import get_lan_ip
    return render_template("dashboard.html", server_ip=get_lan_ip())


# ── Discovery API ─────────────────────────────────────────────────────────────

@app.route("/api/discover/targeted", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def discover_targeted():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    target = data.get("target", "").strip()
    mode   = data.get("mode", "mac").strip().lower()

    if mode not in ("mac", "ip"):
        return jsonify({"error": "mode must be 'mac' or 'ip'"}), 400
    if not target:
        return jsonify({"error": "target is required"}), 400

    request_id = str(uuid.uuid4())
    store.init_session(request_id, "targeted")
    log.info("Targeted discovery: mode=%s target=%s id=%s", mode, target, request_id)
    broadcaster.send_targeted(request_id, target, mode)

    # Targeted searches are for one specific device — no ARP scan needed.
    return jsonify({"request_id": request_id, "status": "broadcast_sent"})


@app.route("/api/discover/all", methods=["POST"])
@admin_required
@limiter.limit("10 per minute")
def discover_all():
    request_id = str(uuid.uuid4())
    store.init_session(request_id, "full")
    log.info("Full network discovery initiated: id=%s", request_id)
    broadcaster.send_full_discovery(request_id)

    # Run the server-side ARP scan in the background after a short delay,
    # so managed/relayed agents get a head start to self-report. The
    # upgrade-on-conflict logic in ResultStore means correctness doesn't
    # depend on this ordering, but it reduces churn in the UI.
    def delayed_scan():
        time.sleep(ARP_SCAN_DELAY_SECONDS)
        run_arp_scan_for_session(request_id)

    threading.Thread(target=delayed_scan, daemon=True).start()

    return jsonify({"request_id": request_id, "status": "broadcast_sent"})


@app.route("/api/results/<request_id>")
@admin_required
def get_results(request_id):
    results = store.get(request_id)
    if results is None:
        return jsonify({"error": "Unknown request_id"}), 404
    return jsonify(results)


# ── History ───────────────────────────────────────────────────────────────────

@app.route("/api/history")
@admin_required
def get_history():
    """Return lightweight session summaries for the history index list."""
    return jsonify(store.get_history())


@app.route("/api/history/<request_id>")
@admin_required
def get_history_session(request_id):
    """
    Return full session data including all device details for a single session.
    Used by the dashboard when a user clicks a session row to view its devices.
    Falls back to persisted history.json if the session is no longer in memory.
    """
    data = store.get_history_session(request_id)
    if data is None:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(data)


# ── Custom Broadcast Ranges ───────────────────────────────────────────────────

@app.route("/api/ranges", methods=["GET"])
@admin_required
def get_ranges():
    return jsonify({"ranges": broadcaster.get_custom_ranges()})


@app.route("/api/ranges", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def set_ranges():
    data = request.get_json(silent=True)
    if not data or not isinstance(data.get("ranges"), list):
        return jsonify({"error": "Body must be {\"ranges\": [...]}"}), 400

    # broadcaster.set_custom_ranges now handles list of dicts or strings
    parsed = broadcaster.set_custom_ranges(data["ranges"])

    log.info("Custom ranges updated via API: %d/%d accepted", len(parsed), len(data["ranges"]))
    return jsonify({
        "ranges":   parsed,
        "accepted": len(parsed),
        "rejected": len(data["ranges"]) - len(parsed),
    })


# ── Client callback ───────────────────────────────────────────────────────────

@app.route("/api/report", methods=["POST"])
@internal_only
@limiter.limit("500 per minute")
def receive_report():
    raw = request.get_data()

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        log.warning("400 bad JSON from %s: %r", request.remote_addr, raw[:120])
        return jsonify({"error": "bad request"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "bad request"}), 400

    token = data.get("token", "")
    if not validate_token(token):
        log.warning("401 bad token from %s", request.remote_addr)
        return jsonify({"error": "unauthorized"}), 401

    sig = request.headers.get("X-Signature")
    if sig:
        if not verify_hmac(raw, sig):
            log.warning("401 HMAC mismatch from %s", request.remote_addr)
            return jsonify({"error": "signature mismatch"}), 401

    request_id = data.get("request_id")
    if not request_id or not store.session_exists(request_id):
        log.warning("400 unknown request_id %r from %s", request_id, request.remote_addr)
        return jsonify({"error": "unknown request_id"}), 400

    mac         = str(data.get("mac", ""))[:17]
    device_type = str(data.get("type", "managed"))

    vendor = str(data.get("vendor", ""))[:64].strip()
    if not vendor:
        vendor = lookup_vendor(mac)

    # ── Location attribution ──────────────────────────────────────────────────
    # For ALL device types (including unmanaged), we preserve relay location
    # data from the reporting agent. When an agent hotspots a device without
    # its own Mneti agent, it relays building/room from its own config so the
    # unmanaged device is attributed to the physical location of the hotspot
    # host. Server-side ARP scan entries will have empty strings here, which
    # is fine — those devices were seen directly on the server's subnet.
    building       = str(data.get("building", ""))[:128]
    room           = str(data.get("room", ""))[:64]
    relay_host     = str(data.get("relay_host", ""))[:128]
    relay_building = str(data.get("relay_building", ""))[:128]
    relay_room     = str(data.get("relay_room", ""))[:64]

    # For managed devices there is no relay chain — clear relay fields to
    # avoid stale data if a client accidentally includes them.
    if device_type == "managed":
        relay_host     = ""
        relay_building = ""
        relay_room     = ""

    device = {
        "hostname":       str(data.get("hostname", ""))[:128],
        "mac":            mac,
        "ip":             str(data.get("ip", ""))[:45],
        "username":       str(data.get("username", ""))[:64],
        "building":       building,
        "room":           room,
        "timestamp":      str(data.get("timestamp", ""))[:32],
        "type":           device_type,
        "relay_host":     relay_host,
        "relay_building": relay_building,
        "relay_room":     relay_room,
        "vendor":         vendor,
        "received_at":    datetime.now(timezone.utc).isoformat(),
        "reporter_ip":    request.remote_addr,
        "connection_type": str(data.get("connection_type", ""))[:32],
        "port":           str(data.get("port", ""))[:32],
        "additional_ports": data.get("additional_ports", []),
    }

    store.add_result(request_id, device)

    log.info(
        "Report received: %s (%s) id=%s type=%s vendor=%s building=%r room=%r relay_host=%r",
        device["hostname"], device["ip"], request_id, device_type,
        vendor, building, room, relay_host
    )
    return jsonify({"status": "ok"})


# ── Export ────────────────────────────────────────────────────────────────────

@app.route("/api/export/<request_id>")
@admin_required
def export_csv(request_id):
    # Try live session first, then history
    data = store.get(request_id)
    if not data:
        data = store.get_history_session(request_id)
    if not data:
        abort(404)

    output = io.StringIO()
    fields = [
        "hostname", "mac", "ip", "username",
        "building", "room", "type",
        "relay_host", "relay_building", "relay_room",
        "vendor", "timestamp", "received_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for d in data.get("devices", []):
        writer.writerow(d)
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"discovery_{request_id[:8]}.csv",
    )


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if MANUF_AVAILABLE:
        log.info("manuf IEEE OUI database loaded successfully")
    else:
        log.warning("manuf library not installed. MAC vendor lookup disabled.")

    log.info("Mneti Server starting on port %d", Config.HTTP_PORT)
    app.run(host="0.0.0.0", port=Config.HTTP_PORT, debug=False, threaded=True)