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
from discovery import DiscoveryBroadcaster
from result_store import ResultStore

# ── MAC Vendor Lookup Library ────────────────────────────────────────────────
#
# Install:
#   pip install manuf
#
# This uses the full IEEE OUI database and automatically identifies
# manufacturers from MAC addresses.
#

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

store = ResultStore()
broadcaster = DiscoveryBroadcaster(Config, store)

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

        log.warning(
            "Rejected request from untrusted IP: %s",
            client_ip
        )

        abort(403)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)

    return decorated


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/")
@admin_required
def dashboard():
    from config import get_lan_ip

    return render_template(
        "dashboard.html",
        server_ip=get_lan_ip()
    )


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
        return jsonify(
            {"error": "mode must be 'mac' or 'ip'"}
        ), 400

    if not target:
        return jsonify(
            {"error": "target is required"}
        ), 400

    request_id = str(uuid.uuid4())

    store.init_session(request_id, "targeted")

    log.info(
        "Targeted discovery: mode=%s target=%s id=%s",
        mode,
        target,
        request_id
    )

    broadcaster.send_targeted(
        request_id,
        target,
        mode
    )

    return jsonify({
        "request_id": request_id,
        "status": "broadcast_sent"
    })


@app.route("/api/discover/all", methods=["POST"])
@admin_required
@limiter.limit("10 per minute")
def discover_all():

    request_id = str(uuid.uuid4())

    store.init_session(request_id, "full")

    log.info(
        "Full network discovery initiated: id=%s",
        request_id
    )

    broadcaster.send_full_discovery(request_id)

    return jsonify({
        "request_id": request_id,
        "status": "broadcast_sent"
    })


@app.route("/api/results/<request_id>")
@admin_required
def get_results(request_id):

    results = store.get(request_id)

    if results is None:
        return jsonify(
            {"error": "Unknown request_id"}
        ), 404

    return jsonify(results)


@app.route("/api/history")
@admin_required
def get_history():
    return jsonify(store.get_history())


# ── Vendor Lookup ─────────────────────────────────────────────────────────────

def lookup_vendor(mac: str) -> str:
    """
    Lookup MAC vendor using manuf IEEE OUI database.
    """

    if not mac:
        return ""

    try:

        mac = (
            str(mac)
            .replace("-", ":")
            .upper()
            .strip()
        )

        if not MANUF_AVAILABLE:
            return ""

        vendor = _mac_parser.get_manuf(mac)

        if vendor:
            return str(vendor)[:64]

    except Exception as e:
        log.debug(
            "Vendor lookup failed for MAC %s: %s",
            mac,
            e
        )

    return ""


# ── Client callback ───────────────────────────────────────────────────────────

@app.route("/api/report", methods=["POST"])
@internal_only
@limiter.limit("500 per minute")
def receive_report():
    """
    Location and relay attribution rules enforced server-side:

      type = 'managed'   → has its own building/room (agent reported it).
                           relay fields are blank.

      type = 'relayed'   → managed agent reached via another machine's hotspot.
                           relay_host/building/room = the hotspot machine.
                           building/room = the device's own reported location.

      type = 'unmanaged' → ARP-discovered device, no agent installed.
                           building/room forced blank (location unknown).
                           relay fields forced blank (not a hotspot client).

    Raw body must be read before any JSON parsing — get_json() consumes the
    stream and makes a subsequent get_data() return b"", breaking HMAC verify.
    """

    raw = request.get_data()

    try:
        data = json.loads(raw)

    except (json.JSONDecodeError, ValueError):

        log.warning(
            "400 bad JSON from %s: %r",
            request.remote_addr,
            raw[:120]
        )

        return jsonify({"error": "bad request"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "bad request"}), 400

    token = data.get("token", "")

    if not validate_token(token):

        log.warning(
            "401 bad token from %s",
            request.remote_addr
        )

        return jsonify({"error": "unauthorized"}), 401

    sig = request.headers.get("X-Signature")

    if sig:
        if not verify_hmac(raw, sig):

            log.warning(
                "401 HMAC mismatch from %s",
                request.remote_addr
            )

            return jsonify(
                {"error": "signature mismatch"}
            ), 401

    request_id = data.get("request_id")

    if not request_id or not store.session_exists(request_id):

        log.warning(
            "400 unknown request_id %r from %s",
            request_id,
            request.remote_addr
        )

        return jsonify(
            {"error": "unknown request_id"}
        ), 400

    mac         = str(data.get("mac", ""))[:17]
    device_type = str(data.get("type", "managed"))

    vendor = (
        str(data.get("vendor", ""))
        [:64]
        .strip()
    )

    if not vendor:
        vendor = lookup_vendor(mac)

    # ── Location attribution ──────────────────────────────────────────────────

    if device_type == "unmanaged":

        building       = ""
        room           = ""
        relay_host     = ""
        relay_building = ""
        relay_room     = ""

    elif device_type == "relayed":

        building       = str(data.get("building", ""))[:128]
        room           = str(data.get("room", ""))[:64]

        relay_host     = str(data.get("relay_host", ""))[:128]
        relay_building = str(data.get("relay_building", ""))[:128]
        relay_room     = str(data.get("relay_room", ""))[:64]

    else:  # managed

        building       = str(data.get("building", ""))[:128]
        room           = str(data.get("room", ""))[:64]

        relay_host     = ""
        relay_building = ""
        relay_room     = ""

    device = {

        "hostname": str(data.get("hostname", ""))[:128],
        "mac": mac,
        "ip": str(data.get("ip", ""))[:45],
        "username": str(data.get("username", ""))[:64],

        "building": building,
        "room": room,

        "timestamp": str(data.get("timestamp", ""))[:32],

        "type": device_type,

        "relay_host": relay_host,
        "relay_building": relay_building,
        "relay_room": relay_room,

        "vendor": vendor,

        "received_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "reporter_ip": request.remote_addr,
    }

    store.add_result(request_id, device)

    log.info(
        "Report received: %s (%s) id=%s type=%s vendor=%s building=%r room=%r",
        device["hostname"],
        device["ip"],
        request_id,
        device_type,
        vendor,
        building,
        room
    )

    return jsonify({"status": "ok"})


# ── Export ────────────────────────────────────────────────────────────────────

@app.route("/api/export/<request_id>")
@admin_required
def export_csv(request_id):

    data = store.get(request_id)

    if not data:
        abort(404)

    output = io.StringIO()

    fields = [
        "hostname",
        "mac",
        "ip",
        "username",
        "building",
        "room",
        "type",
        "relay_host",
        "relay_building",
        "relay_room",
        "vendor",
        "timestamp",
        "received_at",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fields,
        extrasaction="ignore"
    )

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

    return jsonify({
        "status": "ok",
        "time": datetime.now(
            timezone.utc
        ).isoformat()
    })


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    if MANUF_AVAILABLE:
        log.info("manuf IEEE OUI database loaded successfully")
    else:
        log.warning(
            "manuf library not installed. "
            "MAC vendor lookup disabled."
        )

    log.info(
        "Mneti Server starting on port %d",
        Config.HTTP_PORT
    )

    app.run(
        host="0.0.0.0",
        port=Config.HTTP_PORT,
        debug=False,
        threaded=True
    )