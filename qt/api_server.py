import json
import logging
from flask import Flask, request, jsonify
from PyQt6.QtCore import QThread, pyqtSignal
from qt.logic import Config, lookup_vendor

log = logging.getLogger("mneti.api")

class ApiServerThread(QThread):
    device_reported = pyqtSignal(str, dict)  # request_id, device_data

    def __init__(self, store):
        super().__init__()
        self.store = store
        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):
        @self.app.route("/api/report", methods=["POST"])
        def receive_report():
            raw = request.get_data()
            try:
                data = json.loads(raw)
            except Exception:
                return jsonify({"error": "bad request"}), 400

            # Minimal validation (token check)
            if data.get("token") != Config.SHARED_TOKEN:
                return jsonify({"error": "unauthorized"}), 401

            request_id = data.get("request_id")
            if not request_id or not self.store.session_exists(request_id):
                return jsonify({"error": "unknown request_id"}), 400

            mac = str(data.get("mac", ""))[:17]
            vendor = str(data.get("vendor", "")).strip()
            if not vendor:
                vendor = lookup_vendor(mac)

            device = {
                "hostname": str(data.get("hostname", ""))[:128],
                "mac": mac,
                "ip": str(data.get("ip", ""))[:45],
                "username": str(data.get("username", ""))[:64],
                "building": str(data.get("building", ""))[:128],
                "room": str(data.get("room", ""))[:64],
                "timestamp": str(data.get("timestamp", ""))[:32],
                "type": str(data.get("type", "managed")),
                "relay_host": str(data.get("relay_host", ""))[:128],
                "relay_building": str(data.get("relay_building", ""))[:128],
                "relay_room": str(data.get("relay_room", ""))[:64],
                "vendor": vendor,
                "reporter_ip": request.remote_addr,
            }

            self.store.add_result(request_id, device)
            self.device_reported.emit(request_id, device)
            return jsonify({"status": "ok"})

        @self.app.route("/health")
        def health():
            return "OK"

    def run(self):
        log.info(f"Starting API server on port {Config.HTTP_PORT}")
        self.app.run(host="0.0.0.0", port=Config.HTTP_PORT, debug=False, threaded=True)
