"""
Mneti - UDP Discovery Broadcaster
Sends signed broadcast packets to trigger client-side discovery.
"""

import json
import hmac
import hashlib
import socket
import time
import logging
import threading
from datetime import datetime, timezone

log = logging.getLogger("mneti.broadcaster")



def _sign_payload(payload: bytes, secret: str) -> str:
    """HMAC-SHA256 signature over the raw JSON payload."""
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


class DiscoveryBroadcaster:
    def __init__(self, config, store):
        self.config = config
        self.store = store

    def _build_packet(self, request_id: str, mode: str, target: str = "") -> bytes:
        # Key order MUST match the PowerShell reconstruction template exactly
        packet = {
            "request_id": request_id,
            "mode": mode,
            "target": target,
            "token": self.config.SHARED_TOKEN,
            "callback_url": self.config.SERVER_CALLBACK_URL,
            "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        }
        # Sign the payload JSON directly - key order is preserved in Python 3.7+
        payload_json = json.dumps(packet, separators=(",", ":")).encode()
        sig = _sign_payload(payload_json, self.config.SHARED_TOKEN)

        envelope = {
            "payload": packet,
            "sig": sig,
        }
        return json.dumps(envelope, separators=(",", ":")).encode()

    def _broadcast(self, data: bytes):
        """Send UDP broadcast. Safe: socket is closed immediately."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(2)
            sock.sendto(data, (self.config.UDP_BROADCAST_ADDR, self.config.UDP_PORT))
            sock.close()
            log.info("Broadcast sent (%d bytes) → %s:%d",
                     len(data), self.config.UDP_BROADCAST_ADDR, self.config.UDP_PORT)
        except OSError as e:
            log.error("Broadcast failed: %s", e)

    def send_targeted(self, request_id: str, target: str, mode: str):
        packet = self._build_packet(request_id, f"targeted_{mode}", target)
        t = threading.Thread(target=self._broadcast, args=(packet,), daemon=True)
        t.start()

    def send_full_discovery(self, request_id: str):
        packet = self._build_packet(request_id, "full")
        t = threading.Thread(target=self._broadcast, args=(packet,), daemon=True)
        t.start()