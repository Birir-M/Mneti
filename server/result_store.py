"""
Mneti - Thread-safe in-memory result store with TTL expiry.
No persistent database required — keeps memory footprint minimal.
"""

import threading
import time
import logging
from datetime import datetime, timezone

log = logging.getLogger("mneti.store")


_TTL = 3600  # 1 hour default


class ResultStore:
    def __init__(self, ttl: int = _TTL):
        self._ttl = ttl
        self._lock = threading.Lock()
        self._sessions: dict = {}   # request_id → session dict
        self._history: list = []    # Summarised past sessions

        # Background cleanup thread
        t = threading.Thread(target=self._reap, daemon=True)
        t.start()

    # ── Session lifecycle ─────────────────────────────────────────────────────

    def init_session(self, request_id: str, discovery_type: str):
        with self._lock:
            self._sessions[request_id] = {
                "request_id": request_id,
                "type": discovery_type,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "devices": [],
                "expires_at": time.monotonic() + self._ttl,
            }

    def session_exists(self, request_id: str) -> bool:
        with self._lock:
            return request_id in self._sessions

    def add_result(self, request_id: str, device: dict):
        with self._lock:
            session = self._sessions.get(request_id)
            if not session:
                log.warning("add_result: unknown request_id %s", request_id)
                return
            # Deduplicate by MAC
            mac = device.get("mac", "").lower()
            existing_macs = {d.get("mac", "").lower() for d in session["devices"]}
            if mac and mac in existing_macs:
                log.debug("Duplicate MAC %s for %s — skipped", mac, request_id)
                return
            session["devices"].append(device)

    def get(self, request_id: str) -> dict | None:
        with self._lock:
            session = self._sessions.get(request_id)
            if not session:
                return None
            return dict(session)  # shallow copy to avoid external mutation

    # ── History ───────────────────────────────────────────────────────────────

    def get_history(self) -> list:
        with self._lock:
            return list(self._history[-50:])  # last 50 sessions

    def _archive_session(self, session: dict):
        summary = {
            "request_id": session["request_id"],
            "type": session["type"],
            "started_at": session["started_at"],
            "device_count": len(session["devices"]),
        }
        self._history.append(summary)
        if len(self._history) > 200:
            self._history = self._history[-200:]

    # ── TTL reaper ────────────────────────────────────────────────────────────

    def _reap(self):
        """Background thread: evict expired sessions every 60 s."""
        while True:
            time.sleep(60)
            now = time.monotonic()
            with self._lock:
                expired = [rid for rid, s in self._sessions.items()
                           if s["expires_at"] < now]
                for rid in expired:
                    self._archive_session(self._sessions.pop(rid))
            if expired:
                log.info("Reaped %d expired sessions", len(expired))