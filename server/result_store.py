"""
Mneti - Thread-safe in-memory result store with TTL expiry.
Tracks last_activity per session so the dashboard can poll until
results stop arriving rather than using a fixed-duration timeout.
"""
import threading
import time
import logging
from datetime import datetime, timezone

log = logging.getLogger("mneti.store")

_TTL = 3600  # 1 hour


class ResultStore:
    def __init__(self, ttl: int = _TTL):
        self._ttl  = ttl
        self._lock = threading.Lock()
        self._sessions: dict = {}
        self._history:  list = []
        threading.Thread(target=self._reap, daemon=True).start()

    # ── Session lifecycle ─────────────────────────────────────────────────────

    def init_session(self, request_id: str, discovery_type: str):
        now = time.monotonic()
        with self._lock:
            self._sessions[request_id] = {
                "request_id":    request_id,
                "type":          discovery_type,
                "started_at":    datetime.now(timezone.utc).isoformat(),
                "devices":       [],
                "expires_at":    now + self._ttl,
                # last_activity lets the dashboard detect when results have
                # stopped arriving without needing a fixed poll window.
                "last_activity": now,
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

            mac = device.get("mac", "").strip().lower()

            # Deduplicate only on real non-empty MACs.
            # Blank-MAC unmanaged devices (phones, IoT) must all be stored.
            if mac:
                existing_macs = {
                    d.get("mac", "").strip().lower()
                    for d in session["devices"]
                    if d.get("mac", "").strip()
                }
                if mac in existing_macs:
                    log.debug("Duplicate MAC %s for %s — skipped", mac, request_id)
                    return

            session["devices"].append(device)
            session["last_activity"] = time.monotonic()

    def get(self, request_id: str) -> dict | None:
        with self._lock:
            session = self._sessions.get(request_id)
            if not session:
                return None
            # Expose seconds-since-last-activity so the dashboard JS can
            # decide to stop polling when this number stays high (e.g. > 60s).
            result = dict(session)
            result["seconds_since_activity"] = time.monotonic() - session["last_activity"]
            return result

    # ── History ───────────────────────────────────────────────────────────────

    def get_history(self) -> list:
        with self._lock:
            return list(self._history[-50:])

    def _archive_session(self, session: dict):
        summary = {
            "request_id":  session["request_id"],
            "type":        session["type"],
            "started_at":  session["started_at"],
            "device_count": len(session["devices"]),
        }
        self._history.append(summary)
        if len(self._history) > 200:
            self._history = self._history[-200:]

    # ── TTL reaper ────────────────────────────────────────────────────────────

    def _reap(self):
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