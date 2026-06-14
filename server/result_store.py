"""
Mneti - Thread-safe in-memory result store with TTL expiry.
Tracks last_activity per session so the dashboard can poll until
results stop arriving rather than using a fixed-duration timeout.

Session history (the list shown under "Session History" in the
dashboard) is persisted to a JSON file on disk so it survives server
restarts. Full device data (MAC, IP, location, relay info, vendor, etc.)
is stored per session and written on every new device arrival.

── Type-priority upgrade ─────────────────────────────────────────────────
Devices may be reported more than once for the same session, in any
order:

  - The server's own ARP scan (arp_scanner.py) may report a device as
    "unmanaged" before its agent has had a chance to respond.
  - The agent itself may report the same MAC as "managed" or "relayed"
    shortly after (or before) the ARP scan runs.

Rather than "first write wins" (which could permanently strand a device
as "unmanaged" if the ARP scan happens to run first), add_result()
upgrades an existing entry in place whenever a higher-priority report
for the same MAC arrives — regardless of arrival order. This guarantees
each device appears exactly once, with its best-known classification.
"""
import os
import json
import threading
import time
import logging
from datetime import datetime, timezone

log = logging.getLogger("mneti.store")

_TTL = 3600  # 1 hour

# Default location: <server>/data/history.json
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_HISTORY_FILE = os.path.join(_DATA_DIR, "history.json")

# Keep at most this many history entries (in memory and on disk)
_MAX_HISTORY = 200

# Higher number = higher priority. A later report only replaces an
# existing one if its priority is strictly greater (equal priority is
# treated as a duplicate and dropped, preserving the original record).
_TYPE_PRIORITY = {
    "unmanaged": 0,
    "relayed":   1,
    "managed":   2,
}


def _type_priority(device_type: str) -> int:
    return _TYPE_PRIORITY.get(device_type, 0)


class ResultStore:
    def __init__(self, ttl: int = _TTL, history_file: str = _HISTORY_FILE):
        self._ttl = ttl
        self._lock = threading.Lock()
        self._sessions: dict = {}
        self._history_file = history_file
        self._history: list = self._load_history()
        threading.Thread(target=self._reap, daemon=True).start()

    # ── Persistence ────────────────────────────────────────────────────────────

    def _load_history(self) -> list:
        """Load previously saved session history from disk, if present."""
        try:
            if os.path.exists(self._history_file):
                with open(self._history_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    log.info(
                        "Loaded %d session history record(s) from %s",
                        len(data), self._history_file
                    )
                    return data[-_MAX_HISTORY:]
                log.warning(
                    "History file %s did not contain a list — ignoring",
                    self._history_file
                )
        except Exception as e:
            log.warning("Failed to load history file %s: %s", self._history_file, e)
        return []

    def _save_history_locked(self):
        """
        Write current history (with full device data) to disk.
        Caller must hold self._lock.
        """
        try:
            os.makedirs(os.path.dirname(self._history_file), exist_ok=True)
            tmp_path = self._history_file + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self._history[-_MAX_HISTORY:], f, indent=2)
            os.replace(tmp_path, self._history_file)
        except Exception as e:
            log.warning("Failed to save history file %s: %s", self._history_file, e)

    def _upsert_history_locked(self, session: dict):
        """
        Insert or update the history record for this session with full device
        data. Called on every new device arrival/upgrade and on TTL reap.
        Caller must hold self._lock.
        """
        record = {
            "request_id":   session["request_id"],
            "type":         session["type"],
            "started_at":   session["started_at"],
            "device_count": len(session["devices"]),
            # Full device list — same schema as the in-memory session
            "devices":      list(session["devices"]),
        }

        # Replace existing record for this request_id, or append
        for i, h in enumerate(self._history):
            if h.get("request_id") == session["request_id"]:
                self._history[i] = record
                self._save_history_locked()
                return

        self._history.append(record)
        if len(self._history) > _MAX_HISTORY:
            self._history = self._history[-_MAX_HISTORY:]
        self._save_history_locked()

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
                "last_activity": now,
            }
            # Write stub record immediately so the session appears in history
            # even before any devices respond.
            self._upsert_history_locked(self._sessions[request_id])

    def session_exists(self, request_id: str) -> bool:
        with self._lock:
            return request_id in self._sessions

    def add_result(self, request_id: str, device: dict):
        """
        Add a device report to a session, or upgrade an existing entry for
        the same MAC if the new report has a higher-priority type
        (unmanaged < relayed < managed).

        - No existing entry for this MAC → append as a new device.
        - Existing entry with LOWER priority than the new report →
          replace it in place (upgrade), preserving its position.
        - Existing entry with EQUAL or HIGHER priority → drop the new
          report as a duplicate.

        Devices with no MAC (blank-MAC unmanaged devices, e.g. phones/IoT
        discovered without ARP) are never deduplicated/upgraded — they are
        always appended as-is, same as before.
        """
        with self._lock:
            session = self._sessions.get(request_id)
            if not session:
                log.warning("add_result: unknown request_id %s", request_id)
                return

            mac = device.get("mac", "").strip().lower()

            if mac:
                for i, existing in enumerate(session["devices"]):
                    existing_mac = existing.get("mac", "").strip().lower()
                    if existing_mac != mac:
                        continue

                    existing_prio = _type_priority(existing.get("type", ""))
                    new_prio      = _type_priority(device.get("type", ""))

                    if new_prio > existing_prio:
                        session["devices"][i] = device
                        session["last_activity"] = time.monotonic()
                        self._upsert_history_locked(session)
                        log.info(
                            "Upgraded device %s: %s -> %s (id=%s)",
                            mac, existing.get("type"), device.get("type"), request_id
                        )
                    else:
                        log.debug(
                            "Duplicate/lower-priority MAC %s (%s, existing=%s) for %s — skipped",
                            mac, device.get("type"), existing.get("type"), request_id
                        )
                    return

            # No existing entry for this MAC (or blank MAC) — append new.
            session["devices"].append(device)
            session["last_activity"] = time.monotonic()

            # Persist the updated device list to history on every new arrival
            self._upsert_history_locked(session)

    def get(self, request_id: str) -> dict | None:
        with self._lock:
            session = self._sessions.get(request_id)
            if not session:
                return None
            result = dict(session)
            result["seconds_since_activity"] = time.monotonic() - session["last_activity"]
            return result

    # ── History ───────────────────────────────────────────────────────────────

    def get_history(self) -> list:
        """Return list of session summaries (no device data) for the history index."""
        with self._lock:
            summaries = []
            for h in self._history[-_MAX_HISTORY:]:
                summaries.append({
                    "request_id":   h.get("request_id"),
                    "type":         h.get("type"),
                    "started_at":   h.get("started_at"),
                    "device_count": h.get("device_count", 0),
                })
            return summaries

    def get_history_session(self, request_id: str) -> dict | None:
        """
        Return the full history record (including all device data) for a
        single session — first checking the live in-memory sessions, then
        falling back to the persisted history list.
        """
        with self._lock:
            # Prefer live session data if it's still in memory
            if request_id in self._sessions:
                session = self._sessions[request_id]
                result = dict(session)
                result["seconds_since_activity"] = (
                    time.monotonic() - session["last_activity"]
                )
                return result

            # Fall back to persisted history
            for h in reversed(self._history):
                if h.get("request_id") == request_id:
                    return dict(h)

        return None

    def _archive_session(self, session: dict):
        """Called by reaper when a session TTL expires — final history write."""
        self._upsert_history_locked(session)

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