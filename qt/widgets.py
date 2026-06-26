from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QPushButton, QScrollArea
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QBrush, QFont
from datetime import datetime, timezone
import urllib.request
import threading
import functools


# ── Timestamp helper ──────────────────────────────────────────────────────────

def utc_to_local_str(ts_str):
    """Convert ISO UTC timestamp string to the machine's local time."""
    if not ts_str:
        return ""
    try:
        ts = ts_str.strip()
        if ts.endswith('Z'):
            ts = ts[:-1] + '+00:00'
        dt_utc = datetime.fromisoformat(ts)
        if dt_utc.tzinfo is None:
            dt_utc = dt_utc.replace(tzinfo=timezone.utc)
        return dt_utc.astimezone().strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ts_str.replace('T', ' ').split('.')[0]


# ── OUI vendor lookup (mirrors the Flask dashboard) ───────────────────────────
#
# Two-tier: first check a built-in table (instant), then try the public
# IEEE OUI CSV via a background thread and cache the result.  The
# background fetch never blocks the UI; the table cell simply updates
# with a more descriptive name the next time the table is refreshed.

_OUI_BUILTIN: dict[str, str] = {
    '00:50:56': 'VMware',       '00:0C:29': 'VMware',
    '00:15:5D': 'Microsoft Hyper-V',
    '08:00:27': 'Oracle VirtualBox',
    '52:54:00': 'QEMU/KVM',
    'B8:27:EB': 'Raspberry Pi Foundation',
    'DC:A6:32': 'Raspberry Pi Foundation',
    'E4:5F:01': 'Raspberry Pi Foundation',
    '28:CD:C1': 'Raspberry Pi Foundation',
    '2C:CF:67': 'Raspberry Pi Foundation',
    'D8:3A:DD': 'Raspberry Pi Foundation',
    '00:1A:11': 'Google',       'A4:C3:F0': 'Google',
    'AC:BC:32': 'Apple',        '3C:22:FB': 'Apple',
    '00:17:F2': 'Apple',        'A8:BE:27': 'Apple',
    'F4:5C:89': 'Apple',        '00:1B:63': 'Apple',
    '00:1B:21': 'Intel',        '8C:EC:4B': 'Intel',
    'A4:C3:F0': 'Google',
    '14:18:77': 'Dell',         '00:23:AE': 'Dell',
    'F8:DB:88': 'Dell',         'F4:8E:38': 'Dell',
    'B4:B6:86': 'HP',           '3C:D9:2B': 'HP',
    'FC:15:B4': 'HP',           '98:90:96': 'HP',
    '18:B4:30': 'Nest Labs',    '64:16:66': 'Nest Labs',
    '00:17:88': 'Philips Hue',
    'B0:BE:76': 'Samsung',      '8C:77:12': 'Samsung',
    'F0:27:65': 'Samsung',
    '00:0F:00': 'Rockwell Automation',
    'CC:46:D6': 'Cisco',        '00:1A:A0': 'Cisco',
    '00:0B:BE': 'Cisco',        'F8:72:EA': 'Cisco',
    'B8:38:61': 'Cisco Meraki',
    'AC:22:0B': 'Ubiquiti',     '00:27:22': 'Ubiquiti',
    '04:18:D6': 'Ubiquiti',     '78:8A:20': 'Ubiquiti',
    '68:72:51': 'TP-Link',      '98:DA:C4': 'TP-Link',
    '10:FE:ED': 'TP-Link',      '30:DE:4B': 'TP-Link',
    '00:0C:E7': 'Netgear',      'A0:21:B7': 'Netgear',
    'C0:3F:0E': 'Netgear',
    '18:E8:29': 'D-Link',       '28:10:7B': 'D-Link',
    'C8:BE:19': 'ASUS',         '10:C3:7B': 'ASUS',
    '00:1A:2B': 'Fujitsu',
    '00:25:B5': 'Cisco',
    'EC:F4:BB': 'Amazon Echo/Fire',
    'FC:65:DE': 'Amazon',
    '44:65:0D': 'Amazon',
    '40:B4:CD': 'Amazon',
    '00:FC:8B': 'Amazon',
    '74:C2:46': 'Amazon',
}

# LRU cache for fetched OUI entries  (oui_prefix → vendor string)
_oui_cache: dict[str, str] = {}
_oui_fetch_lock = threading.Lock()
_oui_pending: set[str] = set()


def _normalise_oui(mac: str) -> str:
    """Return uppercase OUI prefix 'XX:XX:XX' from any MAC format."""
    clean = mac.upper().replace('-', ':').replace('.', ':')
    parts = clean.split(':')
    if len(parts) >= 3:
        return ':'.join(parts[:3])
    # dotted-quad style (e.g. AABB.CCDD.EEFF)
    hex_only = mac.upper().replace(':', '').replace('-', '').replace('.', '')
    if len(hex_only) >= 6:
        return ':'.join(hex_only[i:i+2] for i in range(0, 6, 2))
    return ''


def _fetch_oui_background(oui: str, callback=None):
    """
    Fetch vendor from macvendors.com in a background thread.
    Calls callback(oui, vendor_string) when done so the table can refresh.
    """
    with _oui_fetch_lock:
        if oui in _oui_pending or oui in _oui_cache:
            return
        _oui_pending.add(oui)

    def _do_fetch():
        vendor = ''
        try:
            mac_query = oui.replace(':', '').lower()
            url = f'https://api.macvendors.com/{mac_query[:6]}'
            req = urllib.request.Request(url, headers={'User-Agent': 'Mneti/1.0'})
            with urllib.request.urlopen(req, timeout=4) as resp:
                vendor = resp.read().decode('utf-8', errors='replace').strip()
        except Exception:
            vendor = ''
        finally:
            with _oui_fetch_lock:
                _oui_cache[oui] = vendor
                _oui_pending.discard(oui)
        if callback and vendor:
            callback(oui, vendor)

    threading.Thread(target=_do_fetch, daemon=True).start()


def lookup_vendor(mac: str, refresh_callback=None) -> str:
    """
    Return the best known vendor string for a MAC address.

    1. Check built-in table  (instant)
    2. Check in-process cache from previous fetches
    3. If not cached, kick off a background fetch; return '' for now
       and optionally call refresh_callback(oui, vendor) when it arrives.
    """
    if not mac:
        return ''
    oui = _normalise_oui(mac)
    if not oui:
        return ''

    # Built-in wins first
    if oui in _OUI_BUILTIN:
        return _OUI_BUILTIN[oui]

    # Cache hit
    with _oui_fetch_lock:
        if oui in _oui_cache:
            return _oui_cache[oui]

    # Background fetch — result arrives asynchronously
    _fetch_oui_background(oui, refresh_callback)
    return ''


# ── Type metadata ─────────────────────────────────────────────────────────────

# effective_type → (display label, dot colour)
TYPE_META = {
    "managed":           ("Managed",             "#0366d6"),  # blue
    "managed_hotspot":   ("Relayed",             "#28a745"),  # green
    "unmanaged":         ("Unmanaged",           "#dc3545"),  # red
    "unmanaged_hotspot": ("Unmanaged (Hotspot)", "#f59f00"),  # amber
}

# Maps effective_type to a CSS-like key used in filter chips
FILTER_KEYS = ["all", "managed", "managed_hotspot", "unmanaged_hotspot", "unmanaged"]

CHIP_COLORS = {
    "all":               ("#6c757d", "#fff"),
    "managed":           ("#0366d6", "#fff"),
    "managed_hotspot":   ("#28a745", "#fff"),
    "unmanaged_hotspot": ("#f59f00", "#fff"),
    "unmanaged":         ("#dc3545", "#fff"),
}

CHIP_LABELS = {
    "all":               "All",
    "managed":           "● Managed",
    "managed_hotspot":   "↗ Relayed",
    "unmanaged_hotspot": "○ Unmanaged Hotspot",
    "unmanaged":         "✕ Unmanaged",
}


# ── StatCard ──────────────────────────────────────────────────────────────────

class StatCard(QFrame):
    clicked = pyqtSignal(str)

    def __init__(self, title, count, color, filter_key):
        super().__init__()
        self.filter_key = filter_key
        self.setObjectName("Panel")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 10)
        layout.setSpacing(2)

        line = QFrame()
        line.setFixedHeight(3)
        line.setStyleSheet(f"background-color: {color};")
        layout.addWidget(line)

        self.num_label = QLabel(str(count))
        self.num_label.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(self.num_label)

        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet("font-size: 10px; color: #6c757d; font-weight: bold;")
        layout.addWidget(self.title_label)

    def set_count(self, count):
        self.num_label.setText(str(count))

    def mousePressEvent(self, event):
        self.clicked.emit(self.filter_key)
        super().mousePressEvent(event)


# ── Filter chips bar ──────────────────────────────────────────────────────────

class FilterChipsBar(QWidget):
    """
    A row of toggle-style chips mirroring the web dashboard's filter bar.
    Each chip shows a label + live count badge.  One chip is "active" at a time.

    Emits: filter_changed(str) with the active filter key.
    """
    filter_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._active = "all"
        self._counts: dict[str, int] = {k: 0 for k in FILTER_KEYS}

        outer = QHBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(0)

        lbl = QLabel("Filter:")
        lbl.setStyleSheet("font-size: 11px; color: #6c757d; font-weight: bold; margin-right: 6px;")
        outer.addWidget(lbl)

        self._chips: dict[str, QPushButton] = {}
        for key in FILTER_KEYS:
            btn = QPushButton(CHIP_LABELS[key] + "  0")
            btn.setCheckable(True)
            btn.setChecked(key == "all")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(functools.partial(self._on_chip_clicked, key))
            btn.setStyleSheet(self._chip_style(key, key == "all"))
            outer.addWidget(btn)
            outer.addSpacing(4)
            self._chips[key] = btn

        outer.addStretch()

    def _chip_style(self, key: str, active: bool) -> str:
        accent, fg = CHIP_COLORS[key]
        if active:
            return (
                f"QPushButton {{ background:{accent}; color:{fg}; border:1px solid {accent}; "
                f"border-radius:11px; padding:3px 12px; font-size:12px; font-weight:600; }}"
                f"QPushButton:hover {{ background:{accent}; }}"
            )
        else:
            return (
                f"QPushButton {{ background:#fff; color:{accent}; border:1px solid {accent}; "
                f"border-radius:11px; padding:3px 12px; font-size:12px; font-weight:600; }}"
                f"QPushButton:hover {{ background:#f0f0f0; }}"
            )

    def _on_chip_clicked(self, key: str):
        self._active = key
        for k, btn in self._chips.items():
            btn.setChecked(k == key)
            btn.setStyleSheet(self._chip_style(k, k == key))
        self.filter_changed.emit(key)

    def set_counts(self, counts: dict[str, int]):
        self._counts.update(counts)
        for key, btn in self._chips.items():
            n = self._counts.get(key, 0)
            btn.setText(f"{CHIP_LABELS[key]}  {n}")

    def active_filter(self) -> str:
        return self._active

    def reset(self):
        self._on_chip_clicked("all")
        self.set_counts({k: 0 for k in FILTER_KEYS})


# ── Coloured dot widget ───────────────────────────────────────────────────────

class _DotWidget(QWidget):
    def __init__(self, color: str):
        super().__init__()
        self._color = QColor(color)
        self.setFixedSize(10, 10)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(self._color))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(0, 0, 10, 10)


class TypeCell(QWidget):
    """Coloured dot + plain label, no background colour on the cell."""

    def __init__(self, label: str, dot_color: str):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 0, 6, 0)
        layout.setSpacing(6)
        layout.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(_DotWidget(dot_color))
        lbl = QLabel(label)
        lbl.setStyleSheet("font-size: 12px;")
        layout.addWidget(lbl)
        layout.addStretch()


# ── Port tags widget ──────────────────────────────────────────────────────────

class PortsCell(QWidget):
    """
    Renders connection type + ports with in-use / available distinction,
    matching the web dashboard's port-tag style.

      • 🔌  port label  — green pill  = this device's primary port (in use)
      • 🔌  port label  — green pill  = another device also uses this port
      • ⚪  port label  — grey pill   = port is listed but not currently in use
                                        by any device in the same room

    `primary_port`       — the port this device is physically connected to
    `additional_ports`   — other ports in the same room (from config)
    `room_in_use`        — set of ports known to be in use in this room
                           (derived from all devices sharing building+room)
    """

    IN_USE_BG    = "#e6ffed"
    IN_USE_BORDER= "#28a745"
    IN_USE_FG    = "#22863a"
    AVAIL_BG     = "#f6f8fa"
    AVAIL_BORDER = "#d1d5da"
    AVAIL_FG     = "#6a737d"

    def __init__(
        self,
        conn_type: str,
        primary_port: str,
        additional_ports: list[str],
        room_in_use: set[str],
    ):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(3)

        if conn_type:
            ct_lbl = QLabel(f"📶 {conn_type}")
            ct_lbl.setStyleSheet("font-size: 10px; color: #666; font-weight: bold; text-transform: uppercase;")
            layout.addWidget(ct_lbl)

        tags_row = QHBoxLayout()
        tags_row.setSpacing(4)
        tags_row.setContentsMargins(0, 0, 0, 0)
        tags_row.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        if primary_port:
            tags_row.addWidget(self._tag(primary_port, in_use=True, is_primary=True))

        for p in additional_ports:
            if p == primary_port:
                continue
            in_use = p in room_in_use
            tags_row.addWidget(self._tag(p, in_use=in_use, is_primary=False))

        tags_row.addStretch()
        layout.addLayout(tags_row)

    def _tag(self, label: str, in_use: bool, is_primary: bool) -> QLabel:
        icon = "🔌" if in_use else "⚪"
        tag = QLabel(f"{icon} {label}")
        if in_use:
            style = (
                f"background:{self.IN_USE_BG}; color:{self.IN_USE_FG}; "
                f"border:1px solid {self.IN_USE_BORDER}; border-radius:10px; "
                f"padding:1px 6px; font-size:11px; font-weight:600;"
            )
        else:
            style = (
                f"background:{self.AVAIL_BG}; color:{self.AVAIL_FG}; "
                f"border:1px solid {self.AVAIL_BORDER}; border-radius:10px; "
                f"padding:1px 6px; font-size:11px; font-weight:600;"
            )
        tag.setStyleSheet(style)
        if is_primary:
            tag.setToolTip("This device is connected to this port")
        else:
            tag.setToolTip("In use by another device in this room" if in_use else "Available in this room")
        return tag


# ── DeviceTable ───────────────────────────────────────────────────────────────

def _effective_type(d: dict) -> str:
    """Map raw device dict to one of the four effective-type filter keys."""
    dtype      = d.get("type", "unmanaged")
    relay_host = d.get("relay_host", "")
    if dtype == "managed":
        return "managed"
    if dtype == "relayed":
        return "managed_hotspot"
    if dtype == "unmanaged":
        return "unmanaged_hotspot" if relay_host else "unmanaged"
    return "unmanaged"


def _build_room_in_use(devices: list[dict]) -> dict[tuple, set[str]]:
    """
    For each (building, room) pair, return the set of ports that are the
    `port` field of at least one device (i.e. currently occupied ports).
    """
    room_map: dict[tuple, set[str]] = {}
    for d in devices:
        b = d.get("building", "") or ""
        r = d.get("room", "") or ""
        p = str(d.get("port", "")).strip()
        if b or r:
            key = (b, r)
            room_map.setdefault(key, set())
            if p:
                room_map[key].add(p)
    return room_map


class DeviceTable(QTableWidget):
    #                    header          min-px  stretch?
    COLUMNS = [
        ("Hostname",      180,  False),
        ("MAC Address",   140,  False),
        ("IP Address",    115,  False),
        ("Type",          165,  False),
        ("Location",      155,  False),
        ("Ports",         200,  True),   # absorbs spare horizontal space
        ("Vendor",        130,  True),   # absorbs spare horizontal space
        ("Seen At",       140,  False),
    ]

    # Signal emitted when a background OUI fetch completes so the table
    # can refresh a single cell without a full redraw.
    # We store a list of all devices we last rendered to support this.
    _last_devices: list[dict] = []
    _last_filter:  str = "all"
    _last_search:  str = ""

    def __init__(self):
        super().__init__()
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])

        hdr = self.horizontalHeader()
        for i, (_, min_w, stretch) in enumerate(self.COLUMNS):
            if stretch:
                hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
            else:
                hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
                self.setColumnWidth(i, min_w)

        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents)
        self.setAlternatingRowColors(False)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setWordWrap(True)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _item(self, text: str) -> QTableWidgetItem:
        item = QTableWidgetItem(str(text))
        item.setTextAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        return item

    @staticmethod
    def _wrap(widget: QWidget) -> QWidget:
        """Centre a widget inside a plain wrapper so setCellWidget works cleanly."""
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 2, 0, 2)
        lay.addWidget(widget)
        return w

    # ── main update ───────────────────────────────────────────────────────────

    def update_devices(self, devices: list[dict], filter_type: str = "all", search_query: str = ""):
        self._last_devices = devices
        self._last_filter  = filter_type
        self._last_search  = search_query

        self.setRowCount(0)
        sq = search_query.lower().strip()

        # Build room→occupied ports map from ALL devices (before filtering)
        room_in_use = _build_room_in_use(devices)

        def _vendor_callback(oui: str, vendor: str):
            # Called from background thread — schedule a GUI-safe refresh.
            # Simple approach: update _OUI_BUILTIN so the next refresh picks it up.
            _OUI_BUILTIN[oui] = vendor

        for d in devices:
            etype = _effective_type(d)

            if filter_type != "all" and filter_type != etype:
                continue

            # ── Ports ────────────────────────────────────────────────────────
            primary_port     = str(d.get("port", "")).strip()
            additional_ports = d.get("additional_ports", [])
            if not isinstance(additional_ports, list):
                additional_ports = []
            additional_ports = [str(p).strip() for p in additional_ports if str(p).strip()]

            conn_type = str(d.get("connection_type", "")).strip()

            b = d.get("building", "") or ""
            r = d.get("room", "") or ""
            room_key = (b, r)
            occupied = room_in_use.get(room_key, set())

            # ── Vendor (with background OUI fetch) ───────────────────────────
            vendor = d.get("vendor", "") or ""
            if not vendor:
                vendor = lookup_vendor(d.get("mac", ""), refresh_callback=_vendor_callback)

            # ── Search filter ─────────────────────────────────────────────────
            if sq:
                relay_host = d.get("relay_host", "") or ""
                searchable = [
                    d.get("hostname", ""), d.get("mac", ""), d.get("ip", ""),
                    d.get("username", ""), b, r,
                    vendor, relay_host, conn_type,
                ] + ([primary_port] if primary_port else []) + additional_ports
                if not any(sq in str(f).lower() for f in searchable):
                    continue

            row = self.rowCount()
            self.insertRow(row)

            # 0 – Hostname
            self.setItem(row, 0, self._item(d.get("hostname", "")))

            # 1 – MAC
            self.setItem(row, 1, self._item(d.get("mac", "")))

            # 2 – IP
            self.setItem(row, 2, self._item(d.get("ip", "")))

            # 3 – Type: dot + plain label
            label, dot_color = TYPE_META.get(etype, ("Unknown", "#6c757d"))
            self.setCellWidget(row, 3, self._wrap(TypeCell(label, dot_color)))

            # 4 – Location
            location = f"{b} {r}".strip()
            relay_host = d.get("relay_host", "") or ""
            if relay_host:
                location += f"\nvia {relay_host}"
            self.setItem(row, 4, self._item(location))

            # 5 – Ports (rich port-tag widget)
            ports_widget = PortsCell(
                conn_type=conn_type,
                primary_port=primary_port,
                additional_ports=additional_ports,
                room_in_use=occupied,
            )
            self.setCellWidget(row, 5, ports_widget)

            # 6 – Vendor
            self.setItem(row, 6, self._item(vendor))

            # 7 – Seen At (local time)
            self.setItem(row, 7, self._item(utc_to_local_str(d.get("timestamp", ""))))