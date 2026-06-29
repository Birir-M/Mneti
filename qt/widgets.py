from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QPushButton,
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QPainter, QBrush
from datetime import datetime, timezone
import urllib.request
import threading
import functools


# ── Timestamp helper ──────────────────────────────────────────────────────────

def utc_to_local_str(ts_str):
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


# ── OUI vendor lookup ─────────────────────────────────────────────────────────
#
# Two-tier lookup:
#   1. Built-in dict  — instant, covers ~50 common OUIs
#   2. macvendors.com — background HTTP fetch; result cached and table
#      refreshed via a Qt signal so the UI update is always on the main thread.

_OUI_BUILTIN: dict[str, str] = {
    '00:50:56': 'VMware',            '00:0C:29': 'VMware',
    '00:15:5D': 'Microsoft Hyper-V', '08:00:27': 'Oracle VirtualBox',
    '52:54:00': 'QEMU/KVM',
    'B8:27:EB': 'Raspberry Pi Foundation',
    'DC:A6:32': 'Raspberry Pi Foundation',
    'E4:5F:01': 'Raspberry Pi Foundation',
    '28:CD:C1': 'Raspberry Pi Foundation',
    '2C:CF:67': 'Raspberry Pi Foundation',
    'D8:3A:DD': 'Raspberry Pi Foundation',
    '00:1A:11': 'Google',            'A4:C3:F0': 'Google',
    'AC:BC:32': 'Apple',             '3C:22:FB': 'Apple',
    '00:17:F2': 'Apple',             'A8:BE:27': 'Apple',
    'F4:5C:89': 'Apple',             '00:1B:63': 'Apple',
    '00:1B:21': 'Intel',             '8C:EC:4B': 'Intel',
    '14:18:77': 'Dell',              '00:23:AE': 'Dell',
    'F8:DB:88': 'Dell',              'F4:8E:38': 'Dell',
    'B4:B6:86': 'HP',                '3C:D9:2B': 'HP',
    'FC:15:B4': 'HP',                '98:90:96': 'HP',
    '18:B4:30': 'Nest Labs',         '64:16:66': 'Nest Labs',
    '00:17:88': 'Philips Hue',
    'B0:BE:76': 'Samsung',           '8C:77:12': 'Samsung',
    'F0:27:65': 'Samsung',
    'CC:46:D6': 'Cisco',             '00:1A:A0': 'Cisco',
    '00:0B:BE': 'Cisco',             'F8:72:EA': 'Cisco',
    'B8:38:61': 'Cisco Meraki',
    'AC:22:0B': 'Ubiquiti',          '00:27:22': 'Ubiquiti',
    '04:18:D6': 'Ubiquiti',          '78:8A:20': 'Ubiquiti',
    '68:72:51': 'TP-Link',           '98:DA:C4': 'TP-Link',
    '10:FE:ED': 'TP-Link',           '30:DE:4B': 'TP-Link',
    '00:0C:E7': 'Netgear',           'A0:21:B7': 'Netgear',
    'C0:3F:0E': 'Netgear',
    '18:E8:29': 'D-Link',            '28:10:7B': 'D-Link',
    'C8:BE:19': 'ASUS',              '10:C3:7B': 'ASUS',
    'EC:F4:BB': 'Amazon',            'FC:65:DE': 'Amazon',
    '44:65:0D': 'Amazon',            '40:B4:CD': 'Amazon',
    '00:FC:8B': 'Amazon',            '74:C2:46': 'Amazon',
    '00:1A:2B': 'Fujitsu',
    '00:0F:00': 'Rockwell Automation',
    '00:25:B5': 'Cisco',
}

_oui_cache:   dict[str, str] = {}   # fetched results
_oui_pending: set[str]        = set()
_oui_lock     = threading.Lock()


def _normalise_oui(mac: str) -> str:
    clean = mac.upper().replace('-', ':').replace('.', ':')
    parts = clean.split(':')
    if len(parts) >= 3:
        return ':'.join(p.zfill(2) for p in parts[:3])
    hex_only = mac.upper().replace(':', '').replace('-', '').replace('.', '')
    if len(hex_only) >= 6:
        return ':'.join(hex_only[i:i+2] for i in range(0, 6, 2))
    return ''


def lookup_vendor(mac: str, on_fetched=None) -> str:
    """
    Return vendor string immediately from built-in table or cache.
    If unknown, starts a background fetch.  When the fetch completes,
    calls on_fetched(oui, vendor) — must be a Qt-signal-emit or other
    thread-safe callable.
    """
    if not mac:
        return ''
    oui = _normalise_oui(mac)
    if not oui:
        return ''

    if oui in _OUI_BUILTIN:
        return _OUI_BUILTIN[oui]

    with _oui_lock:
        if oui in _oui_cache:
            return _oui_cache[oui]
        if oui in _oui_pending:
            return ''
        _oui_pending.add(oui)

    def _fetch():
        vendor = ''
        try:
            hex6 = oui.replace(':', '')[:6].lower()
            url  = f'https://api.macvendors.com/{hex6}'
            req  = urllib.request.Request(url, headers={'User-Agent': 'Mneti/1.0'})
            with urllib.request.urlopen(req, timeout=4) as resp:
                vendor = resp.read().decode('utf-8', errors='replace').strip()
        except Exception:
            vendor = ''
        finally:
            with _oui_lock:
                _oui_cache[oui] = vendor
                _oui_pending.discard(oui)
        if vendor and on_fetched:
            try:
                on_fetched(oui, vendor)   # caller is responsible for thread safety
            except Exception:
                pass

    threading.Thread(target=_fetch, daemon=True).start()
    return ''


# ── Type metadata ─────────────────────────────────────────────────────────────

TYPE_META = {
    "managed":           ("Managed",             "#0366d6"),
    "managed_hotspot":   ("Relayed",             "#28a745"),
    "unmanaged":         ("Unmanaged",           "#dc3545"),
    "unmanaged_hotspot": ("Unmanaged (Hotspot)", "#f59f00"),
}

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
    filter_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._active = "all"
        self._counts: dict[str, int] = {k: 0 for k in FILTER_KEYS}

        outer = QHBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(0)

        lbl = QLabel("Filter:")
        lbl.setStyleSheet(
            "font-size: 11px; color: #6c757d; font-weight: bold; margin-right: 6px;")
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


# ── Coloured dot ──────────────────────────────────────────────────────────────

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
    Green pill  🔌  = primary port (device is plugged in here) or in-use by another room device.
    Grey  pill  ⚪  = listed additional port, currently unoccupied in this room.
    """
    IN_USE_STYLE = (
        "background:#e6ffed; color:#22863a; border:1px solid #28a745; "
        "border-radius:10px; padding:1px 6px; font-size:11px; font-weight:600;"
    )
    AVAIL_STYLE = (
        "background:#f6f8fa; color:#6a737d; border:1px solid #d1d5da; "
        "border-radius:10px; padding:1px 6px; font-size:11px; font-weight:600;"
    )

    def __init__(self, conn_type: str, primary_port: str,
                 additional_ports: list[str], room_in_use: set[str]):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(3)

        if conn_type:
            ct = QLabel(f"📶 {conn_type}")
            ct.setStyleSheet(
                "font-size:10px; color:#666; font-weight:bold; text-transform:uppercase;")
            layout.addWidget(ct)

        row = QHBoxLayout()
        row.setSpacing(4)
        row.setContentsMargins(0, 0, 0, 0)
        row.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        if primary_port:
            row.addWidget(self._tag(primary_port, in_use=True, tooltip="Connected to this device"))

        seen = {primary_port} if primary_port else set()
        for p in additional_ports:
            if p in seen:
                continue
            seen.add(p)
            in_use = p in room_in_use
            tip = "In use by another device in this room" if in_use else "Available"
            row.addWidget(self._tag(p, in_use=in_use, tooltip=tip))

        row.addStretch()
        layout.addLayout(row)

    def _tag(self, label: str, in_use: bool, tooltip: str) -> QLabel:
        icon = "🔌" if in_use else "⚪"
        tag = QLabel(f"{icon} {label}")
        tag.setStyleSheet(self.IN_USE_STYLE if in_use else self.AVAIL_STYLE)
        tag.setToolTip(tooltip)
        return tag


# ── Effective-type helpers ────────────────────────────────────────────────────

def _effective_type(d: dict) -> str:
    dtype = d.get("type", "unmanaged")
    relay = d.get("relay_host", "")
    if dtype == "managed":        return "managed"
    if dtype == "relayed":        return "managed_hotspot"
    if dtype == "unmanaged":      return "unmanaged_hotspot" if relay else "unmanaged"
    return "unmanaged"


def _build_room_in_use(devices: list[dict]) -> dict[tuple, set[str]]:
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


# ── DeviceTable ───────────────────────────────────────────────────────────────

class DeviceTable(QTableWidget):
    # Signal emitted (on the main thread, via queued connection) when a
    # background OUI fetch returns a result.  The slot re-renders the table.
    _vendor_arrived = pyqtSignal(str, str)   # (oui, vendor)

    COLUMNS = [
        ("Hostname",    180, False),
        ("MAC Address", 140, False),
        ("IP Address",  115, False),
        ("Type",        165, False),
        ("Location",    155, False),
        ("Ports",       200, True),
        ("Vendor",      130, True),
        ("Seen At",     140, False),
    ]

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

        # Store last render args so the vendor-arrived slot can re-render
        self._last_devices: list[dict] = []
        self._last_filter:  str = "all"
        self._last_search:  str = ""

        # Queued (cross-thread safe) connection: background thread emits
        # _vendor_arrived; Qt delivers it on the main thread.
        self._vendor_arrived.connect(
            self._on_vendor_arrived, Qt.ConnectionType.QueuedConnection)

    # ── vendor callback (called from background fetch thread) ─────────────────

    def _emit_vendor(self, oui: str, vendor: str):
        """Thread-safe: emits signal; Qt queues delivery to main thread."""
        _OUI_BUILTIN[oui] = vendor      # update cache so re-render picks it up
        self._vendor_arrived.emit(oui, vendor)

    def _on_vendor_arrived(self, oui: str, vendor: str):
        """Main-thread slot: re-render if we have data and the oui is relevant."""
        if not self._last_devices:
            return
        # Only re-render if at least one visible device uses this OUI
        for d in self._last_devices:
            if _normalise_oui(d.get("mac", "")) == oui:
                self.update_devices(
                    self._last_devices, self._last_filter, self._last_search)
                return

    # ── helpers ───────────────────────────────────────────────────────────────

    def _item(self, text: str) -> QTableWidgetItem:
        item = QTableWidgetItem(str(text))
        item.setTextAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        return item

    @staticmethod
    def _wrap(widget: QWidget) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 2, 0, 2)
        lay.addWidget(widget)
        return w

    # ── main update ───────────────────────────────────────────────────────────

    def update_devices(self, devices: list[dict],
                       filter_type: str = "all", search_query: str = ""):
        self._last_devices = devices
        self._last_filter  = filter_type
        self._last_search  = search_query

        self.setRowCount(0)
        sq = search_query.lower().strip()

        room_in_use = _build_room_in_use(devices)

        for d in devices:
            etype = _effective_type(d)
            if filter_type != "all" and filter_type != etype:
                continue

            # ── Ports ─────────────────────────────────────────────────────────
            primary_port     = str(d.get("port", "")).strip()
            additional_ports = d.get("additional_ports", [])
            if not isinstance(additional_ports, list):
                additional_ports = []
            additional_ports = [str(p).strip() for p in additional_ports if str(p).strip()]
            conn_type = str(d.get("connection_type", "")).strip()

            b = d.get("building", "") or ""
            r = d.get("room", "") or ""
            occupied = room_in_use.get((b, r), set())

            # ── Vendor — synchronous lookup; triggers background fetch ─────────
            vendor = d.get("vendor", "") or ""
            if not vendor:
                vendor = lookup_vendor(d.get("mac", ""), on_fetched=self._emit_vendor)

            # ── Search ────────────────────────────────────────────────────────
            if sq:
                relay = d.get("relay_host", "") or ""
                fields = [
                    d.get("hostname", ""), d.get("mac", ""), d.get("ip", ""),
                    d.get("username", ""), b, r, vendor, relay, conn_type,
                ] + ([primary_port] if primary_port else []) + additional_ports
                if not any(sq in str(f).lower() for f in fields):
                    continue

            row = self.rowCount()
            self.insertRow(row)

            # 0 – Hostname
            self.setItem(row, 0, self._item(d.get("hostname", "")))

            # 1 – MAC
            self.setItem(row, 1, self._item(d.get("mac", "")))

            # 2 – IP
            self.setItem(row, 2, self._item(d.get("ip", "")))

            # 3 – Type dot + label
            label, dot_color = TYPE_META.get(etype, ("Unknown", "#6c757d"))
            self.setCellWidget(row, 3, self._wrap(TypeCell(label, dot_color)))

            # 4 – Location
            location = f"{b} {r}".strip()
            relay = d.get("relay_host", "") or ""
            if relay:
                location += f"\nvia {relay}"
            self.setItem(row, 4, self._item(location))

            # 5 – Ports (rich widget)
            self.setCellWidget(row, 5, PortsCell(
                conn_type=conn_type,
                primary_port=primary_port,
                additional_ports=additional_ports,
                room_in_use=occupied,
            ))

            # 6 – Vendor
            self.setItem(row, 6, self._item(vendor))

            # 7 – Seen At
            self.setItem(row, 7, self._item(utc_to_local_str(d.get("timestamp", ""))))