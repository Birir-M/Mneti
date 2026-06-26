from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QBrush
from datetime import datetime, timezone


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


# ── Type metadata ─────────────────────────────────────────────────────────────

# effective_type -> (display label, dot colour)
TYPE_META = {
    "managed":           ("Managed",            "#0366d6"),  # blue
    "managed_hotspot":   ("Relayed",            "#28a745"),  # green
    "unmanaged":         ("Unmanaged",          "#dc3545"),  # red
    "unmanaged_hotspot": ("Unmanaged (Hotspot)","#f59f00"),  # amber
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


# ── DeviceTable ───────────────────────────────────────────────────────────────

class DeviceTable(QTableWidget):
    #                    header         min-px  stretch?
    COLUMNS = [
        ("Hostname",     180,  False),
        ("MAC Address",  140,  False),
        ("IP Address",   115,  False),
        ("Type",         165,  False),
        ("Location",     160,  True),   # absorbs spare horizontal space
        ("Ports",        190,  True),   # absorbs spare horizontal space
        ("Vendor",       110,  False),
        ("Seen At",      140,  False),
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

    def update_devices(self, devices, filter_type="all", search_query=""):
        self.setRowCount(0)
        sq = search_query.lower().strip()

        for d in devices:
            dtype      = d.get("type", "unmanaged")
            relay_host = d.get("relay_host", "")

            # Effective filter bucket
            if dtype == "relayed":
                etype = "managed_hotspot"
            elif dtype == "unmanaged" and relay_host:
                etype = "unmanaged_hotspot"
            elif dtype == "managed":
                etype = "managed"
            else:
                etype = "unmanaged"

            if filter_type != "all" and filter_type != etype:
                continue

            # ── Ports: build a clean, deduplicated ordered list ───────────
            primary_port     = str(d.get("port", "")).strip()
            additional_ports = d.get("additional_ports", [])
            if not isinstance(additional_ports, list):
                additional_ports = []
            additional_ports = [str(p).strip() for p in additional_ports if str(p).strip()]

            all_ports = []
            for p in ([primary_port] if primary_port else []) + additional_ports:
                if p and p not in all_ports:
                    all_ports.append(p)

            conn_type = str(d.get("connection_type", "")).strip()

            # ── Search filter ─────────────────────────────────────────────
            if sq:
                searchable = [
                    d.get("hostname", ""), d.get("mac", ""), d.get("ip", ""),
                    d.get("username", ""), d.get("building", ""), d.get("room", ""),
                    d.get("vendor", ""), relay_host, conn_type,
                ] + all_ports
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

            # 3 – Type: dot + plain label, no cell background
            label, dot_color = TYPE_META.get(etype, ("Unknown", "#6c757d"))
            self.setCellWidget(row, 3, self._wrap(TypeCell(label, dot_color)))

            # 4 – Location
            location = f"{d.get('building', '')} {d.get('room', '')}".strip()
            if relay_host:
                location += f"\nvia {relay_host}"
            self.setItem(row, 4, self._item(location))

            # 5 – Ports: connection type on first line, every port beneath it
            parts = []
            if conn_type:
                parts.append(conn_type)   # e.g. "Wall Port"
            for p in all_ports:
                parts.append(p)           # e.g. "WP-04A", "WP-04B"
            self.setItem(row, 5, self._item("\n".join(parts)))

            # 6 – Vendor
            self.setItem(row, 6, self._item(d.get("vendor", "")))

            # 7 – Seen At (local time)
            self.setItem(row, 7, self._item(utc_to_local_str(d.get("timestamp", ""))))