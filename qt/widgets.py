from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal
from qt.styles import BADGE_STYLES

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

        # Top accent border
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

class BadgeLabel(QLabel):
    def __init__(self, text, badge_type):
        super().__init__(text.upper())
        style = BADGE_STYLES.get(badge_type, BADGE_STYLES["unmanaged"])
        self.setStyleSheet(style)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setContentsMargins(4, 2, 4, 2)

class DeviceTable(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(8)
        self.setHorizontalHeaderLabels([
            "Hostname", "MAC Address", "IP Address", 
            "Type", "Location", "Ports", "Vendor", "Timestamp"
        ])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

    def update_devices(self, devices, filter_type="all", search_query=""):
        self.setRowCount(0)
        search_query = search_query.lower().strip()
        for d in devices:
            dtype = d.get("type", "unmanaged")
            relay_host = d.get("relay_host", "")
            port = d.get("port", "")
            additional_ports = d.get("additional_ports", [])
            
            # Determine effective filter type
            effective_type = "managed" if dtype == "managed" else "unmanaged"
            if dtype == "relayed": effective_type = "managed_hotspot"
            elif dtype == "unmanaged" and relay_host: effective_type = "unmanaged_hotspot"

            if filter_type != "all" and filter_type != effective_type:
                continue

            # Search Filter
            if search_query:
                match_fields = [
                    d.get("hostname", ""), d.get("mac", ""), d.get("ip", ""),
                    d.get("username", ""), d.get("building", ""), d.get("room", ""),
                    d.get("vendor", ""), relay_host, port
                ]
                # Include additional ports in search
                plus_additional = match_fields + (additional_ports if isinstance(additional_ports, list) else [])
                if not any(search_query in str(f).lower() for f in plus_additional):
                    continue

            row = self.rowCount()
            self.insertRow(row)

            self.setItem(row, 0, QTableWidgetItem(d.get("hostname", "")))
            self.setItem(row, 1, QTableWidgetItem(d.get("mac", "")))
            self.setItem(row, 2, QTableWidgetItem(d.get("ip", "")))
            
            # Badge for Type
            badge_type = dtype
            if dtype == "unmanaged" and relay_host: badge_type = "unmanaged_hotspot"
            badge = BadgeLabel(dtype if not relay_host else f"{dtype} hotspot", badge_type)
            self.setCellWidget(row, 3, self._center_widget(badge))

            location = f"{d.get('building', '')} {d.get('room', '')}".strip()
            if relay_host:
                location += f"\n(via {relay_host})"
            self.setItem(row, 4, QTableWidgetItem(location))

            # Ports column
            conn_type = d.get("connection_type", "")
            prefix = f"📶 {conn_type}: " if conn_type else ""
            
            ports_text = ""
            if port:
                ports_text = f"{prefix}🔌 {port}"
                if additional_ports:
                    ports_text += f" (+{len(additional_ports)})"
            elif additional_ports:
                 ports_text = f"{prefix}⚪ {len(additional_ports)} additional"
            elif conn_type:
                 ports_text = f"📶 {conn_type}"
            
            ports_item = QTableWidgetItem(ports_text)
            if additional_ports:
                ports_item.setToolTip("\n".join(additional_ports))
            self.setItem(row, 5, ports_item)
            
            self.setItem(row, 6, QTableWidgetItem(d.get("vendor", "")))
            self.setItem(row, 7, QTableWidgetItem(d.get("timestamp", "")))

    def _center_widget(self, w):
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.addWidget(w)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(0, 5, 0, 5)
        return container
