import uuid
import time
import threading
import csv
import os
from datetime import datetime, timezone
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QStackedWidget, QListWidget, QListWidgetItem, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit, QFormLayout, QFileDialog, 
    QScrollArea, QFrame, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSlot, QTimer, pyqtSignal
from qt.logic import Config, ResultStore, DiscoveryBroadcaster, get_lan_ip
from qt.widgets import StatCard, DeviceTable
from qt.api_server import ApiServerThread
from qt.styles import LIGHT_STYLE, DARK_STYLE
from qt.logic import scan_subnet, lookup_vendor

class MainWindow(QMainWindow):
    arp_scan_result_received = pyqtSignal(str, dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mneti — Administrative Discovery Dashboard")
        self.resize(1200, 750)   # slightly wider default to give columns room
        
        self.countdown_val = 0
        self.countdown_timer = QTimer()
        self.countdown_timer.timeout.connect(self._update_countdown)
        
        self.arp_scan_result_received.connect(self.on_device_reported)

        self.store = ResultStore()
        self.broadcaster = DiscoveryBroadcaster(self.store)
        self.active_session_id = None
        self.current_filter = "all"
        self.is_dark_mode = False

        self.api_thread = ApiServerThread(self.store)
        self.api_thread.device_reported.connect(self.on_device_reported)
        self.api_thread.start()

        self._setup_ui()
        self.set_theme(False)
        self.show_view("discover")

    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Sidebar ───────────────────────────────────────────────────────
        self.sidebar = QWidget()
        self.sidebar.setObjectName("Sidebar")
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 20, 0, 20)
        
        logo_label = QLabel("MNETI")
        logo_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 20px; padding: 10px 20px;")
        sidebar_layout.addWidget(logo_label)

        self.nav_btns = {}
        for key, text in [("discover", "◈ Discover Devices"), ("ranges", "⊞ Broadcast Ranges"), ("history", "◷ Session History")]:
            btn = QPushButton(text)
            btn.clicked.connect(lambda checked, k=key: self.show_view(k))
            sidebar_layout.addWidget(btn)
            self.nav_btns[key] = btn

        sidebar_layout.addStretch()
        
        self.theme_btn = QPushButton("🌙 Dark Mode")
        self.theme_btn.clicked.connect(self.toggle_theme)
        sidebar_layout.addWidget(self.theme_btn)
        
        info_label = QLabel(f"Server: Online\nIP: {get_lan_ip()}")
        info_label.setStyleSheet("font-size: 11px; color: #777; padding: 20px;")
        sidebar_layout.addWidget(info_label)

        main_layout.addWidget(self.sidebar)

        # ── Content stack ─────────────────────────────────────────────────
        self.content_stack = QStackedWidget()
        main_layout.addWidget(self.content_stack)

        self._init_discover_view()
        self._init_ranges_view()
        self._init_history_view()

    def _init_discover_view(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        # ── Header row ────────────────────────────────────────────────────
        header = QHBoxLayout()

        title_v = QVBoxLayout()
        title_v.addWidget(QLabel("Discovery Dashboard", styleSheet="font-size: 20px; font-weight: bold;"))
        title_v.addWidget(QLabel("Network device location system", styleSheet="font-size: 11px; color: #666;"))
        header.addLayout(title_v)
        header.addStretch()

        # Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search IP, MAC, room…")
        self.search_input.setFixedWidth(220)
        self.search_input.setStyleSheet("padding: 5px 10px; border-radius: 4px; border: 1px solid #ccc;")
        self.search_input.textChanged.connect(self.refresh_table)
        header.addWidget(self.search_input)

        header.addSpacing(8)

        # Reset button — clears current view and starts fresh
        self.reset_btn = QPushButton("↺ New Session")
        self.reset_btn.setToolTip("Clear results and start a new discovery session")
        self.reset_btn.clicked.connect(self.reset_session)
        header.addWidget(self.reset_btn)

        self.export_btn = QPushButton("⬇ Export CSV")
        self.export_btn.setObjectName("Primary")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_csv)
        header.addWidget(self.export_btn)

        layout.addLayout(header)

        # ── Progress bar ──────────────────────────────────────────────────
        self.progress_panel = QFrame()
        self.progress_panel.setObjectName("Panel")
        self.progress_panel.setStyleSheet("background-color: #f0f7ff; border: 1px solid #cce5ff; border-radius: 5px;")
        self.progress_panel.hide()
        pp_layout = QHBoxLayout(self.progress_panel)
        self.status_label = QLabel("SEARCHING...")
        self.status_label.setStyleSheet("color: #0366d6; font-weight: bold; font-size: 13px;")
        pp_layout.addWidget(self.status_label)
        pp_layout.addStretch()
        layout.addWidget(self.progress_panel)

        # ── Stat cards ────────────────────────────────────────────────────
        self.stats_bar = QHBoxLayout()
        self.stat_cards = {
            "all":               StatCard("Total Discovered",   0, "#6c757d", "all"),
            "managed":           StatCard("Managed",            0, "#0366d6", "managed"),
            "managed_hotspot":   StatCard("Relayed",            0, "#28a745", "managed_hotspot"),
            "unmanaged_hotspot": StatCard("Unmanaged Hotspot",  0, "#f59f00", "unmanaged_hotspot"),
            "unmanaged":         StatCard("Unmanaged",          0, "#dc3545", "unmanaged"),
        }
        for card in self.stat_cards.values():
            card.clicked.connect(self.filter_devices)
            self.stats_bar.addWidget(card)
        layout.addLayout(self.stats_bar)

        # ── Action panels ─────────────────────────────────────────────────
        panels = QHBoxLayout()
        
        target_panel = QFrame()
        target_panel.setObjectName("Panel")
        tp_layout = QVBoxLayout(target_panel)
        tp_layout.addWidget(QLabel("Targeted Discovery"))
        
        form = QFormLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP or MAC Address")
        form.addRow("Target:", self.target_input)
        
        btn_target = QPushButton("Locate Target")
        btn_target.clicked.connect(self.start_targeted_discovery)
        
        btn_all = QPushButton("Scan Network")
        btn_all.setObjectName("Primary")
        btn_all.clicked.connect(self.start_full_discovery)
        
        tp_layout.addLayout(form)
        tp_layout.addWidget(btn_target)
        tp_layout.addWidget(btn_all)
        panels.addWidget(target_panel)
        
        layout.addLayout(panels)

        # ── Results table ─────────────────────────────────────────────────
        self.table = DeviceTable()
        layout.addWidget(self.table)

        self.content_stack.addWidget(page)

    def _init_ranges_view(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        
        layout.addWidget(QLabel("Broadcast Ranges", styleSheet="font-size: 20px; font-weight: bold;"))
        layout.addWidget(QLabel("Define custom subnets for discovery broadcasts", styleSheet="margin-bottom: 20px;"))

        form_panel = QFrame()
        form_panel.setObjectName("Panel")
        form_h = QHBoxLayout(form_panel)
        self.range_input = QLineEdit()
        self.range_input.setPlaceholderText("e.g. 10.51.144.1-254")
        self.range_input.setStyleSheet("font-family: Consolas, monospace;")
        self.range_input.returnPressed.connect(self.add_custom_range)
        
        add_btn = QPushButton("Add")
        add_btn.setObjectName("Primary")
        add_btn.clicked.connect(self.add_custom_range)
        
        scan_now_btn = QPushButton("Scan This Range Now")
        scan_now_btn.clicked.connect(self.scan_immediate_range)
        
        self.primary_checkbox = QCheckBox("Mark as Primary")
        self.primary_checkbox.setToolTip("Agents will only report physical wall ports if discovery comes from a primary subnet.")
        
        form_h.addWidget(QLabel("Add Range:"))
        form_h.addWidget(self.range_input, 1)
        form_h.addWidget(self.primary_checkbox)
        form_h.addWidget(add_btn)
        form_h.addWidget(scan_now_btn)
        layout.addWidget(form_panel)
        
        self.range_preview = QLabel("")
        self.range_preview.setStyleSheet("font-size: 11px; color: #6c757d; font-family: Consolas, monospace;")
        layout.addWidget(self.range_preview)
        self.range_input.textChanged.connect(self.update_range_preview)

        list_header = QHBoxLayout()
        list_header.addWidget(QLabel("Saved Discovery Ranges", styleSheet="font-weight: bold; margin-top: 10px;"))
        list_header.addStretch()
        scan_all_btn = QPushButton("Scan All Saved Ranges")
        scan_all_btn.clicked.connect(self.scan_all_custom_ranges)
        list_header.addWidget(scan_all_btn)
        layout.addLayout(list_header)

        self.ranges_list = QListWidget()
        self.ranges_list.setObjectName("Panel")
        layout.addWidget(self.ranges_list)
        
        bottom_btns = QHBoxLayout()
        del_btn = QPushButton("Delete Selected")
        del_btn.clicked.connect(self.delete_custom_range)
        bottom_btns.addWidget(del_btn)
        bottom_btns.addStretch()
        layout.addLayout(bottom_btns)
        
        self.content_stack.addWidget(page)
        self.refresh_ranges_list()

    def _init_history_view(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        
        layout.addWidget(QLabel("Session History", styleSheet="font-size: 20px; font-weight: bold;"))
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["Session ID", "Type", "Devices", "Started", "Action"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.itemDoubleClicked.connect(self.load_history_session_item)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.history_table)
        
        self.content_stack.addWidget(page)

    # ── Slots & Actions ───────────────────────────────────────────────────────

    def show_view(self, key):
        for k, btn in self.nav_btns.items():
            btn.setProperty("active", k == key)
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        
        if key == "discover":
            self.content_stack.setCurrentIndex(0)
        elif key == "ranges":
            self.refresh_ranges_list()
            self.content_stack.setCurrentIndex(1)
        elif key == "history":
            self.refresh_history_list()
            self.content_stack.setCurrentIndex(2)

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.set_theme(self.is_dark_mode)
        self.theme_btn.setText("☀️ Light Mode" if self.is_dark_mode else "🌙 Dark Mode")

    def set_theme(self, dark):
        self.setStyleSheet(DARK_STYLE if dark else LIGHT_STYLE)

    # ── Session management ────────────────────────────────────────────────────

    def reset_session(self):
        """Clear the current view and deactivate the session — ready for a new scan."""
        self.countdown_timer.stop()
        self.progress_panel.hide()
        self.active_session_id = None
        self.current_filter = "all"
        for card in self.stat_cards.values():
            card.set_count(0)
        self.table.setRowCount(0)
        self.export_btn.setEnabled(False)
        self.search_input.clear()

    def start_full_discovery(self):
        self.active_session_id = str(uuid.uuid4())
        self.store.init_session(self.active_session_id, "full")
        self.reset_session()
        self.active_session_id = str(uuid.uuid4())  # re-create after reset clears it
        self.store.init_session(self.active_session_id, "full")
        self.broadcaster.broadcast(self.active_session_id, "full")
        self.export_btn.setEnabled(True)
        self.start_countdown(60)
        
        def deferred_scan():
            time.sleep(3.0)
            self.run_background_arp_scan(self.active_session_id)
            
        threading.Thread(target=deferred_scan, daemon=True).start()

    def start_targeted_discovery(self):
        target = self.target_input.text().strip()
        if not target:
            return
        self.reset_session()
        self.active_session_id = str(uuid.uuid4())
        self.store.init_session(self.active_session_id, "targeted")
        self.broadcaster.broadcast(self.active_session_id, "targeted", target)
        self.export_btn.setEnabled(True)
        self.start_countdown(5)

    def start_countdown(self, seconds):
        self.countdown_val = seconds
        self.status_label.setText(f"NETWORK SCANNING IN PROGRESS… {self.countdown_val}s REMAINING")
        self.progress_panel.show()
        self.countdown_timer.start(1000)

    def _update_countdown(self):
        self.countdown_val -= 1
        if self.countdown_val <= 0:
            self.countdown_timer.stop()
            self.status_label.setText("SEARCH COMPLETE — DEVICES SYNCED")
            QTimer.singleShot(5000, self.progress_panel.hide)
        else:
            self.status_label.setText(f"NETWORK SCANNING IN PROGRESS… {self.countdown_val}s REMAINING")

    def on_device_reported(self, req_id, device):
        if req_id == self.active_session_id:
            self.update_stats()
            self.refresh_table()

    def run_background_arp_scan(self, session_id):
        networks = self.broadcaster.get_scan_networks()
        for net in networks:
            found = scan_subnet(net)
            for ip, mac in found.items():
                device = {
                    "hostname":    f"Unmanaged-{ip}",
                    "mac":         mac,
                    "ip":          ip,
                    "type":        "unmanaged",
                    "vendor":      lookup_vendor(mac),
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                    "reporter_ip": "internal-arp-scan"
                }
                self.store.add_result(session_id, device)
                self.arp_scan_result_received.emit(session_id, device)

    def update_stats(self):
        if not self.active_session_id:
            return
        session = self.store.get_session(self.active_session_id)
        if not session:
            return
        
        devices = session["devices"]
        counts = {"all": len(devices), "managed": 0, "managed_hotspot": 0, "unmanaged_hotspot": 0, "unmanaged": 0}
        
        for d in devices:
            dtype      = d.get("type", "unmanaged")
            relay_host = d.get("relay_host", "")
            if dtype == "managed":
                counts["managed"] += 1
            elif dtype == "relayed":
                counts["managed_hotspot"] += 1
            elif dtype == "unmanaged":
                if relay_host:
                    counts["unmanaged_hotspot"] += 1
                else:
                    counts["unmanaged"] += 1
        
        for key, count in counts.items():
            self.stat_cards[key].set_count(count)

    def refresh_table(self):
        if not self.active_session_id:
            return
        session = self.store.get_session(self.active_session_id)
        if session:
            self.table.update_devices(session["devices"], self.current_filter, self.search_input.text())

    def filter_devices(self, filter_key):
        self.current_filter = filter_key
        self.refresh_table()

    def clear_dashboard(self):
        """Internal helper used by scan actions to wipe visible state only."""
        for card in self.stat_cards.values():
            card.set_count(0)
        self.table.setRowCount(0)
        self.export_btn.setEnabled(False)

    # ── Range management ──────────────────────────────────────────────────────

    def add_custom_range(self):
        cidr = self.range_input.text().strip()
        is_primary = self.primary_checkbox.isChecked()
        if cidr:
            if self.broadcaster.add_range(cidr, cidr, is_primary):
                self.range_input.clear()
                self.primary_checkbox.setChecked(False)
                self.refresh_ranges_list()

    def scan_immediate_range(self):
        cidr = self.range_input.text().strip()
        if not cidr:
            return
        self.reset_session()
        self.active_session_id = str(uuid.uuid4())
        self.store.init_session(self.active_session_id, "range_scan")
        if self.broadcaster.send_range_discovery(self.active_session_id, cidr):
            self.show_view("discover")
            self.export_btn.setEnabled(True)

    def scan_all_custom_ranges(self):
        ranges = self.broadcaster.get_ranges()
        if not ranges:
            return
        self.reset_session()
        self.active_session_id = str(uuid.uuid4())
        self.store.init_session(self.active_session_id, "all_ranges_scan")
        for r in ranges:
            self.broadcaster.send_range_discovery(self.active_session_id, str(r.network))
        self.show_view("discover")
        self.export_btn.setEnabled(True)

    def update_range_preview(self):
        from qt.logic import parse_custom_range
        text = self.range_input.text().strip()
        if not text:
            self.range_preview.setText("")
            return
        pr = parse_custom_range(text)
        if pr:
            self.range_preview.setText(f"✓ Valid: {pr.network} ({pr.host_count} hosts, broadcast: {pr.broadcast})")
            self.range_preview.setStyleSheet("font-size: 11px; color: #28a745; font-family: Consolas, monospace;")
        else:
            self.range_preview.setText("⚠ Invalid range format")
            self.range_preview.setStyleSheet("font-size: 11px; color: #dc3545; font-family: Consolas, monospace;")

    def delete_custom_range(self):
        row = self.ranges_list.currentRow()
        if row >= 0:
            self.broadcaster.remove_range(row)
            self.refresh_ranges_list()

    def refresh_ranges_list(self):
        self.ranges_list.clear()
        for r in self.broadcaster.get_ranges():
            prefix = "[PRIMARY] " if r.is_primary else ""
            item = QListWidgetItem(f"{prefix}{r.network} (Broadcast: {r.broadcast}, Hosts: {r.host_count})")
            if r.is_primary:
                item.setForeground(Qt.GlobalColor.blue)
            item.setData(Qt.ItemDataRole.UserRole, str(r.network))
            self.ranges_list.addItem(item)

    # ── History ───────────────────────────────────────────────────────────────

    def refresh_history_list(self):
        self.history_table.setRowCount(0)
        history = self.store.get_history()
        for h in reversed(history):
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            
            short_id = h['request_id'][:8].upper() + "…"
            id_item = QTableWidgetItem(short_id)
            id_item.setData(Qt.ItemDataRole.UserRole, h['request_id'])
            id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 0, id_item)
            
            dtype = h['type'].replace("_", " ").upper()
            type_item = QTableWidgetItem(dtype)
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 1, type_item)
            
            count_item = QTableWidgetItem(f"{h['device_count']} devices")
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 2, count_item)
            
            ts = h['started_at'].replace('T', ' ').split('.')[0]
            ts_item = QTableWidgetItem(ts)
            ts_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 3, ts_item)
            
            view_btn = QPushButton("View Session →")
            view_btn.setStyleSheet("color: #0366d6; border: none; background: transparent; font-weight: bold;")
            view_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            view_btn.clicked.connect(lambda checked, rid=h['request_id']: self.load_history_by_id(rid))
            self.history_table.setCellWidget(row, 4, view_btn)

    def load_history_session_item(self, item):
        row = self.history_table.row(item)
        id_item = self.history_table.item(row, 0)
        if id_item:
            self.load_history_by_id(id_item.data(Qt.ItemDataRole.UserRole))

    def load_history_by_id(self, req_id):
        self.active_session_id = req_id
        self.show_view("discover")
        self.update_stats()
        self.refresh_table()
        self.export_btn.setEnabled(True)

    # ── Export ────────────────────────────────────────────────────────────────

    def export_csv(self):
        if not self.active_session_id:
            return
        session = self.store.get_session(self.active_session_id)
        if not session:
            return
        
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Results",
            f"discovery_{self.active_session_id[:8]}.csv",
            "CSV Files (*.csv)"
        )
        if path:
            try:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        "hostname", "mac", "ip", "username", "building", "room",
                        "type", "relay_host", "vendor", "timestamp",
                        "connection_type", "port", "additional_ports"
                    ], extrasaction="ignore")
                    writer.writeheader()
                    for d in session["devices"]:
                        writer.writerow(d)
            except Exception as e:
                print(f"Export failed: {e}")