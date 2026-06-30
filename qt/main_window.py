"""
qt/main_window.py  (patched)

Key fixes
─────────
1. FREEZE FIX  — broadcaster.broadcast() and run_background_arp_scan() now
   both run on worker QThreads so the Qt event loop is never blocked.

2. TABLE THRASH — DeviceTable.update_devices() was called on every single
   device arrival.  Now a QTimer coalesces rapid-fire updates into one
   redraw per 400 ms (matching the web dashboard's 1-second poll cadence).

3. TARGETED TIMEOUT — was 5 s, now 30 s.  The round-trip to a remote agent
   (packet → agent → HTTP POST back) can easily exceed 5 s on a loaded LAN.

4. TARGET INPUT — replaced QLineEdit with TargetInputWidget which provides
   a MAC/IP mode toggle, auto-formatting, per-character validation (✓/✗),
   and Enter-to-search — identical to the HTML dashboard.
"""

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
    QScrollArea, QFrame, QCheckBox, QMessageBox,
)
from PyQt6.QtCore import Qt, pyqtSlot, QTimer, pyqtSignal, QThread, QObject

from qt.logic import Config, ResultStore, DiscoveryBroadcaster, get_lan_ip
from qt.widgets import StatCard, DeviceTable, FilterChipsBar
from qt.api_server import ApiServerThread
from qt.styles import LIGHT_STYLE, DARK_STYLE
from qt.logic import scan_subnet, lookup_vendor
from qt.target_widget import TargetInputWidget


# ── Background worker: broadcast + ARP scan ───────────────────────────────────

class _BroadcastWorker(QObject):
    """
    Runs broadcaster.broadcast() and (after a delay) the ARP scan on a
    dedicated QThread so the main thread stays responsive.
    """
    device_found = pyqtSignal(str, dict)   # session_id, device
    finished     = pyqtSignal()

    def __init__(self, broadcaster, store, session_id: str,
                 mode: str = "full", target: str = ""):
        super().__init__()
        self._broadcaster = broadcaster
        self._store       = store
        self._session_id  = session_id
        self._mode        = mode
        self._target      = target

    def run(self):
        try:
            # 1. Send UDP broadcast(s) — fast but uses sockets
            self._broadcaster.broadcast(self._session_id, self._mode, self._target)

            # 2. For full scans also run ARP (deferred 3 s)
            if self._mode == "full":
                time.sleep(3.0)
                networks = self._broadcaster.get_scan_networks()
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
                            "reporter_ip": "internal-arp-scan",
                        }
                        self._store.add_result(self._session_id, device)
                        self.device_found.emit(self._session_id, device)
        finally:
            self.finished.emit()


# ── MainWindow ────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    # Internal signal: device arrived from ARP worker (already on bg thread)
    _arp_device_arrived = pyqtSignal(str, dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mneti — Administrative Discovery Dashboard")
        self.resize(1200, 750)

        # Countdown / progress
        self.countdown_val   = 0
        self.countdown_timer = QTimer()
        self.countdown_timer.timeout.connect(self._update_countdown)

        # Batched table refresh — coalesces rapid device-arrived signals
        self._refresh_pending = False
        self._batch_timer = QTimer()
        self._batch_timer.setSingleShot(True)
        self._batch_timer.setInterval(400)   # ms between table redraws
        self._batch_timer.timeout.connect(self._do_refresh_table)

        # Internal signals wired with Qt.QueuedConnection automatically
        self._arp_device_arrived.connect(self._on_arp_device)

        self.store       = ResultStore()
        self.broadcaster = DiscoveryBroadcaster(self.store)
        self.active_session_id = None
        self.current_filter    = "all"
        self.is_dark_mode      = False

        # Background worker handles
        self._worker_thread: QThread | None = None
        self._worker: _BroadcastWorker | None = None

        self.api_thread = ApiServerThread(self.store)
        self.api_thread.device_reported.connect(self.on_device_reported)
        self.api_thread.start()

        self._setup_ui()
        self.set_theme(False)
        self.show_view("discover")

    # ─────────────────────────────────────────────────────────────────────────
    # UI setup
    # ─────────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Sidebar ───────────────────────────────────────────────────────────
        self.sidebar = QWidget()
        self.sidebar.setObjectName("Sidebar")
        sb_layout = QVBoxLayout(self.sidebar)
        sb_layout.setContentsMargins(0, 20, 0, 20)

        logo = QLabel("MNETI")
        logo.setStyleSheet(
            "font-size: 18px; font-weight: bold; margin-bottom: 20px; padding: 10px 20px;")
        sb_layout.addWidget(logo)

        self.nav_btns = {}
        for key, text in [
            ("discover", "◈ Discover Devices"),
            ("ranges",   "⊞ Broadcast Ranges"),
            ("history",  "◷ Session History"),
        ]:
            btn = QPushButton(text)
            btn.clicked.connect(lambda _checked, k=key: self.show_view(k))
            sb_layout.addWidget(btn)
            self.nav_btns[key] = btn

        sb_layout.addStretch()

        self.theme_btn = QPushButton("🌙 Dark Mode")
        self.theme_btn.clicked.connect(self.toggle_theme)
        sb_layout.addWidget(self.theme_btn)

        info = QLabel(f"Server: Online\nIP: {get_lan_ip()}")
        info.setStyleSheet("font-size: 11px; color: #777; padding: 20px;")
        sb_layout.addWidget(info)

        main_layout.addWidget(self.sidebar)

        # ── Content stack ─────────────────────────────────────────────────────
        self.content_stack = QStackedWidget()
        main_layout.addWidget(self.content_stack)

        self._init_discover_view()
        self._init_ranges_view()
        self._init_history_view()

    # ─────────────────────────────────────────────────────────────────────────
    # Discover view
    # ─────────────────────────────────────────────────────────────────────────

    def _init_discover_view(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header row
        header = QHBoxLayout()
        title_v = QVBoxLayout()
        title_v.addWidget(QLabel("Discovery Dashboard",
                                 styleSheet="font-size: 20px; font-weight: bold;"))
        title_v.addWidget(QLabel("Network device location system",
                                 styleSheet="font-size: 11px; color: #666;"))
        header.addLayout(title_v)
        header.addStretch()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search IP, MAC, room…")
        self.search_input.setFixedWidth(220)
        self.search_input.setStyleSheet(
            "QLineEdit { background:#fff; color:#212529; border:1px solid #ced4da;"
            " border-radius:4px; padding:5px 10px; font-size:13px; }"
            "QLineEdit:focus { border-color:#80bdff; }"
        )
        self.search_input.textChanged.connect(self._schedule_refresh)
        header.addWidget(self.search_input)

        header.addSpacing(8)

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

        # Progress banner
        self.progress_panel = QFrame()
        self.progress_panel.setObjectName("Panel")
        self.progress_panel.setStyleSheet(
            "background-color:#f0f7ff; border:1px solid #cce5ff; border-radius:5px;")
        self.progress_panel.hide()
        pp_layout = QHBoxLayout(self.progress_panel)
        self.status_label = QLabel("SEARCHING...")
        self.status_label.setStyleSheet(
            "color:#0366d6; font-weight:bold; font-size:13px;")
        pp_layout.addWidget(self.status_label)
        pp_layout.addStretch()
        layout.addWidget(self.progress_panel)

        # Stat cards
        self.stats_bar = QHBoxLayout()
        self.stat_cards = {
            "all":               StatCard("Total Discovered",   0, "#6c757d", "all"),
            "managed":           StatCard("Managed",            0, "#0366d6", "managed"),
            "managed_hotspot":   StatCard("Relayed",            0, "#28a745", "managed_hotspot"),
            "unmanaged_hotspot": StatCard("Unmanaged Hotspot",  0, "#f59f00", "unmanaged_hotspot"),
            "unmanaged":         StatCard("Unmanaged",          0, "#dc3545", "unmanaged"),
        }
        for card in self.stat_cards.values():
            card.clicked.connect(self._on_stat_card_clicked)
            self.stats_bar.addWidget(card)
        layout.addLayout(self.stats_bar)

        # Action panels
        panels = QHBoxLayout()

        # ── Targeted Discovery panel ──────────────────────────────────────────
        target_panel = QFrame()
        target_panel.setObjectName("Panel")
        tp_layout = QVBoxLayout(target_panel)
        tp_layout.addWidget(QLabel("Targeted Discovery",
                                   styleSheet="font-weight:bold; font-size:14px;"))

        self.target_widget = TargetInputWidget()
        self.target_widget.search_requested.connect(self.start_targeted_discovery)
        tp_layout.addWidget(self.target_widget)

        tp_layout.addWidget(QLabel(
            "Sends a UDP broadcast. Only the matching device responds.",
            styleSheet="font-size:11px; color:#6c757d; margin-top:4px;"))
        panels.addWidget(target_panel)

        # ── Full Discovery panel ──────────────────────────────────────────────
        full_panel = QFrame()
        full_panel.setObjectName("Panel")
        fp_layout = QVBoxLayout(full_panel)
        fp_layout.addWidget(QLabel("Full Network Discovery Scan",
                                   styleSheet="font-weight:bold; font-size:14px;"))
        fp_layout.addWidget(QLabel(
            "Broadcast discovery to all clients — including custom ranges. "
            "All listening devices will report their location.",
            styleSheet="font-size:13px; color:#555; margin-bottom:12px;"))

        btn_all = QPushButton("Scan Network")
        btn_all.setObjectName("Primary")
        btn_all.clicked.connect(self.start_full_discovery)
        fp_layout.addWidget(btn_all)
        fp_layout.addStretch()
        panels.addWidget(full_panel)

        layout.addLayout(panels)

        # Filter chips
        self.chips_bar = FilterChipsBar()
        self.chips_bar.filter_changed.connect(self._on_chip_filter_changed)
        layout.addWidget(self.chips_bar)

        # Results table
        self.table = DeviceTable()
        layout.addWidget(self.table)

        self.content_stack.addWidget(page)

    # ─────────────────────────────────────────────────────────────────────────
    # Ranges view (unchanged from original)
    # ─────────────────────────────────────────────────────────────────────────

    def _init_ranges_view(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        layout.addWidget(QLabel("Broadcast Ranges",
                                styleSheet="font-size: 20px; font-weight: bold;"))
        layout.addWidget(QLabel("Define custom subnets for discovery broadcasts",
                                styleSheet="margin-bottom: 20px;"))

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
        self.primary_checkbox.setToolTip(
            "Agents report wall ports only when discovery comes from a primary subnet.")

        form_h.addWidget(QLabel("Add Range:"))
        form_h.addWidget(self.range_input, 1)
        form_h.addWidget(self.primary_checkbox)
        form_h.addWidget(add_btn)
        form_h.addWidget(scan_now_btn)
        layout.addWidget(form_panel)

        self.range_preview = QLabel("")
        self.range_preview.setStyleSheet(
            "font-size: 11px; color: #6c757d; font-family: Consolas, monospace;")
        layout.addWidget(self.range_preview)
        self.range_input.textChanged.connect(self.update_range_preview)

        list_header = QHBoxLayout()
        list_header.addWidget(QLabel("Saved Discovery Ranges",
                                     styleSheet="font-weight: bold; margin-top: 10px;"))
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

    # ─────────────────────────────────────────────────────────────────────────
    # History view (unchanged from original)
    # ─────────────────────────────────────────────────────────────────────────

    def _init_history_view(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addWidget(QLabel("Session History",
                                styleSheet="font-size: 20px; font-weight: bold;"))
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(
            ["Session ID", "Type", "Devices", "Started", "Action"])
        self.history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.itemDoubleClicked.connect(self.load_history_session_item)
        self.history_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.history_table)
        self.content_stack.addWidget(page)

    # ─────────────────────────────────────────────────────────────────────────
    # Navigation
    # ─────────────────────────────────────────────────────────────────────────

    def show_view(self, key: str):
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

    def set_theme(self, dark: bool):
        self.setStyleSheet(DARK_STYLE if dark else LIGHT_STYLE)
        self.search_input.setStyleSheet(
            "QLineEdit { background:#fff; color:#212529; border:1px solid #ced4da;"
            " border-radius:4px; padding:5px 10px; font-size:13px; }"
            "QLineEdit:focus { border-color:#80bdff; }"
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Filter routing
    # ─────────────────────────────────────────────────────────────────────────

    def _on_stat_card_clicked(self, filter_key: str):
        self.current_filter = filter_key
        self.chips_bar._on_chip_clicked(filter_key)
        self._schedule_refresh()

    def _on_chip_filter_changed(self, filter_key: str):
        self.current_filter = filter_key
        self._schedule_refresh()

    # ─────────────────────────────────────────────────────────────────────────
    # Session management
    # ─────────────────────────────────────────────────────────────────────────

    def reset_session(self):
        """Stop any running scan and clear the display."""
        self._stop_worker()
        self.countdown_timer.stop()
        self._batch_timer.stop()
        self.progress_panel.hide()
        self.active_session_id = None
        self.current_filter = "all"
        for card in self.stat_cards.values():
            card.set_count(0)
        self.chips_bar.reset()
        self.table.setRowCount(0)
        self.export_btn.setEnabled(False)
        self.search_input.clear()

    def _stop_worker(self):
        """Cleanly stop the background broadcast/ARP worker if running."""
        if self._worker_thread and self._worker_thread.isRunning():
            self._worker_thread.quit()
            self._worker_thread.wait(2000)
        self._worker_thread = None
        self._worker = None

    def start_full_discovery(self):
        self.reset_session()
        sid = str(uuid.uuid4())
        self.active_session_id = sid
        self.store.init_session(sid, "full")
        self.export_btn.setEnabled(True)
        self.start_countdown(60)
        self._launch_worker(mode="full")

    def start_targeted_discovery(self):
        value = self.target_widget.value()
        if not value:
            QMessageBox.warning(self, "Invalid Target",
                                "Please enter a valid MAC address or IP address.")
            return

        mode = "targeted_mac" if self.target_widget.mode() == "mac" else "targeted_ip"
        self.reset_session()
        sid = str(uuid.uuid4())
        self.active_session_id = sid
        self.store.init_session(sid, "targeted")
        self.export_btn.setEnabled(True)
        # 30 s — enough for agent round-trip on a loaded LAN
        self.start_countdown(30)
        self._launch_worker(mode=mode, target=value)

    def _launch_worker(self, mode: str, target: str = ""):
        """Offload broadcast + ARP scan to a background QThread."""
        self._stop_worker()

        worker  = _BroadcastWorker(self.broadcaster, self.store,
                                   self.active_session_id, mode, target)
        thread  = QThread(self)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.device_found.connect(self._arp_device_arrived)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        self._worker        = worker
        self._worker_thread = thread
        thread.start()

    # ─────────────────────────────────────────────────────────────────────────
    # Countdown
    # ─────────────────────────────────────────────────────────────────────────

    def start_countdown(self, seconds: int):
        self.countdown_val = seconds
        self.status_label.setText(
            f"NETWORK SCANNING IN PROGRESS… {seconds}s REMAINING")
        self.progress_panel.show()
        self.countdown_timer.start(1000)

    def _update_countdown(self):
        self.countdown_val -= 1
        if self.countdown_val <= 0:
            self.countdown_timer.stop()
            session = self.store.get_session(self.active_session_id) if self.active_session_id else None
            count = len(session["devices"]) if session else 0
            self.status_label.setText(
                f"SCAN COMPLETE — {count} device(s) found")
            QTimer.singleShot(5000, self.progress_panel.hide)
        else:
            self.status_label.setText(
                f"NETWORK SCANNING IN PROGRESS… {self.countdown_val}s REMAINING")

    # ─────────────────────────────────────────────────────────────────────────
    # Device arrival  (both managed via HTTP and unmanaged via ARP)
    # ─────────────────────────────────────────────────────────────────────────

    @pyqtSlot(str, dict)
    def on_device_reported(self, req_id: str, device: dict):
        """Called on the main thread via ApiServerThread signal."""
        if req_id == self.active_session_id:
            self.update_stats()
            self._schedule_refresh()

    @pyqtSlot(str, dict)
    def _on_arp_device(self, req_id: str, device: dict):
        """Called on the main thread via _arp_device_arrived signal."""
        if req_id == self.active_session_id:
            self.update_stats()
            self._schedule_refresh()

    # ─────────────────────────────────────────────────────────────────────────
    # Batched table refresh
    # ─────────────────────────────────────────────────────────────────────────

    def _schedule_refresh(self, *_):
        """Coalesce rapid device-arrived signals into one redraw per 400 ms."""
        if not self._batch_timer.isActive():
            self._batch_timer.start()

    def _do_refresh_table(self):
        if not self.active_session_id:
            return
        session = self.store.get_session(self.active_session_id)
        if session:
            self.table.update_devices(
                session["devices"],
                self.current_filter,
                self.search_input.text(),
            )

    # Legacy alias kept so existing call-sites (history load) still work
    def refresh_table(self):
        self._do_refresh_table()

    # ─────────────────────────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────────────────────────

    def update_stats(self):
        if not self.active_session_id:
            return
        session = self.store.get_session(self.active_session_id)
        if not session:
            return
        devices = session["devices"]
        counts = {
            "all": len(devices), "managed": 0,
            "managed_hotspot": 0, "unmanaged_hotspot": 0, "unmanaged": 0,
        }
        for d in devices:
            dtype = d.get("type", "unmanaged")
            relay = d.get("relay_host", "")
            if dtype == "managed":
                counts["managed"] += 1
            elif dtype == "relayed":
                counts["managed_hotspot"] += 1
            elif dtype == "unmanaged":
                if relay:
                    counts["unmanaged_hotspot"] += 1
                else:
                    counts["unmanaged"] += 1
        for key, count in counts.items():
            self.stat_cards[key].set_count(count)
        self.chips_bar.set_counts(counts)

    # ─────────────────────────────────────────────────────────────────────────
    # Range management (unchanged)
    # ─────────────────────────────────────────────────────────────────────────

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
        sid = str(uuid.uuid4())
        self.active_session_id = sid
        self.store.init_session(sid, "range_scan")
        if self.broadcaster.send_range_discovery(sid, cidr):
            self.show_view("discover")
            self.export_btn.setEnabled(True)

    def scan_all_custom_ranges(self):
        ranges = self.broadcaster.get_ranges()
        if not ranges:
            return
        self.reset_session()
        sid = str(uuid.uuid4())
        self.active_session_id = sid
        self.store.init_session(sid, "all_ranges_scan")
        for r in ranges:
            self.broadcaster.send_range_discovery(sid, str(r.network))
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
            self.range_preview.setText(
                f"✓ Valid: {pr.network} ({pr.host_count} hosts, broadcast: {pr.broadcast})")
            self.range_preview.setStyleSheet(
                "font-size:11px; color:#28a745; font-family:Consolas,monospace;")
        else:
            self.range_preview.setText("⚠ Invalid range format")
            self.range_preview.setStyleSheet(
                "font-size:11px; color:#dc3545; font-family:Consolas,monospace;")

    def delete_custom_range(self):
        row = self.ranges_list.currentRow()
        if row >= 0:
            self.broadcaster.remove_range(row)
            self.refresh_ranges_list()

    def refresh_ranges_list(self):
        self.ranges_list.clear()
        for r in self.broadcaster.get_ranges():
            prefix = "[PRIMARY] " if r.is_primary else ""
            item = QListWidgetItem(
                f"{prefix}{r.network} (Broadcast: {r.broadcast}, Hosts: {r.host_count})")
            if r.is_primary:
                item.setForeground(Qt.GlobalColor.blue)
            item.setData(Qt.ItemDataRole.UserRole, str(r.network))
            self.ranges_list.addItem(item)

    # ─────────────────────────────────────────────────────────────────────────
    # History (unchanged)
    # ─────────────────────────────────────────────────────────────────────────

    def refresh_history_list(self):
        self.history_table.setRowCount(0)
        for h in reversed(self.store.get_history()):
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            short_id = h["request_id"][:8].upper() + "…"
            id_item = QTableWidgetItem(short_id)
            id_item.setData(Qt.ItemDataRole.UserRole, h["request_id"])
            id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 0, id_item)
            type_item = QTableWidgetItem(h["type"].replace("_", " ").upper())
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 1, type_item)
            count_item = QTableWidgetItem(f"{h['device_count']} devices")
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 2, count_item)
            ts = h["started_at"].replace("T", " ").split(".")[0]
            ts_item = QTableWidgetItem(ts)
            ts_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 3, ts_item)
            view_btn = QPushButton("View Session →")
            view_btn.setStyleSheet(
                "color:#0366d6; border:none; background:transparent; font-weight:bold;")
            view_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            view_btn.clicked.connect(
                lambda _c, rid=h["request_id"]: self.load_history_by_id(rid))
            self.history_table.setCellWidget(row, 4, view_btn)

    def load_history_session_item(self, item):
        row = self.history_table.row(item)
        id_item = self.history_table.item(row, 0)
        if id_item:
            self.load_history_by_id(id_item.data(Qt.ItemDataRole.UserRole))

    def load_history_by_id(self, req_id: str):
        self.active_session_id = req_id
        self.show_view("discover")
        self.update_stats()
        self.refresh_table()
        self.export_btn.setEnabled(True)

    # ─────────────────────────────────────────────────────────────────────────
    # Export
    # ─────────────────────────────────────────────────────────────────────────

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
                        "connection_type", "port", "additional_ports",
                    ], extrasaction="ignore")
                    writer.writeheader()
                    for d in session["devices"]:
                        writer.writerow(d)
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))