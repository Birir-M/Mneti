"""
qt/target_widget.py
~~~~~~~~~~~~~~~~~~~
Targeted-discovery input widget for the Mneti Qt dashboard.

Mirrors the HTML dashboard's MAC / IP input exactly:
  • Toggle button switches between MAC and IP mode
  • MAC mode  — formats as AA:BB:CC:DD:EE:FF, validates hex pairs, shows ✓/✗
  • IP mode   — four separate octet boxes (0-255 each) with auto-advance, shows ✓/✗
  • Returns the typed value via .value() and emits search_requested when Enter/button hit
"""

import re
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel,
    QPushButton, QLineEdit, QFrame,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QKeyEvent


# ── MAC input ─────────────────────────────────────────────────────────────────

_MAC_RE = re.compile(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$')


class _MacLineEdit(QLineEdit):
    """Auto-formats MAC address as the user types (AA:BB:CC:DD:EE:FF)."""

    def __init__(self):
        super().__init__()
        self.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.setMaxLength(17)
        self.setFixedWidth(160)
        self.setStyleSheet(
            "font-family: Consolas, 'Courier New', monospace;"
            "letter-spacing: 0.05em; font-size: 13px;"
        )

    def is_valid(self) -> bool:
        return bool(_MAC_RE.match(self.text().upper()))

    def get_value(self) -> str:
        return self.text().upper()

    def keyPressEvent(self, event: QKeyEvent):
        key = event.key()
        text = event.text().upper()

        # Allow navigation / control keys through unchanged
        if key in (Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Home,
                   Qt.Key.Key_End, Qt.Key.Key_Delete, Qt.Key.Key_Tab):
            super().keyPressEvent(event)
            return

        if key == Qt.Key.Key_Backspace:
            pos = self.cursorPosition()
            cur = self.text()
            # If cursor is right after a colon, delete the colon too
            if pos > 0 and cur[pos - 1] == ':' and self.selectionLength() == 0:
                self.setText(cur[:pos - 1] + cur[pos:])
                self.setCursorPosition(pos - 1)
            else:
                super().keyPressEvent(event)
            self._refresh_icon()
            return

        if not re.match(r'[0-9A-F]', text):
            return  # swallow non-hex

        # Build new raw hex string and re-format
        raw = self.text().replace(':', '')
        pos = self.cursorPosition()
        # Map display pos → raw index (every 3rd char is a colon)
        group = pos // 3
        offset = pos % 3
        raw_pos = group * 2 + min(offset, 1)
        if raw_pos > len(raw):
            raw_pos = len(raw)
        if len(raw) >= 12:
            return  # full
        new_raw = raw[:raw_pos] + text + raw[raw_pos:]
        pairs = re.findall(r'[0-9A-F]{1,2}', new_raw)
        self.setText(':'.join(p.zfill(2)[:2] for p in pairs[:6]))

        # Advance cursor past new char (and the colon if applicable)
        new_raw_pos = raw_pos + 1
        new_group = new_raw_pos // 2
        new_offset = new_raw_pos % 2
        new_disp_pos = new_group * 3 + new_offset
        self.setCursorPosition(min(new_disp_pos, len(self.text())))
        self._refresh_icon()

    def _refresh_icon(self):
        # Trigger parent widget to update its validity label
        self.textChanged.emit(self.text())


# ── IP octet box ──────────────────────────────────────────────────────────────

class _OctetEdit(QLineEdit):
    advance_requested  = pyqtSignal()   # move focus to next octet
    retreat_requested  = pyqtSignal()   # move focus to previous octet
    search_requested   = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setMaxLength(3)
        self.setFixedWidth(36)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            "border: none; background: transparent;"
            "font-family: Consolas, monospace; font-size: 13px;"
        )
        self.textChanged.connect(self._auto_advance)

    def _clamp(self):
        try:
            v = int(self.text())
            if v > 255:
                self.setText("255")
        except ValueError:
            pass

    def _auto_advance(self):
        self._clamp()
        v = self.text()
        try:
            n = int(v)
            if len(v) == 3 or (len(v) == 2 and n > 25):
                self.advance_requested.emit()
        except ValueError:
            pass

    def keyPressEvent(self, event: QKeyEvent):
        key = event.key()
        if key == Qt.Key.Key_Return or key == Qt.Key.Key_Enter:
            self.search_requested.emit()
            return
        if key == Qt.Key.Key_Tab:
            self.advance_requested.emit()
            return
        if key == Qt.Key.Key_Period or key == Qt.Key.Key_Right:
            if self.cursorPosition() == len(self.text()):
                self._clamp()
                self.advance_requested.emit()
                return
        if key in (Qt.Key.Key_Backspace, Qt.Key.Key_Left):
            if self.cursorPosition() == 0 and self.selectionLength() == 0:
                self.retreat_requested.emit()
                return
        if event.text() and not event.text().isdigit():
            return  # swallow non-digit
        super().keyPressEvent(event)


# ── IP widget (4 octets with dots) ───────────────────────────────────────────

class _IPWidget(QWidget):
    value_changed = pyqtSignal()
    search_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._octets: list[_OctetEdit] = []

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Frame that mimics a single input box
        frame = QFrame()
        frame.setStyleSheet(
            "QFrame { border: 1px solid #ced4da; border-radius: 4px;"
            " background: #ffffff; }"
        )
        row = QHBoxLayout(frame)
        row.setContentsMargins(6, 0, 6, 0)
        row.setSpacing(0)

        for i in range(4):
            octet = _OctetEdit()
            self._octets.append(octet)
            row.addWidget(octet)
            if i < 3:
                dot = QLabel(".")
                dot.setStyleSheet(
                    "font-family: Consolas, monospace; font-size: 15px;"
                    " font-weight: bold; color: #343a40;"
                )
                row.addWidget(dot)

            octet.advance_requested.connect(
                lambda idx=i: self._focus(idx + 1))
            octet.retreat_requested.connect(
                lambda idx=i: self._focus(idx - 1))
            octet.search_requested.connect(self.search_requested)
            octet.textChanged.connect(lambda _: self.value_changed.emit())

        outer.addWidget(frame)

    def _focus(self, idx: int):
        if 0 <= idx < 4:
            self._octets[idx].setFocus()
            self._octets[idx].selectAll()

    def is_valid(self) -> bool:
        parts = [o.text() for o in self._octets]
        if not all(parts):
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def get_value(self) -> str:
        return '.'.join(o.text() for o in self._octets)

    def clear(self):
        for o in self._octets:
            o.clear()
        self._octets[0].setFocus()


# ── Combined TargetInputWidget ────────────────────────────────────────────────

class TargetInputWidget(QWidget):
    """
    Drop-in widget for the Discover panel.

    Signals
    -------
    search_requested   emitted when Enter pressed or Search button clicked
    """
    search_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._mode = "mac"   # "mac" | "ip"

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)

        # ── Row 1: toggle + input + search btn ───────────────────────────────
        row1 = QHBoxLayout()
        row1.setSpacing(6)

        self._toggle_btn = QPushButton("MAC ▾")
        self._toggle_btn.setFixedWidth(72)
        self._toggle_btn.setCheckable(False)
        self._toggle_btn.setStyleSheet(
            "QPushButton { font-weight: 600; border: 1px solid #ced4da;"
            " border-radius: 4px; padding: 5px 8px; background: #f8f9fa; }"
            "QPushButton:hover { background: #e2e6ea; }"
        )
        self._toggle_btn.clicked.connect(self._toggle_mode)
        row1.addWidget(self._toggle_btn)

        # MAC input
        self._mac_edit = _MacLineEdit()
        self._mac_edit.textChanged.connect(self._on_input_changed)
        self._mac_edit.returnPressed.connect(self.search_requested)
        row1.addWidget(self._mac_edit)

        # IP input
        self._ip_widget = _IPWidget()
        self._ip_widget.value_changed.connect(self._on_input_changed)
        self._ip_widget.search_requested.connect(self.search_requested)
        self._ip_widget.hide()
        row1.addWidget(self._ip_widget)

        # Validity icon
        self._valid_lbl = QLabel("")
        self._valid_lbl.setFixedWidth(18)
        row1.addWidget(self._valid_lbl)

        self._search_btn = QPushButton("Search")
        self._search_btn.setObjectName("Primary")
        self._search_btn.clicked.connect(self.search_requested)
        row1.addWidget(self._search_btn)

        root.addLayout(row1)

        # ── Row 2: hint ───────────────────────────────────────────────────────
        self._hint_lbl = QLabel("Format: AA:BB:CC:DD:EE:FF")
        self._hint_lbl.setStyleSheet("font-size: 11px; color: #6c757d; font-family: Consolas, monospace;")
        root.addWidget(self._hint_lbl)

    # ── Mode toggle ────────────────────────────────────────────────────────────

    def _toggle_mode(self):
        self._mode = "ip" if self._mode == "mac" else "mac"
        is_mac = self._mode == "mac"
        self._toggle_btn.setText("MAC ▾" if is_mac else "IP ▾")
        self._mac_edit.setVisible(is_mac)
        self._ip_widget.setVisible(not is_mac)
        self._hint_lbl.setText(
            "Format: AA:BB:CC:DD:EE:FF" if is_mac
            else "Format: 0–255 · 0–255 · 0–255 · 0–255"
        )
        self._valid_lbl.setText("")
        if is_mac:
            self._mac_edit.clear()
            self._mac_edit.setFocus()
        else:
            self._ip_widget.clear()

    # ── Validation indicator ──────────────────────────────────────────────────

    def _on_input_changed(self, *_):
        valid = self._is_valid()
        has_input = bool(self.raw_value())
        if not has_input:
            self._valid_lbl.setText("")
        elif valid:
            self._valid_lbl.setText('<span style="color:#28a745; font-size:14px;">✓</span>')
            self._valid_lbl.setTextFormat(Qt.TextFormat.RichText)
        else:
            self._valid_lbl.setText('<span style="color:#dc3545; font-size:14px;">✗</span>')
            self._valid_lbl.setTextFormat(Qt.TextFormat.RichText)

    def _is_valid(self) -> bool:
        if self._mode == "mac":
            return self._mac_edit.is_valid()
        return self._ip_widget.is_valid()

    # ── Public API ─────────────────────────────────────────────────────────────

    def raw_value(self) -> str:
        """Return the current typed value (may be partial/invalid)."""
        if self._mode == "mac":
            return self._mac_edit.get_value()
        return self._ip_widget.get_value()

    def mode(self) -> str:
        """Return 'mac' or 'ip'."""
        return self._mode

    def is_valid(self) -> bool:
        return self._is_valid()

    def value(self) -> str | None:
        """Return validated value, or None if invalid."""
        return self.raw_value() if self._is_valid() else None

    def clear(self):
        self._mac_edit.clear()
        self._ip_widget.clear()
        self._valid_lbl.setText("")