
LIGHT_STYLE = """
QMainWindow {
    background-color: #ffffff;
}
QWidget {
    font-family: "Segoe UI", Roboto, Arial, sans-serif;
    font-size: 13px;
    color: #212529;
}
/* Sidebar */
#Sidebar {
    background-color: #f8f9fa;
    border-right: 1px solid #dee2e6;
    min-width: 200px;
}
#Sidebar QPushButton {
    text-align: left;
    padding: 10px 15px;
    border: none;
    border-radius: 5px;
    margin: 2px 10px;
    font-weight: 500;
}
#Sidebar QPushButton:hover {
    background-color: #e9ecef;
}
#Sidebar QPushButton[active="true"] {
    background-color: #0366d6;
    color: white;
}
/* Panels */
#Panel {
    background-color: #ffffff;
    border: 1px solid #dee2e6;
    border-radius: 5px;
}
#PanelTitle {
    font-weight: bold;
    font-size: 14px;
    border-bottom: 1px solid #f1f1f1;
    padding-bottom: 5px;
}
/* Buttons */
QPushButton {
    background-color: #f8f9fa;
    border: 1px solid #ced4da;
    border-radius: 4px;
    padding: 6px 12px;
}
QPushButton:hover {
    background-color: #e2e6ea;
}
QPushButton#Primary {
    background-color: #343a40;
    color: white;
    border-color: #343a40;
}
QPushButton#Primary:hover {
    background-color: #23272b;
}
/* Table */
QTableWidget {
    border: 1px solid #dee2e6;
    gridline-color: #f1f1f1;
    selection-background-color: #e8f4fd;
    selection-color: #212529;
}
QHeaderView::section {
    background-color: #e9ecef;
    padding: 8px;
    border: 1px solid #dee2e6;
    font-weight: bold;
}
"""

DARK_STYLE = """
QMainWindow {
    background-color: #1a1a1a;
}
QWidget {
    font-family: "Segoe UI", Roboto, Arial, sans-serif;
    font-size: 13px;
    color: #e0e0e0;
}
/* Sidebar */
#Sidebar {
    background-color: #2d2d2d;
    border-right: 1px solid #404040;
    min-width: 200px;
}
#Sidebar QPushButton {
    text-align: left;
    padding: 10px 15px;
    border: none;
    border-radius: 5px;
    margin: 2px 10px;
    font-weight: 500;
    color: #e0e0e0;
}
#Sidebar QPushButton:hover {
    background-color: #404040;
}
#Sidebar QPushButton[active="true"] {
    background-color: #0366d6;
    color: white;
}
/* Panels */
#Panel {
    background-color: #2d2d2d;
    border: 1px solid #404040;
    border-radius: 5px;
}
#PanelTitle {
    font-weight: bold;
    font-size: 14px;
    border-bottom: 1px solid #404040;
    padding-bottom: 5px;
    color: #ffffff;
}
/* Buttons */
QPushButton {
    background-color: #404040;
    border: 1px solid #555555;
    border-radius: 4px;
    padding: 6px 12px;
    color: #e0e0e0;
}
QPushButton:hover {
    background-color: #505050;
}
QPushButton#Primary {
    background-color: #0366d6;
    color: white;
    border-color: #0366d6;
}
QPushButton#Primary:hover {
    background-color: #0056b3;
}
/* Table */
QTableWidget {
    background-color: #2d2d2d;
    border: 1px solid #404040;
    gridline-color: #404040;
    selection-background-color: #0366d6;
    selection-color: white;
    color: #e0e0e0;
}
QHeaderView::section {
    background-color: #404040;
    padding: 8px;
    border: 1px solid #555555;
    font-weight: bold;
    color: #ffffff;
}
QLineEdit {
    background-color: #404040;
    border: 1px solid #555555;
    color: #ffffff;
    padding: 5px;
}
"""

BADGE_STYLES = {
    "managed": "background-color: #e8f4fd; border: 1px solid #bbeeef; color: #0366d6; font-size: 10px; font-weight: bold; border-radius: 3px; padding: 2px 6px;",
    "relayed": "background-color: #eef9f0; border: 1px solid #cce8cc; color: #28a745; font-size: 10px; font-weight: bold; border-radius: 3px; padding: 2px 6px;",
    "unmanaged": "background-color: #fff0f0; border: 1px solid #ffcccc; color: #dc3545; font-size: 10px; font-weight: bold; border-radius: 3px; padding: 2px 6px;",
    "unmanaged_hotspot": "background-color: #fff9db; border: 1px solid #ffe066; color: #c87800; font-size: 10px; font-weight: bold; border-radius: 3px; padding: 2px 6px;",
}
