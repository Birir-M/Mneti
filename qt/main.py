import sys
import os
import logging
from PyQt6.QtWidgets import QApplication

# Add current directory to path to allow 'import qt'
sys.path.insert(0, os.getcwd())

from qt.main_window import MainWindow

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Mneti")
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
