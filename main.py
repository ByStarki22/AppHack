import sys
from app.UI.MainUI import Interfaz

from PySide6.QtWidgets import QApplication

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ventana = Interfaz()
    ventana.showMaximized()
    sys.exit(app.exec())
