import sys
from app.UI.MainUI import Interfaz

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import qInstallMessageHandler, QtMsgType

# Filtrar warnings de Qt que no afectan la funcionalidad
def qt_message_handler(mode, context, message):
    if mode == QtMsgType.QtWarningMsg:
        # Filtrar warnings conocidos de Qt
        ignored_patterns = [
            "QPainter::",
            "Unknown property",
        ]
        if any(pattern in message for pattern in ignored_patterns):
            return
    # Imprimir otros mensajes normalmente
    print(message)

if __name__ == "__main__":
    qInstallMessageHandler(qt_message_handler)
    app = QApplication(sys.argv)
    ventana = Interfaz()
    ventana.showMaximized()
    sys.exit(app.exec())
