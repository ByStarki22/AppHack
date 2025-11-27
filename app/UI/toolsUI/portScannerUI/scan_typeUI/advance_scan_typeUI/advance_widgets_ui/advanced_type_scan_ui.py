from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QComboBox, QCheckBox, QHBoxLayout, QSizePolicy
)
from PySide6.QtCore import Qt


class NoWheelComboBox(QComboBox):
    def wheelEvent(self, event):
        if self.view().isVisible():
            # Solo procesar la rueda si el desplegable está abierto
            super().wheelEvent(event)
        else:
            # Ignorar el evento rueda si el desplegable está cerrado
            event.ignore()


class ScanTechniquesUI(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        group = QGroupBox("Método de escaneo")
        group_layout = QVBoxLayout()
        group.setLayout(group_layout)

        # Layout horizontal para checkbox + combo
        h_layout = QHBoxLayout()

        self.checkbox = QCheckBox()
        self.checkbox.setChecked(False)  # Checkbox NO marcado por defecto
        self.checkbox.toggled.connect(self.toggle_combo)
        self.checkbox.setCursor(Qt.PointingHandCursor)  # <-- cursor de mano en checkbox

        self.combo_box = NoWheelComboBox()

        # Lista completa de técnicas de escaneo con su descripción
        scan_methods = [
            ("TCP SYN", "-sS"),
            ("TCP Connect", "-sT"),
            ("UDP", "-sU"),
            ("SCTP INIT", "-sY"),
            ("SCTP COOKIE ECHO", "-sZ"),
            ("TCP NULL", "-sN"),
            ("TCP FIN", "-sF"),
            ("TCP Xmas", "-sX"),
            ("TCP ACK", "-sA"),
            ("TCP Window", "-sW"),
            ("TCP Maimon", "-sM"),
            ("Custom TCP Flags", "--scanflags"),
            ("Idle scan (zombie)", "-sI <zombie>"),
            ("IP protocol scan", "-sO"),
            ("FTP bounce scan", "-b <ftp relay>")
        ]

        # Agregamos los items con etiquetas que incluyan el flag
        for name, flag in scan_methods:
            self.combo_box.addItem(f"{name} ({flag})")

        self.combo_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        h_layout.addWidget(self.checkbox)
        h_layout.addWidget(self.combo_box)
        # El checkbox no se expande, el combo sí
        h_layout.setStretch(0, 0)
        h_layout.setStretch(1, 1)

        group_layout.addLayout(h_layout)
        layout.addWidget(group)

        layout.addStretch()

        # Ajustar estado inicial del combo según checkbox
        self.toggle_combo(self.checkbox.isChecked())

    def toggle_combo(self, checked):
        self.combo_box.setEnabled(checked)
        if checked:
            self.combo_box.setStyleSheet("color: white;")
        else:
            self.combo_box.setStyleSheet("color: gray;")
