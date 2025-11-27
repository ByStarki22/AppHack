from PySide6.QtWidgets import (
    QGroupBox, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit
)
from PySide6.QtCore import Qt


class OSDetectionSelectorUI(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Detección de Sistema Operativo", parent)
        self.init_ui()

    def init_ui(self):
        self.setCursor(Qt.ArrowCursor)
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Crear checkboxes
        self.check_O = QCheckBox("Remote OS detection")
        self.check_osscan_limit = QCheckBox("OS scan limit")
        self.check_osscan_guess = QCheckBox("OS scan guess")
        self.check_max_os_tries = QCheckBox("Max OS tries")
        self.check_A = QCheckBox("Escaneo agresivo")

        # Asignar cursor de mano
        self.checkboxes = [
            self.check_O, self.check_osscan_limit, self.check_osscan_guess,
            self.check_max_os_tries, self.check_A
        ]
        for cb in self.checkboxes:
            cb.setCursor(Qt.PointingHandCursor)

        # Campo de entrada para max-os-tries
        self.input_max_os_tries_num = QLineEdit()
        self.input_max_os_tries_num.setPlaceholderText("Número máximo de intentos")
        self.input_max_os_tries_num.setEnabled(False)

        # Aplicar estilo inicial
        self.update_input_style(self.input_max_os_tries_num)

        # Alinear checkboxes
        self._align_checkboxes_width()

        # Añadir al layout
        layout.addWidget(self.check_O)
        layout.addWidget(self.check_osscan_limit)
        layout.addWidget(self.check_osscan_guess)
        layout.addLayout(self._hbox(self.check_max_os_tries, self.input_max_os_tries_num))
        layout.addWidget(self.check_A)

        self.setLayout(layout)

        # Conexión con función personalizada
        self.check_max_os_tries.toggled.connect(
            lambda checked: self.enable_input(self.input_max_os_tries_num, checked)
        )

    def _hbox(self, *widgets):
        box = QHBoxLayout()
        for i, w in enumerate(widgets):
            box.addWidget(w)
            box.setStretch(i, 0 if i == 0 else 1)
        return box

    def _align_checkboxes_width(self):
        max_width = max(cb.sizeHint().width() for cb in self.checkboxes)
        max_width += 80  # margen
        for cb in self.checkboxes:
            cb.setFixedWidth(max_width)

    def enable_input(self, input_widget, enable):
        input_widget.setEnabled(enable)
        self.update_input_style(input_widget)

    def update_input_style(self, input_widget):
        if not input_widget.isEnabled() and input_widget.text():
            input_widget.setStyleSheet("""
                color: gray;
                QLineEdit::placeholder {
                    color: lightgray;
                }
            """)
        else:
            input_widget.setStyleSheet("""
                color: white;
                QLineEdit::placeholder {
                    color: lightgray;
                }
            """)

    def get_selected_os_command(self):
        command = "nmap"

        if self.check_O.isChecked():
            command += " -O"
        if self.check_osscan_limit.isChecked():
            command += " --osscan-limit"
        if self.check_osscan_guess.isChecked():
            command += " --osscan-guess"
        if self.check_max_os_tries.isChecked():
            tries = self.input_max_os_tries_num.text().strip()
            if tries:
                command += f" --max-os-tries {tries}"
        if self.check_A.isChecked():
            command += " -A"

        return command if command != "nmap" else None
