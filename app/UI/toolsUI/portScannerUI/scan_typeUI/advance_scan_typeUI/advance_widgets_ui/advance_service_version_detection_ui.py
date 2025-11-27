from PySide6.QtWidgets import (
    QGroupBox, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit
)
from PySide6.QtCore import Qt


class ServiceVersionDetectionUI(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Detección de Servicio y Versión", parent)
        self.init_ui()

    def init_ui(self):
        self.setCursor(Qt.ArrowCursor)
        layout = QVBoxLayout()
        layout.setSpacing(8)

        # Opción -sV
        self.checkbox_sV = QCheckBox("Detectar versión de servicio")

        # Opción --allports
        self.checkbox_allports = QCheckBox("Escanear todos los puertos (--allports)")

        # Opción -sV --version-intensity
        self.checkbox_version_intensity = QCheckBox("Intensidad de versión")
        self.input_version_intensity = QLineEdit()
        self.input_version_intensity.setPlaceholderText("Nivel de intensidad 0 a 9 (Ejemplo: 8)")
        self.input_version_intensity.setEnabled(False)

        # Opción -sV --version-light
        self.checkbox_version_light = QCheckBox("Modo ligero")

        # Opción -sV --version-all
        self.checkbox_version_all = QCheckBox("Modo intensidad máxima")

        # Opción --version-trace
        self.checkbox_version_trace = QCheckBox("Traza actividad versión (--version-trace)")

        # Opción -A
        self.checkbox_A = QCheckBox("Detección completa")

        # Lista de checkboxes
        self.checkboxes = [
            self.checkbox_sV,
            self.checkbox_allports,
            self.checkbox_version_intensity,
            self.checkbox_version_light,
            self.checkbox_version_all,
            self.checkbox_version_trace,
            self.checkbox_A,
        ]

        # Cursor de mano para todos
        for cb in self.checkboxes:
            cb.setCursor(Qt.PointingHandCursor)

        # Alineación de ancho para checkbox con input
        self._align_checkboxes_width()

        # Layouts
        layout.addWidget(self.checkbox_sV)
        layout.addWidget(self.checkbox_allports)
        layout.addLayout(self._hbox(self.checkbox_version_intensity, self.input_version_intensity))
        layout.addWidget(self.checkbox_version_light)
        layout.addWidget(self.checkbox_version_all)
        layout.addWidget(self.checkbox_version_trace)
        layout.addWidget(self.checkbox_A)

        self.setLayout(layout)

        # Conexiones para habilitar inputs
        self.checkbox_version_intensity.toggled.connect(
            lambda checked: self.enable_input(self.input_version_intensity, checked)
        )

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

    def _hbox(self, *widgets):
        box = QHBoxLayout()
        for i, w in enumerate(widgets):
            box.addWidget(w)
            box.setStretch(i, 0 if i == 0 else 1)
        return box

    def _align_checkboxes_width(self):
        checkboxes_with_inputs = [self.checkbox_version_intensity]
        max_width = max(cb.sizeHint().width() for cb in checkboxes_with_inputs)
        max_width += 80
        for cb in checkboxes_with_inputs:
            cb.setFixedWidth(max_width)

    def get_selected_options(self):
        options = []
        if self.checkbox_sV.isChecked():
            options.append("-sV")
        if self.checkbox_allports.isChecked():
            options.append("--allports")
        if self.checkbox_version_intensity.isChecked():
            intensity = self.input_version_intensity.text().strip()
            if intensity.isdigit() and 0 <= int(intensity) <= 9:
                options.append(f"--version-intensity {intensity}")
            else:
                options.append("--version-intensity")
        if self.checkbox_version_light.isChecked():
            options.append("--version-light")
        if self.checkbox_version_all.isChecked():
            options.append("--version-all")
        if self.checkbox_version_trace.isChecked():
            options.append("--version-trace")
        if self.checkbox_A.isChecked():
            options.append("-A")
        return " ".join(options) if options else None
