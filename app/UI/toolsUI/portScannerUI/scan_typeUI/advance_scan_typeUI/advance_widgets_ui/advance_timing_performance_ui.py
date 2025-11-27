from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QComboBox, QCheckBox, QHBoxLayout, QSizePolicy
)
from PySide6.QtCore import Qt


class NoWheelComboBox(QComboBox):
    def wheelEvent(self, event):
        if self.view().isVisible():
            super().wheelEvent(event)
        else:
            event.ignore()


class TimingPerformanceSelectorUI(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        group = QGroupBox("Timing and Performance")
        group_layout = QVBoxLayout()
        group.setLayout(group_layout)

        h_layout = QHBoxLayout()

        self.checkbox = QCheckBox()
        self.checkbox.setChecked(False)
        self.checkbox.toggled.connect(self.toggle_combo)
        self.checkbox.setCursor(Qt.PointingHandCursor)

        self.combo_timing = NoWheelComboBox()
        self.combo_timing.addItem("-T0 - Evasión paranoica del sistema de detección de intrusos")
        self.combo_timing.addItem("-T1 - Evasión sigilosa del sistema de detección de intrusos")
        self.combo_timing.addItem("-T2 - Cortés, reduce la velocidad del escaneo para usar menos ancho de banda y menos recursos de la máquina objetivo")
        self.combo_timing.addItem("-T3 - Normal, que es la velocidad predeterminada", "-T3")
        self.combo_timing.addItem("-T4 - Agresivo, acelera los escaneos; asume que estás en una red razonablemente rápida y confiable")
        self.combo_timing.addItem("-T5 - Insano, velocidad extrema de escaneo; asume que estás en una red extraordinariamente rápida")
        self.combo_timing.setCurrentIndex(3)
        self.combo_timing.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        h_layout.addWidget(self.checkbox)
        h_layout.addWidget(self.combo_timing)
        h_layout.setStretch(0, 0)
        h_layout.setStretch(1, 1)

        group_layout.addLayout(h_layout)
        layout.addWidget(group)
        layout.addStretch()

        self.toggle_combo(self.checkbox.isChecked())

    def toggle_combo(self, checked):
        self.combo_timing.setEnabled(checked)
        self.combo_timing.setStyleSheet("color: white;" if checked else "color: gray;")

    def get_selected_timing(self):
        if self.checkbox.isChecked():
            return self.combo_timing.currentData()
        return None
