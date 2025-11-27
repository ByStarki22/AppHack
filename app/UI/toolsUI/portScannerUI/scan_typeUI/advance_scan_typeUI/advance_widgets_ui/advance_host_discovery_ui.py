from PySide6.QtWidgets import (
    QGroupBox, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit, QLabel
)
from PySide6.QtCore import Qt


class HostDiscoveryOptionsUI(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Descubrimiento de Host", parent)
        self.init_ui()

    def init_ui(self):
        self.setCursor(Qt.ArrowCursor)
        layout = QVBoxLayout()
        layout.setSpacing(10)

        self.check_sL = QCheckBox("Lista solo de objetivos (Sin escaneo)")
        self.check_sn = QCheckBox("Solo detección de host (Desactivar el escaneo de puertos)")
        self.check_Pn = QCheckBox("Solo escaneo de puertos (Deshabilitar la detección de host)")

        self.check_PS = QCheckBox("Descubrimiento TCP SYN")
        self.input_PS_ports = QLineEdit()
        self.input_PS_ports.setPlaceholderText("Puerto 80 por defecto")
        self.input_PS_ports.setEnabled(False)

        self.check_PA = QCheckBox("Descubrimiento TCP ACK")
        self.input_PA_ports = QLineEdit()
        self.input_PA_ports.setPlaceholderText("Puerto 80 por defecto")
        self.input_PA_ports.setEnabled(False)

        self.check_PU = QCheckBox("Descubrimiento UDP")
        self.input_PU_ports = QLineEdit()
        self.input_PU_ports.setPlaceholderText("Puerto 40125 por defecto")
        self.input_PU_ports.setEnabled(False)

        self.check_PY = QCheckBox("Descubrimiento SCTP INIT (root solo)")

        self.check_PE = QCheckBox("ICMP Echo Request (-PE)")
        self.check_PP = QCheckBox("ICMP Timestamp Request (-PP)")
        self.check_PM = QCheckBox("ICMP Netmask Request (-PM)")

        self.check_PO = QCheckBox("Descubrimiento IP protocol ping (-PO)")

        self.check_disable_arp_ping = QCheckBox("Deshabilitar ping ARP/ND (--disable-arp-ping)")
        self.check_discovery_ignore_rst = QCheckBox("Ignorar TCP RST falsificados (--discovery-ignore-rst)")
        self.check_traceroute = QCheckBox("Ejecutar traceroute después del escaneo (--traceroute)")

        self.check_PR = QCheckBox("Descubrimiento ARP (red local)")
        self.check_n = QCheckBox("Sin resolución DNS")

        for cb in [self.check_sL, self.check_sn, self.check_Pn, self.check_PS, self.check_PA,
                   self.check_PU, self.check_PY, self.check_PE, self.check_PP, self.check_PM,
                   self.check_PO, self.check_disable_arp_ping, self.check_discovery_ignore_rst,
                   self.check_traceroute, self.check_PR, self.check_n]:
            cb.setCursor(Qt.PointingHandCursor)

        self.check_boxes = [
            self.check_sL, self.check_sn, self.check_Pn, self.check_PS, self.check_PA,
            self.check_PU, self.check_PY, self.check_PE, self.check_PP, self.check_PM,
            self.check_PO, self.check_disable_arp_ping, self.check_discovery_ignore_rst,
            self.check_traceroute, self.check_PR, self.check_n
        ]
        self._align_checkboxes_width()

        layout.addWidget(self.check_sL)
        layout.addWidget(self.check_sn)
        layout.addWidget(self.check_Pn)
        layout.addLayout(self._hbox(self.check_PS, self.input_PS_ports))
        layout.addLayout(self._hbox(self.check_PA, self.input_PA_ports))
        layout.addLayout(self._hbox(self.check_PU, self.input_PU_ports))
        layout.addWidget(self.check_PY)

        # Aquí usamos un QVBoxLayout para las opciones ICMP
        icmp_layout = QVBoxLayout()
        icmp_layout.addWidget(self.check_PE)
        icmp_layout.addWidget(self.check_PP)
        icmp_layout.addWidget(self.check_PM)
        layout.addLayout(icmp_layout)

        layout.addWidget(self.check_PO)
        layout.addWidget(self.check_disable_arp_ping)
        layout.addWidget(self.check_discovery_ignore_rst)
        layout.addWidget(self.check_traceroute)
        layout.addWidget(self.check_PR)
        layout.addWidget(self.check_n)

        self.setLayout(layout)

        # Conexiones para habilitar/deshabilitar inputs y actualizar estilo
        self.check_PS.toggled.connect(lambda c: self.enable_input(self.input_PS_ports, c))
        self.check_PA.toggled.connect(lambda c: self.enable_input(self.input_PA_ports, c))
        self.check_PU.toggled.connect(lambda c: self.enable_input(self.input_PU_ports, c))

        # Inicializar estilo de inputs
        self.update_input_style(self.input_PS_ports)
        self.update_input_style(self.input_PA_ports)
        self.update_input_style(self.input_PU_ports)

    def _hbox(self, *widgets):
        box = QHBoxLayout()
        for i, w in enumerate(widgets):
            box.addWidget(w)
            box.setStretch(i, 0 if i == 0 else 1)
        return box

    def _align_checkboxes_width(self):
        max_width = max(cb.sizeHint().width() for cb in self.check_boxes)
        max_width += 90
        for cb in self.check_boxes:
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

    def get_selected_options(self):
        options = []
        if self.check_sL.isChecked():
            options.append("-sL")
        if self.check_sn.isChecked():
            options.append("-sn")
        if self.check_Pn.isChecked():
            options.append("-Pn")
        if self.check_PS.isChecked():
            ports = self.input_PS_ports.text().strip()
            options.append(f"-PS{ports}" if ports else "-PS")
        if self.check_PA.isChecked():
            ports = self.input_PA_ports.text().strip()
            options.append(f"-PA{ports}" if ports else "-PA")
        if self.check_PU.isChecked():
            ports = self.input_PU_ports.text().strip()
            options.append(f"-PU{ports}" if ports else "-PU")
        if self.check_PY.isChecked():
            options.append("-PY")
        if self.check_PE.isChecked():
            options.append("-PE")
        if self.check_PP.isChecked():
            options.append("-PP")
        if self.check_PM.isChecked():
            options.append("-PM")
        if self.check_PO.isChecked():
            options.append("-PO")
        if self.check_disable_arp_ping.isChecked():
            options.append("--disable-arp-ping")
        if self.check_discovery_ignore_rst.isChecked():
            options.append("--discovery-ignore-rst")
        if self.check_traceroute.isChecked():
            options.append("--traceroute")
        if self.check_PR.isChecked():
            options.append("-PR")
        if self.check_n.isChecked():
            options.append("-n")
        return options
