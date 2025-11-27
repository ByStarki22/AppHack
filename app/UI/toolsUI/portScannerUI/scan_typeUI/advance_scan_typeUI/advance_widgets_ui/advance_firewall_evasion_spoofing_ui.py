from PySide6.QtWidgets import (
    QGroupBox, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit,
    QLabel
)
from PySide6.QtCore import Qt

class FirewallEvasionOptionsUI(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Firewall / IDS Evasion and Spoofing", parent)
        self.init_ui()

    def init_ui(self):
        self.setCursor(Qt.ArrowCursor)
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Opciones actuales + nuevas opciones añadidas

        self.checkbox_f = QCheckBox("Solicita escaneo con paquetes IP fragmentados")
        self.checkbox_f.setCursor(Qt.PointingHandCursor)

        self.checkbox_mtu = QCheckBox("Configura el tamaño del offset para fragmentación")
        self.checkbox_mtu.setCursor(Qt.PointingHandCursor)
        self.input_mtu = QLineEdit()
        self.input_mtu.setEnabled(False)
        self.input_mtu.setPlaceholderText("Ej: 32")

        self.checkbox_D = QCheckBox("Envía escaneos desde IPs falsificadas (spoofed)")
        self.checkbox_D.setCursor(Qt.PointingHandCursor)
        self.input_D = QLineEdit()
        self.input_D.setEnabled(False)
        self.input_D.setPlaceholderText("IPs separadas por comas")

        self.checkbox_S = QCheckBox("Escanea usando IP fuente falsificada (spoofing)")
        self.checkbox_S.setCursor(Qt.PointingHandCursor)
        self.input_S = QLineEdit()
        self.input_S.setEnabled(False)
        self.input_S.setPlaceholderText("Ej: 192.168.1.100")

        self.checkbox_e = QCheckBox("Usar interfaz de red específica")
        self.checkbox_e.setCursor(Qt.PointingHandCursor)
        self.input_e = QLineEdit()
        self.input_e.setEnabled(False)
        self.input_e.setPlaceholderText("Ej: eth0")

        self.checkbox_g = QCheckBox("Usa un puerto de origen específico")
        self.checkbox_g.setCursor(Qt.PointingHandCursor)
        self.input_g = QLineEdit()
        self.input_g.setEnabled(False)
        self.input_g.setPlaceholderText("Ej: 53")

        self.checkbox_data = QCheckBox("Añade datos binarios hex personalizados a los paquetes")
        self.checkbox_data.setCursor(Qt.PointingHandCursor)
        self.input_data = QLineEdit()
        self.input_data.setEnabled(False)
        self.input_data.setPlaceholderText("Ej: 4a6f686e")

        self.checkbox_data_string = QCheckBox("Añade cadena personalizada a los paquetes")
        self.checkbox_data_string.setCursor(Qt.PointingHandCursor)
        self.input_data_string = QLineEdit()
        self.input_data_string.setEnabled(False)
        self.input_data_string.setPlaceholderText("Ej: hola_mundo")

        self.checkbox_ip_options = QCheckBox("Añade opciones IP personalizadas")
        self.checkbox_ip_options.setCursor(Qt.PointingHandCursor)
        self.input_ip_options = QLineEdit()
        self.input_ip_options.setEnabled(False)
        self.input_ip_options.setPlaceholderText("Ej: R, T")

        self.checkbox_ttl = QCheckBox("Establece valor TTL en paquetes IP")
        self.checkbox_ttl.setCursor(Qt.PointingHandCursor)
        self.input_ttl = QLineEdit()
        self.input_ttl.setEnabled(False)
        self.input_ttl.setPlaceholderText("Ej: 128")

        self.checkbox_randomize_hosts = QCheckBox("Aleatoriza orden de hosts a escanear")
        self.checkbox_randomize_hosts.setCursor(Qt.PointingHandCursor)

        self.checkbox_spoof_mac = QCheckBox("Falsifica dirección MAC")
        self.checkbox_spoof_mac.setCursor(Qt.PointingHandCursor)
        self.input_spoof_mac = QLineEdit()
        self.input_spoof_mac.setEnabled(False)
        self.input_spoof_mac.setPlaceholderText("Ej: 00:11:22:33:44:55")

        self.checkbox_proxies = QCheckBox("Reenvía conexiones a través de proxies HTTP/SOCKS4")
        self.checkbox_proxies.setCursor(Qt.PointingHandCursor)
        self.input_proxies = QLineEdit()
        self.input_proxies.setEnabled(False)
        self.input_proxies.setPlaceholderText("http://ip:puerto,...")

        self.checkbox_badsum = QCheckBox("Envía paquetes con checksums inválidos")
        self.checkbox_badsum.setCursor(Qt.PointingHandCursor)

        self.checkbox_adler32 = QCheckBox("Usa checksum Adler32 para SCTP (obsoleto)")
        self.checkbox_adler32.setCursor(Qt.PointingHandCursor)

        self.checkbox_data_length = QCheckBox("Agrega datos aleatorios a los paquetes enviados")
        self.checkbox_data_length.setCursor(Qt.PointingHandCursor)
        self.input_data_length = QLineEdit()
        self.input_data_length.setEnabled(False)
        self.input_data_length.setPlaceholderText("Ej: 200")

        self.checkboxes = [
            self.checkbox_f, self.checkbox_mtu, self.checkbox_D,
            self.checkbox_S, self.checkbox_e, self.checkbox_g,
            self.checkbox_data, self.checkbox_data_string,
            self.checkbox_ip_options, self.checkbox_ttl,
            self.checkbox_randomize_hosts, self.checkbox_spoof_mac,
            self.checkbox_proxies, self.checkbox_badsum,
            self.checkbox_adler32, self.checkbox_data_length
        ]

        self._align_checkboxes_width()

        layout.addWidget(self.checkbox_f)  # Sin input para esta opción

        layout.addLayout(self._hbox(self.checkbox_mtu, self.input_mtu))
        layout.addLayout(self._hbox(self.checkbox_D, self.input_D))
        layout.addLayout(self._hbox(self.checkbox_S, self.input_S))
        layout.addLayout(self._hbox(self.checkbox_e, self.input_e))
        layout.addLayout(self._hbox(self.checkbox_g, self.input_g))
        layout.addLayout(self._hbox(self.checkbox_data, self.input_data))
        layout.addLayout(self._hbox(self.checkbox_data_string, self.input_data_string))
        layout.addLayout(self._hbox(self.checkbox_ip_options, self.input_ip_options))
        layout.addLayout(self._hbox(self.checkbox_ttl, self.input_ttl))
        layout.addWidget(self.checkbox_randomize_hosts)
        layout.addLayout(self._hbox(self.checkbox_spoof_mac, self.input_spoof_mac))
        layout.addLayout(self._hbox(self.checkbox_proxies, self.input_proxies))
        layout.addWidget(self.checkbox_badsum)
        layout.addWidget(self.checkbox_adler32)
        layout.addLayout(self._hbox(self.checkbox_data_length, self.input_data_length))

        self.setLayout(layout)

        # Conectar checkboxes para habilitar inputs
        self.checkbox_mtu.toggled.connect(lambda c: self.enable_input(self.input_mtu, c))
        self.checkbox_D.toggled.connect(lambda c: self.enable_input(self.input_D, c))
        self.checkbox_S.toggled.connect(lambda c: self.enable_input(self.input_S, c))
        self.checkbox_e.toggled.connect(lambda c: self.enable_input(self.input_e, c))
        self.checkbox_g.toggled.connect(lambda c: self.enable_input(self.input_g, c))
        self.checkbox_data.toggled.connect(lambda c: self.enable_input(self.input_data, c))
        self.checkbox_data_string.toggled.connect(lambda c: self.enable_input(self.input_data_string, c))
        self.checkbox_ip_options.toggled.connect(lambda c: self.enable_input(self.input_ip_options, c))
        self.checkbox_ttl.toggled.connect(lambda c: self.enable_input(self.input_ttl, c))
        self.checkbox_spoof_mac.toggled.connect(lambda c: self.enable_input(self.input_spoof_mac, c))
        self.checkbox_proxies.toggled.connect(lambda c: self.enable_input(self.input_proxies, c))
        self.checkbox_data_length.toggled.connect(lambda c: self.enable_input(self.input_data_length, c))

        # Actualizar estilo inputs
        inputs = [
            self.input_mtu, self.input_D, self.input_S,
            self.input_e, self.input_g, self.input_data,
            self.input_data_string, self.input_ip_options,
            self.input_ttl, self.input_spoof_mac,
            self.input_proxies, self.input_data_length
        ]
        for inp in inputs:
            inp.textChanged.connect(lambda _, i=inp: self.update_input_style(i))

    def _hbox(self, *widgets):
        box = QHBoxLayout()
        for i, w in enumerate(widgets):
            box.addWidget(w)
            box.setStretch(i, 1 if i > 0 else 0)
        return box

    def _align_checkboxes_width(self):
        max_width = max(cb.sizeHint().width() for cb in self.checkboxes)
        max_width += 80
        for cb in self.checkboxes:
            cb.setFixedWidth(max_width)

    def enable_input(self, input_widget, enable):
        input_widget.setEnabled(enable)
        self.update_input_style(input_widget)

    def update_input_style(self, input_widget):
        if not input_widget.isEnabled() and input_widget.text():
            input_widget.setStyleSheet("color: gray;")
        else:
            input_widget.setStyleSheet("")

    def get_selected_options(self):
        options = []
        if self.checkbox_f.isChecked():
            options.append("-f")
        if self.checkbox_mtu.isChecked():
            val = self.input_mtu.text().strip()
            if val:
                options.append(f"--mtu {val}")
        if self.checkbox_D.isChecked():
            val = self.input_D.text().strip()
            if val:
                options.append(f"-D {val}")
        if self.checkbox_S.isChecked():
            val = self.input_S.text().strip()
            if val:
                options.append(f"-S {val}")
        if self.checkbox_e.isChecked():
            val = self.input_e.text().strip()
            if val:
                options.append(f"-e {val}")
        if self.checkbox_g.isChecked():
            val = self.input_g.text().strip()
            if val:
                options.append(f"-g {val}")
        if self.checkbox_data.isChecked():
            val = self.input_data.text().strip()
            if val:
                options.append(f"--data {val}")
        if self.checkbox_data_string.isChecked():
            val = self.input_data_string.text().strip()
            if val:
                options.append(f"--data-string {val}")
        if self.checkbox_ip_options.isChecked():
            val = self.input_ip_options.text().strip()
            if val:
                options.append(f"--ip-options {val}")
        if self.checkbox_ttl.isChecked():
            val = self.input_ttl.text().strip()
            if val:
                options.append(f"--ttl {val}")
        if self.checkbox_randomize_hosts.isChecked():
            options.append("--randomize-hosts")
        if self.checkbox_spoof_mac.isChecked():
            val = self.input_spoof_mac.text().strip()
            if val:
                options.append(f"--spoof-mac {val}")
        if self.checkbox_proxies.isChecked():
            val = self.input_proxies.text().strip()
            if val:
                options.append(f"--proxies {val}")
        if self.checkbox_badsum.isChecked():
            options.append("--badsum")
        if self.checkbox_adler32.isChecked():
            options.append("--adler32")
        if self.checkbox_data_length.isChecked():
            val = self.input_data_length.text().strip()
            if val:
                options.append(f"--data-length {val}")
        return options
