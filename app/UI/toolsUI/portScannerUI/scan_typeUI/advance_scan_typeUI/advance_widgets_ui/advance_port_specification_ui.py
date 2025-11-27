from PySide6.QtWidgets import (
    QGroupBox, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit, QLabel
)
from PySide6.QtCore import Qt


class PortSpecificationUI(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Especificación de Puertos", parent)
        self.init_ui()

    def init_ui(self):
        self.setCursor(Qt.ArrowCursor)
        layout = QVBoxLayout()
        layout.setSpacing(8)

        self.chk_single_port = QCheckBox("Escanear puerto único")
        self.input_single_port = QLineEdit()
        self.input_single_port.setPlaceholderText("Ejemplo: 21")
        self.input_single_port.setEnabled(False)

        self.chk_port_range = QCheckBox("Escanear rango de puertos")
        self.input_port_range_start = QLineEdit()
        self.input_port_range_start.setPlaceholderText("Puerto inicio")
        self.input_port_range_start.setEnabled(False)
        self.input_port_range_end = QLineEdit()
        self.input_port_range_end.setPlaceholderText("Puerto fin")
        self.input_port_range_end.setEnabled(False)

        self.chk_multi_tcp_udp = QCheckBox("Escanear puertos TCP y UDP múltiple")
        self.input_multi_udp = QLineEdit()
        self.input_multi_udp.setPlaceholderText("UDP Ejemplo: 53")
        self.input_multi_udp.setEnabled(False)
        self.input_multi_tcp = QLineEdit()
        self.input_multi_tcp.setPlaceholderText("TCP Ejemplo: 21-25,80")
        self.input_multi_tcp.setEnabled(False)

        self.chk_all_ports = QCheckBox("Escanear todos los puertos")

        self.chk_service_names = QCheckBox("Escanear por nombres de servicios")
        self.input_service_names = QLineEdit()
        self.input_service_names.setPlaceholderText("Ejemplo: http,https")
        self.input_service_names.setEnabled(False)

        self.chk_fast_scan = QCheckBox("Escaneo rápido (100 puertos)")

        self.chk_top_ports = QCheckBox("Escanear los principales puertos")
        self.input_top_ports = QLineEdit()
        self.input_top_ports.setPlaceholderText("Ejemplo: 2000")
        self.input_top_ports.setEnabled(False)

        self.chk_full_range = QCheckBox("Escanear desde puerto 1 hasta 65535")
        self.chk_from_zero = QCheckBox("Escanear desde puerto 0 hasta fin")

        # NUEVO: Exclusión de puertos
        self.chk_exclude_ports = QCheckBox("Excluir puertos")
        self.input_exclude_ports = QLineEdit()
        self.input_exclude_ports.setPlaceholderText("Ejemplo: 80,443,1000-2000")
        self.input_exclude_ports.setEnabled(False)

        # NUEVO: No randomizar puertos
        self.chk_no_randomize = QCheckBox("Escanear puertos en orden secuencial (no randomizar)")

        # NUEVO: Razón de frecuencia de puertos
        self.chk_port_ratio = QCheckBox("Escanear puertos según ratio de frecuencia")
        self.input_port_ratio = QLineEdit()
        self.input_port_ratio.setPlaceholderText("Ejemplo: 0.5 (0.0 - 1.0)")
        self.input_port_ratio.setEnabled(False)

        self.checkboxes = [
            self.chk_single_port, self.chk_port_range, self.chk_multi_tcp_udp,
            self.chk_all_ports, self.chk_service_names, self.chk_fast_scan,
            self.chk_top_ports, self.chk_full_range, self.chk_from_zero,
            self.chk_exclude_ports,  # NUEVO
            self.chk_no_randomize,   # NUEVO
            self.chk_port_ratio      # NUEVO
        ]

        for cb in self.checkboxes:
            cb.setCursor(Qt.PointingHandCursor)

        self._align_checkboxes_width()

        layout.addLayout(self._hbox(self.chk_single_port, self.input_single_port))

        hbox_port_range = QHBoxLayout()
        hbox_port_range.addWidget(self.chk_port_range)
        hbox_port_range.addWidget(self.input_port_range_start)
        hbox_port_range.addWidget(QLabel("-"))
        hbox_port_range.addWidget(self.input_port_range_end)
        hbox_port_range.setStretch(0, 0)
        hbox_port_range.setStretch(1, 1)
        hbox_port_range.setStretch(2, 0)
        hbox_port_range.setStretch(3, 1)
        layout.addLayout(hbox_port_range)

        hbox_multi_tcp_udp = QHBoxLayout()
        hbox_multi_tcp_udp.addWidget(self.chk_multi_tcp_udp)
        hbox_multi_tcp_udp.addWidget(self.input_multi_udp)
        hbox_multi_tcp_udp.addWidget(QLabel("-"))
        hbox_multi_tcp_udp.addWidget(self.input_multi_tcp)
        hbox_multi_tcp_udp.setStretch(0, 0)
        hbox_multi_tcp_udp.setStretch(1, 1)
        hbox_multi_tcp_udp.setStretch(2, 0)
        hbox_multi_tcp_udp.setStretch(3, 1)
        layout.addLayout(hbox_multi_tcp_udp)

        layout.addWidget(self.chk_all_ports)
        layout.addLayout(self._hbox(self.chk_service_names, self.input_service_names))
        layout.addWidget(self.chk_fast_scan)
        layout.addLayout(self._hbox(self.chk_top_ports, self.input_top_ports))
        layout.addWidget(self.chk_full_range)
        layout.addWidget(self.chk_from_zero)

        # NUEVO: Exclusión de puertos
        layout.addLayout(self._hbox(self.chk_exclude_ports, self.input_exclude_ports))

        # NUEVO: No randomizar
        layout.addWidget(self.chk_no_randomize)

        # NUEVO: Ratio de frecuencia
        layout.addLayout(self._hbox(self.chk_port_ratio, self.input_port_ratio))

        self.setLayout(layout)

        # Conexiones para habilitar/deshabilitar inputs y actualizar estilo
        self.chk_single_port.toggled.connect(lambda c: self.enable_input(self.input_single_port, c))
        self.chk_port_range.toggled.connect(lambda c: self.enable_port_range_inputs(c))
        self.chk_multi_tcp_udp.toggled.connect(lambda c: self.enable_input(self.input_multi_udp, c))
        self.chk_multi_tcp_udp.toggled.connect(lambda c: self.enable_input(self.input_multi_tcp, c))
        self.chk_service_names.toggled.connect(lambda c: self.enable_input(self.input_service_names, c))
        self.chk_top_ports.toggled.connect(lambda c: self.enable_input(self.input_top_ports, c))
        self.chk_exclude_ports.toggled.connect(lambda c: self.enable_input(self.input_exclude_ports, c))  # NUEVO
        self.chk_port_ratio.toggled.connect(lambda c: self.enable_input(self.input_port_ratio, c))        # NUEVO

        # Inicializar estilo de inputs
        self.update_input_style(self.input_single_port)
        self.update_input_style(self.input_port_range_start)
        self.update_input_style(self.input_port_range_end)
        self.update_input_style(self.input_multi_udp)
        self.update_input_style(self.input_multi_tcp)
        self.update_input_style(self.input_service_names)
        self.update_input_style(self.input_top_ports)
        self.update_input_style(self.input_exclude_ports)  # NUEVO
        self.update_input_style(self.input_port_ratio)    # NUEVO

    def enable_port_range_inputs(self, enable):
        self.input_port_range_start.setEnabled(enable)
        self.input_port_range_end.setEnabled(enable)
        self.update_input_style(self.input_port_range_start)
        self.update_input_style(self.input_port_range_end)

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
        max_width = max(cb.sizeHint().width() for cb in self.checkboxes)
        max_width += 80  # margen de seguridad
        for cb in self.checkboxes:
            cb.setFixedWidth(max_width)

    def get_selected_options(self):
        options = []

        if self.chk_single_port.isChecked():
            port = self.input_single_port.text().strip()
            if port:
                options.append(f"-p {port}")

        if self.chk_port_range.isChecked():
            start = self.input_port_range_start.text().strip()
            end = self.input_port_range_end.text().strip()
            if start and end:
                options.append(f"-p {start}-{end}")

        if self.chk_multi_tcp_udp.isChecked():
            udp_ports = self.input_multi_udp.text().strip()
            tcp_ports = self.input_multi_tcp.text().strip()
            multi_ports = []
            if udp_ports:
                multi_ports.append(f"U:{udp_ports}")
            if tcp_ports:
                multi_ports.append(f"T:{tcp_ports}")
            if multi_ports:
                options.append(f"-p {','.join(multi_ports)}")

        if self.chk_all_ports.isChecked():
            options.append("-p-")

        if self.chk_service_names.isChecked():
            services = self.input_service_names.text().strip()
            if services:
                options.append(f"-p {services}")

        if self.chk_fast_scan.isChecked():
            options.append("-F")

        if self.chk_top_ports.isChecked():
            top = self.input_top_ports.text().strip()
            if top:
                options.append(f"--top-ports {top}")

        if self.chk_full_range.isChecked():
            options.append("-p-65535")

        if self.chk_from_zero.isChecked():
            options.append("-p0-")

        # NUEVO: Excluir puertos
        if self.chk_exclude_ports.isChecked():
            exclude = self.input_exclude_ports.text().strip()
            if exclude:
                options.append(f"--exclude-ports {exclude}")

        # NUEVO: No randomizar
        if self.chk_no_randomize.isChecked():
            options.append("-r")

        # NUEVO: Ratio de frecuencia
        if self.chk_port_ratio.isChecked():
            ratio = self.input_port_ratio.text().strip()
            if ratio:
                options.append(f"--port-ratio {ratio}")

        return options
