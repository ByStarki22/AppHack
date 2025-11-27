from PySide6.QtWidgets import (
    QGroupBox, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit,
    QPushButton, QFileDialog, QLabel
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon

class MiscellaneousOptionsUI(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Miscellaneous Options", parent)
        self.init_ui()

    def init_ui(self):
        self.setCursor(Qt.ArrowCursor)
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Checkbox IPv6
        self.checkbox_ipv6 = QCheckBox("Habilita escaneo IPv6 (-6)")
        self.checkbox_ipv6.setCursor(Qt.PointingHandCursor)

        # Checkbox escaneo agresivo
        self.checkbox_aggressive = QCheckBox("Escaneo agresivo (-A)")
        self.checkbox_aggressive.setCursor(Qt.PointingHandCursor)

        # --datadir <dir>
        self.checkbox_datadir = QCheckBox("Directorio personalizado para datos (--datadir)")
        self.checkbox_datadir.setCursor(Qt.PointingHandCursor)
        self.input_datadir = QLineEdit()
        self.input_datadir.setPlaceholderText("Ruta al directorio")
        self.input_datadir.setEnabled(False)
        self.btn_browse_datadir = QPushButton()
        self.btn_browse_datadir.setIcon(QIcon.fromTheme("folder"))
        self.btn_browse_datadir.setEnabled(False)
        self.btn_browse_datadir.setCursor(Qt.PointingHandCursor)
        self.btn_browse_datadir.setFixedWidth(30)

        # --servicedb <file>
        self.checkbox_servicedb = QCheckBox("Archivo de servicios personalizado (--servicedb)")
        self.checkbox_servicedb.setCursor(Qt.PointingHandCursor)
        self.input_servicedb = QLineEdit()
        self.input_servicedb.setPlaceholderText("Ruta al archivo")
        self.input_servicedb.setEnabled(False)
        self.btn_browse_servicedb = QPushButton()
        self.btn_browse_servicedb.setIcon(QIcon.fromTheme("folder"))
        self.btn_browse_servicedb.setEnabled(False)
        self.btn_browse_servicedb.setCursor(Qt.PointingHandCursor)
        self.btn_browse_servicedb.setFixedWidth(30)

        # --versiondb <file>
        self.checkbox_versiondb = QCheckBox("Archivo de sondas de servicio especificado (--versiondb)")
        self.checkbox_versiondb.setCursor(Qt.PointingHandCursor)
        self.input_versiondb = QLineEdit()
        self.input_versiondb.setPlaceholderText("Ruta al archivo")
        self.input_versiondb.setEnabled(False)
        self.btn_browse_versiondb = QPushButton()
        self.btn_browse_versiondb.setIcon(QIcon.fromTheme("folder"))
        self.btn_browse_versiondb.setEnabled(False)
        self.btn_browse_versiondb.setCursor(Qt.PointingHandCursor)
        self.btn_browse_versiondb.setFixedWidth(30)

        # --send-eth
        self.checkbox_send_eth = QCheckBox("Enviar paquetes a nivel Ethernet (--send-eth)")
        self.checkbox_send_eth.setCursor(Qt.PointingHandCursor)

        # --send-ip
        self.checkbox_send_ip = QCheckBox("Enviar paquetes a nivel IP raw (--send-ip)")
        self.checkbox_send_ip.setCursor(Qt.PointingHandCursor)

        # --privileged
        self.checkbox_privileged = QCheckBox("Asumir privilegios para raw sockets (--privileged)")
        self.checkbox_privileged.setCursor(Qt.PointingHandCursor)

        # --unprivileged
        self.checkbox_unprivileged = QCheckBox("Asumir sin privilegios raw sockets (--unprivileged)")
        self.checkbox_unprivileged.setCursor(Qt.PointingHandCursor)

        # --release-memory
        self.checkbox_release_memory = QCheckBox("Liberar memoria antes de terminar (--release-memory)")
        self.checkbox_release_memory.setCursor(Qt.PointingHandCursor)

        # -V, --version
        self.checkbox_version = QCheckBox("Mostrar versión (-V, --version)")
        self.checkbox_version.setCursor(Qt.PointingHandCursor)

        # Agrupar todos los checkboxes para alinear ancho
        self.checkboxes = [
            self.checkbox_ipv6,
            self.checkbox_aggressive,
            self.checkbox_datadir,
            self.checkbox_servicedb,
            self.checkbox_versiondb,
            self.checkbox_send_eth,
            self.checkbox_send_ip,
            self.checkbox_privileged,
            self.checkbox_unprivileged,
            self.checkbox_release_memory,
            self.checkbox_version,
        ]
        self._align_checkboxes_width()

        # Layouts y adiciones al layout principal
        layout.addWidget(self.checkbox_ipv6)
        layout.addWidget(self.checkbox_aggressive)

        hbox_datadir = QHBoxLayout()
        hbox_datadir.addWidget(self.checkbox_datadir)
        hbox_datadir.addWidget(self.input_datadir)
        hbox_datadir.addWidget(self.btn_browse_datadir)
        hbox_datadir.setStretch(0, 0)
        hbox_datadir.setStretch(1, 1)
        hbox_datadir.setStretch(2, 0)
        layout.addLayout(hbox_datadir)

        hbox_servicedb = QHBoxLayout()
        hbox_servicedb.addWidget(self.checkbox_servicedb)
        hbox_servicedb.addWidget(self.input_servicedb)
        hbox_servicedb.addWidget(self.btn_browse_servicedb)
        hbox_servicedb.setStretch(0, 0)
        hbox_servicedb.setStretch(1, 1)
        hbox_servicedb.setStretch(2, 0)
        layout.addLayout(hbox_servicedb)

        hbox_versiondb = QHBoxLayout()
        hbox_versiondb.addWidget(self.checkbox_versiondb)
        hbox_versiondb.addWidget(self.input_versiondb)
        hbox_versiondb.addWidget(self.btn_browse_versiondb)
        hbox_versiondb.setStretch(0, 0)
        hbox_versiondb.setStretch(1, 1)
        hbox_versiondb.setStretch(2, 0)
        layout.addLayout(hbox_versiondb)

        layout.addWidget(self.checkbox_send_eth)
        layout.addWidget(self.checkbox_send_ip)
        layout.addWidget(self.checkbox_privileged)
        layout.addWidget(self.checkbox_unprivileged)
        layout.addWidget(self.checkbox_release_memory)
        layout.addWidget(self.checkbox_version)

        self.setLayout(layout)

        # Conexiones para habilitar inputs
        self.checkbox_datadir.toggled.connect(lambda c: self.enable_input(self.input_datadir, c))
        self.checkbox_datadir.toggled.connect(lambda c: self.btn_browse_datadir.setEnabled(c))

        self.checkbox_servicedb.toggled.connect(lambda c: self.enable_input(self.input_servicedb, c))
        self.checkbox_servicedb.toggled.connect(lambda c: self.btn_browse_servicedb.setEnabled(c))

        self.checkbox_versiondb.toggled.connect(lambda c: self.enable_input(self.input_versiondb, c))
        self.checkbox_versiondb.toggled.connect(lambda c: self.btn_browse_versiondb.setEnabled(c))

        # Cambios estilo inputs al modificar texto
        for inp in [self.input_datadir, self.input_servicedb, self.input_versiondb]:
            inp.textChanged.connect(lambda _, i=inp: self.update_input_style(i))

        # Abrir diálogos de selección de archivo/carpeta
        self.btn_browse_datadir.clicked.connect(self.open_directory_dialog)
        self.btn_browse_servicedb.clicked.connect(self.open_file_dialog_servicedb)
        self.btn_browse_versiondb.clicked.connect(self.open_file_dialog_versiondb)

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

    def open_directory_dialog(self):
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Seleccionar directorio"
        )
        if dir_path:
            self.input_datadir.setText(dir_path)

    def open_file_dialog_servicedb(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo de servicios personalizado",
            "",
            "Archivos (*.txt *.db *.services);;Todos los archivos (*)"
        )
        if file_path:
            self.input_servicedb.setText(file_path)

    def open_file_dialog_versiondb(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo probes de servicio personalizado",
            "",
            "Archivos (*.txt *.db *.probes);;Todos los archivos (*)"
        )
        if file_path:
            self.input_versiondb.setText(file_path)

    def get_selected_options(self):
        # Retorna una lista con las opciones seleccionadas y sus valores
        options = []
        if self.checkbox_ipv6.isChecked():
            options.append("-6")
        if self.checkbox_aggressive.isChecked():
            options.append("-A")
        if self.checkbox_datadir.isChecked():
            val = self.input_datadir.text().strip()
            if val:
                options.append(f"--datadir {val}")
        if self.checkbox_servicedb.isChecked():
            val = self.input_servicedb.text().strip()
            if val:
                options.append(f"--servicedb {val}")
        if self.checkbox_versiondb.isChecked():
            val = self.input_versiondb.text().strip()
            if val:
                options.append(f"--versiondb {val}")
        if self.checkbox_send_eth.isChecked():
            options.append("--send-eth")
        if self.checkbox_send_ip.isChecked():
            options.append("--send-ip")
        if self.checkbox_privileged.isChecked():
            options.append("--privileged")
        if self.checkbox_unprivileged.isChecked():
            options.append("--unprivileged")
        if self.checkbox_release_memory.isChecked():
            options.append("--release-memory")
        if self.checkbox_version.isChecked():
            options.append("-V")
        return options
