from PySide6.QtWidgets import (
    QGroupBox, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit, QLabel, QComboBox, QSizePolicy
)
from PySide6.QtCore import Qt


class NoWheelComboBox(QComboBox):
    def wheelEvent(self, event):
        if self.view().isVisible():
            super().wheelEvent(event)
        else:
            event.ignore()


class TimingPerformanceSwitchesUI(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Timing and Performance Switches", parent)
        self.init_ui()

    def init_ui(self):
        self.setCursor(Qt.ArrowCursor)
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Checkboxes con cursor de mano
        self.cb_defeat_rst = QCheckBox("Ignorar limitación de tasa de paquetes RST (reduce precisión)")
        self.cb_defeat_rst.setCursor(Qt.PointingHandCursor)

        self.cb_defeat_icmp = QCheckBox("Ignorar limitación de tasa de mensajes ICMP (reduce precisión)")
        self.cb_defeat_icmp.setCursor(Qt.PointingHandCursor)

        # Inputs con labels a la izquierda y campos a la derecha
        self.le_host_timeout = QLineEdit()
        self.le_host_timeout.setPlaceholderText("Ejemplo: 1s; 4m; 2h")

        self.le_rtt_timeout = QLineEdit()
        self.le_rtt_timeout.setPlaceholderText("Ejemplo: 1s; 4m; 2h")

        self.le_hostgroup = QLineEdit()
        self.le_hostgroup.setPlaceholderText("Ejemplo: 50; 1024")

        self.le_parallelism = QLineEdit()
        self.le_parallelism.setPlaceholderText("Ejemplo: 10; 1")

        self.le_max_retries = QLineEdit()
        self.le_max_retries.setPlaceholderText("Ejemplo: 3")

        self.le_script_timeout = QLineEdit()
        self.le_script_timeout.setPlaceholderText("Ejemplo: 10s; 5m")

        self.le_scan_delay = QLineEdit()
        self.le_scan_delay.setPlaceholderText("Ejemplo: 1s; 100ms")

        self.le_max_scan_delay = QLineEdit()
        self.le_max_scan_delay.setPlaceholderText("Ejemplo: 5s; 500ms")

        self.le_min_rate = QLineEdit()
        self.le_min_rate.setPlaceholderText("Ejemplo: 100")

        self.le_max_rate = QLineEdit()
        self.le_max_rate.setPlaceholderText("Ejemplo: 100")

        # Checkbox para motor de multiplexación y combobox deshabilitado inicialmente
        self.cb_nsock_engine_enable = QCheckBox("Seleccionar motor de multiplexación IO (--nsock-engine)")
        self.cb_nsock_engine_enable.setCursor(Qt.PointingHandCursor)

        self.cb_nsock_engine = NoWheelComboBox()
        self.cb_nsock_engine.addItems(["iocp", "epoll", "kqueue", "poll", "select"])
        self.cb_nsock_engine.setEnabled(False)
        self.cb_nsock_engine.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.cb_nsock_engine.setStyleSheet("color: gray;")  # estado inicial gris

        # Conectar checkbox para habilitar/deshabilitar combobox con estilo
        self.cb_nsock_engine_enable.toggled.connect(self.toggle_nsock_engine)

        # Lista de inputs con labels (sin el motor de multiplexación, que se maneja aparte)
        inputs = [
            ("Abandonar el objetivo después de este tiempo (--host-timeout)", self.le_host_timeout),
            ("Tiempo de ida y vuelta para sondas (--min/max/initial-rtt-timeout)", self.le_rtt_timeout),
            ("Tamaño del grupo de escaneo de hosts en paralelo (--min/max-hostgroup)", self.le_hostgroup),
            ("Paralelización de sondas (--min/max-parallelism)", self.le_parallelism),
            ("Número máximo de retransmisiones de sondas (--max-retries)", self.le_max_retries),
            ("Tiempo máximo para ejecución de scripts (--script-timeout)", self.le_script_timeout),
            ("Retraso entre sondas a un host (--scan-delay)", self.le_scan_delay),
            ("Retraso máximo permitido entre sondas (--max-scan-delay)", self.le_max_scan_delay),
            ("Enviar paquetes no más lento que <número> por segundo (--min-rate)", self.le_min_rate),
            ("Enviar paquetes no más rápido que <número> por segundo (--max-rate)", self.le_max_rate),
        ]

        # Añadimos los checkboxes primero
        layout.addWidget(self.cb_defeat_rst)
        layout.addWidget(self.cb_defeat_icmp)

        # Añadimos inputs con sus labels
        for label_text, widget in inputs:
            lbl = QLabel(label_text)
            lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            layout.addLayout(self._hbox(lbl, widget))

        # Añadimos checkbox y combobox juntos en un layout horizontal
        layout.addLayout(self._hbox(self.cb_nsock_engine_enable, self.cb_nsock_engine))

        self.setLayout(layout)

    def _hbox(self, left_widget, right_widget):
        hbox = QHBoxLayout()
        hbox.addWidget(left_widget)
        hbox.addWidget(right_widget)
        hbox.setStretch(0, 2)
        hbox.setStretch(1, 1)
        return hbox

    def toggle_nsock_engine(self, checked):
        self.cb_nsock_engine.setEnabled(checked)
        if checked:
            self.cb_nsock_engine.setStyleSheet("color: white;")
        else:
            self.cb_nsock_engine.setStyleSheet("color: gray;")

    def get_options(self):
        return {
            "defeat-rst-ratelimit": self.cb_defeat_rst.isChecked(),
            "defeat-icmp-ratelimit": self.cb_defeat_icmp.isChecked(),
            "host-timeout": self.le_host_timeout.text().strip(),
            "rtt-timeout": self.le_rtt_timeout.text().strip(),
            "hostgroup": self.le_hostgroup.text().strip(),
            "parallelism": self.le_parallelism.text().strip(),
            "max-retries": self.le_max_retries.text().strip(),
            "script-timeout": self.le_script_timeout.text().strip(),
            "scan-delay": self.le_scan_delay.text().strip(),
            "max-scan-delay": self.le_max_scan_delay.text().strip(),
            "min-rate": self.le_min_rate.text().strip(),
            "max-rate": self.le_max_rate.text().strip(),
            "nsock-engine-enabled": self.cb_nsock_engine_enable.isChecked(),
            "nsock-engine": self.cb_nsock_engine.currentText() if self.cb_nsock_engine_enable.isChecked() else None,
        }
