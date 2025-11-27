from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QRadioButton, QComboBox,
    QPushButton, QCheckBox, QGroupBox, QButtonGroup, QLineEdit, QFrame, QSizePolicy, QSpacerItem, QTextEdit,
    QScrollArea
)
from PySide6.QtCore import Qt, QThread, Signal, QEvent, QTimer
from app.logic.toolsLogic.portSscanner.scan_type.fast_scan_type.fast_scan_type import FastScanType
import logging

class ScanThread(QThread):
    result_ready = Signal(dict)
    error = Signal(str)

    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner

    def run(self):
        try:
            result = self.scanner.perform_scan()  # Call perform_scan instead of scan
            self.result_ready.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class QTextEditLogger(logging.Handler):
    def __init__(self, text_edit: QTextEdit):
        super().__init__()
        self.text_edit = text_edit

    def emit(self, record):
        msg = self.format(record)
        self.text_edit.append(msg)


class FastScanTypeUI(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.btn_start_scan.clicked.connect(self.on_start_scan)
        self._last_maximized = None  # Para detectar cambios de estado
        self.scroll_area.viewport().installEventFilter(self)

        # Configura el logger para usar QTextEditLogger
        self.log_text_edit_handler = QTextEditLogger(self.log_text)
        self.log_text_edit_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(self.log_text_edit_handler)
        logging.getLogger().setLevel(logging.DEBUG)

        # Timer para comprobar el estado de la ventana
        self._window_state_timer = QTimer(self)
        self._window_state_timer.timeout.connect(self._check_window_state)
        self._window_state_timer.start(100)  # cada 100 ms

    def _check_window_state(self):
        maximized = self.window().isMaximized()
        if maximized != self._last_maximized:
            self._last_maximized = maximized
            self.update_scrollbar_state()

    def update_scrollbar_state(self):
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)


    def init_ui(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #181818;
                color: #e0e0e0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 15px;
            }
            QGroupBox {
                /* background-color: #232323; */
                border: 2px solid #222;
                border-radius: 14px;
                margin-top: 12px;
                font-weight: bold;
                color: #00ffcc;
                padding: 8px 10px 10px 10px;
            }
            QGroupBox:title {
                subcontrol-origin: margin;
                left: 12px;
                top: 8px;
                padding: 0 4px;
                color: #00ffcc;
                font-size: 16px;
            }
            QLabel {
                color: #e0e0e0;
            }
            QRadioButton, QCheckBox {
                color: #e0e0e0;
                font-size: 15px;
            }
            QRadioButton::indicator, QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 8px;
                border: 2px solid #00ffcc;
                background-color: transparent;
            }
            QRadioButton::indicator:checked, QCheckBox::indicator:checked {
                background-color: #00ffcc;
                border: 2px solid #00ffcc;
            }
            QLineEdit, QComboBox {
                background-color: #222;
                border: 1.5px solid #333;
                border-radius: 8px;
                color: #e0e0e0;
                padding: 6px 10px;
                font-size: 15px;
            }
            QComboBox:open {
                border-bottom-left-radius: 0;
                border-bottom-right-radius: 0;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 32px;
                border-left: 1.5px solid #333;
                background: #232323;
                border-top-right-radius: 8px;
                border-bottom-right-radius: 8px;
            }
            QComboBox::drop-down:open {
                border-bottom-right-radius: 0;
            }
            QComboBox QAbstractItemView {
                background-color: #232323;
                color: #e0e0e0;
                selection-background-color: #00aa88;
                border: 1.5px solid #333;
                border-top-left-radius: 0;
                border-top-right-radius: 0;
                border-bottom-left-radius: 10px;
                border-bottom-right-radius: 10px;
                padding: 4px 0;
            }
            QComboBox::down-arrow {
                image: url("data:image/svg+xml;utf8,<svg width='18' height='18' viewBox='0 0 18 18' fill='none' xmlns='http://www.w3.org/2000/svg'><path d='M4.5 7.5L9 12L13.5 7.5' stroke='%2300ffcc' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/></svg>");
                width: 18px;
                height: 18px;
            }
            QPushButton {
                font-size: 15px;
                padding: 8px 24px;
                background-color: #00aa88;
                color: white;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00ffcc;
                color: #101010;
            }
            QFrame[frameShape="4"] { /* QFrame.HLine */
                background: #222;
                max-height: 2px;
            }
        """)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(36, 36, 36, 36)
        main_layout.setSpacing(22)

        # Título principal
        title = QLabel("Escaneo Rápido de Puertos")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #00ffcc; margin-bottom: 18px;")
        main_layout.addWidget(title)

        # Grupo: Selección de objetivo
        target_group = QGroupBox("Seleccionar objetivo")
        target_layout = QVBoxLayout()
        target_layout.setSpacing(10)

        self.radio_current_ip = QRadioButton("Usar IP actual")
        self.radio_current_ip.setCursor(Qt.PointingHandCursor) 
        self.radio_manual_ip = QRadioButton("Ingresar IP manualmente")
        self.radio_manual_ip.setCursor(Qt.PointingHandCursor)
        self.input_manual_ip = QLineEdit()
        self.input_manual_ip.setPlaceholderText("Ejemplo: 192.168.1.10")
        self.input_manual_ip.setEnabled(False)
        self.radio_saved_list = QRadioButton("Seleccionar objetivo de lista guardada")
        self.radio_saved_list.setCursor(Qt.PointingHandCursor)
        self.combo_saved_targets = QComboBox()
        self.combo_saved_targets.setCursor(Qt.PointingHandCursor)
        self.combo_saved_targets.setEnabled(False)

        self.target_button_group = QButtonGroup()
        self.target_button_group.addButton(self.radio_current_ip)
        self.target_button_group.addButton(self.radio_manual_ip)
        self.target_button_group.addButton(self.radio_saved_list)

        manual_ip_layout = QHBoxLayout()
        manual_ip_layout.addWidget(self.radio_manual_ip)
        manual_ip_layout.addWidget(self.input_manual_ip)

        saved_list_layout = QHBoxLayout()
        saved_list_layout.addWidget(self.radio_saved_list)
        saved_list_layout.addWidget(self.combo_saved_targets)

        target_layout.addWidget(self.radio_current_ip)
        target_layout.addLayout(manual_ip_layout)
        target_layout.addLayout(saved_list_layout)
        target_group.setLayout(target_layout)

        self.radio_manual_ip.toggled.connect(
            lambda checked: self.input_manual_ip.setEnabled(checked)
        )
        self.radio_saved_list.toggled.connect(
            lambda checked: self.combo_saved_targets.setEnabled(checked)
        )

        separator1 = QFrame()
        separator1.setFrameShadow(QFrame.Sunken)
        separator1.setProperty("frameShape", QFrame.HLine)

        main_layout.addWidget(target_group)
        main_layout.addWidget(separator1)

        # Tipo de escaneo
        scan_type_group = QGroupBox("Tipo de escaneo")
        scan_type_layout = QHBoxLayout()
        scan_type_layout.setContentsMargins(8, 8, 8, 8)
        scan_type_layout.setSpacing(12)
        scan_type_layout.addWidget(QLabel("Protocolo:"))
        self.combo_scan_type = QComboBox()
        self.combo_scan_type.addItems(["TCP", "UDP", "ICMP", "SCTP", "SCTP INIT"])
        self.combo_scan_type.setCursor(Qt.PointingHandCursor)
        scan_type_layout.addWidget(self.combo_scan_type)
        scan_type_layout.addStretch()
        scan_type_group.setLayout(scan_type_layout)
        main_layout.addWidget(scan_type_group)

        # Opciones de escaneo rápido
        options_group = QGroupBox("Opciones de escaneo rápido")
        options_layout = QVBoxLayout()
        options_layout.setSpacing(16)

        # Subgrupo: Escaneo básico
        basic_group = QGroupBox("Escaneo básico")
        basic_layout = QVBoxLayout()
        basic_layout.setSpacing(8)

        self.check_ping_sweep = QCheckBox("Ping sweep (detectar hosts activos)")
        self.check_ping_sweep.setCursor(Qt.PointingHandCursor)
        self.check_common_ports = QCheckBox("Escaneo de puertos más comunes")
        self.check_common_ports.setCursor(Qt.PointingHandCursor)
        self.check_fast_scan = QCheckBox("Usar opción Fast Scan (-F)")
        self.check_fast_scan.setCursor(Qt.PointingHandCursor)

        top_ports_layout = QHBoxLayout()
        top_ports_label = QLabel("Top N puertos (--top-ports):")
        self.input_top_ports = QLineEdit()
        self.input_top_ports.setPlaceholderText("Ejemplo: 100")
        self.input_top_ports.setFixedWidth(100)
        top_ports_layout.addWidget(top_ports_label)
        top_ports_layout.addWidget(self.input_top_ports)

        basic_layout.addWidget(self.check_ping_sweep)
        basic_layout.addWidget(self.check_common_ports)
        basic_layout.addWidget(self.check_fast_scan)
        basic_layout.addLayout(top_ports_layout)
        basic_group.setLayout(basic_layout)

        # Subgrupo: Rendimiento
        performance_group = QGroupBox("Rendimiento")
        performance_layout = QVBoxLayout()
        performance_layout.setSpacing(8)

        rate_layout = QHBoxLayout()
        min_rate_label = QLabel("Min rate (--min-rate):")
        self.input_min_rate = QLineEdit()
        self.input_min_rate.setPlaceholderText("Ej: 1000")
        self.input_min_rate.setFixedWidth(100)
        max_rate_label = QLabel("Max rate (--max-rate):")
        self.input_max_rate = QLineEdit()
        self.input_max_rate.setPlaceholderText("Ej: 5000")
        self.input_max_rate.setFixedWidth(100)

        rate_layout.addWidget(min_rate_label)
        rate_layout.addWidget(self.input_min_rate)
        rate_layout.addSpacing(20)
        rate_layout.addWidget(max_rate_label)
        rate_layout.addWidget(self.input_max_rate)

        speed_layout = QHBoxLayout()
        speed_label = QLabel("Nivel de velocidad (-T):")
        speed_label.setFixedWidth(140)
        self.combo_speed_level = QComboBox()
        self.combo_speed_level.addItems([
            "T0 (paranoico)", "T1 (sigiloso)", "T2 (conservador)",
            "T3 (normal)", "T4 (rápido)", "T5 (agresivo)"
        ])
        self.combo_speed_level.setCurrentIndex(4)
        self.combo_speed_level.setCursor(Qt.PointingHandCursor)

        speed_layout.addWidget(speed_label)
        speed_layout.addWidget(self.combo_speed_level)
        speed_layout.addStretch()

        performance_layout.addLayout(rate_layout)
        performance_layout.addLayout(speed_layout)
        performance_group.setLayout(performance_layout)

        # Subgrupo: Detección avanzada
        advanced_group = QGroupBox("Detección avanzada")
        advanced_layout = QVBoxLayout()
        advanced_layout.setSpacing(8)

        self.check_aggressive_t4 = QCheckBox("Escaneo rápido agresivo (-T4)")
        self.check_aggressive_t4.setCursor(Qt.PointingHandCursor)
        self.check_service_version = QCheckBox("Detección de versión (-sV)")
        self.check_service_version.setCursor(Qt.PointingHandCursor)
        self.check_os_detection = QCheckBox("Detección de sistema operativo (-O)")
        self.check_os_detection.setCursor(Qt.PointingHandCursor)
        self.check_no_ping = QCheckBox("No ping (-Pn)")
        self.check_no_ping.setCursor(Qt.PointingHandCursor)

        advanced_layout.addWidget(self.check_aggressive_t4)
        advanced_layout.addWidget(self.check_service_version)
        advanced_layout.addWidget(self.check_os_detection)
        advanced_layout.addWidget(self.check_no_ping)
        advanced_group.setLayout(advanced_layout)

        # Añadir subgrupos al layout principal
        options_layout.addWidget(basic_group)
        options_layout.addWidget(performance_group)
        options_layout.addWidget(advanced_group)

        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)


        separator2 = QFrame()
        separator2.setFrameShadow(QFrame.Sunken)
        separator2.setProperty("frameShape", QFrame.HLine)
        main_layout.addWidget(separator2)

        # Botones: Iniciar, Pausar/Reanudar y Cancelar
        # Botones: Iniciar, Pausar/Reanudar y Cancelar
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(20)
        btn_layout.addStretch()

        # Iniciar escaneo
        self.btn_start_scan = QPushButton("Iniciar escaneo")
        self.btn_start_scan.setCursor(Qt.PointingHandCursor)
        self.btn_start_scan.setMinimumWidth(180)
        btn_layout.addWidget(self.btn_start_scan)

        # Botón Pausar/Reanudar con íconos de texto
        self.btn_toggle_pause = QPushButton("⏸")
        self.btn_toggle_pause.setCursor(Qt.PointingHandCursor)
        self.btn_toggle_pause.setFixedSize(60, 60)  # Más alto y ancho
        self.btn_toggle_pause.setStyleSheet("""
            QPushButton {
                background-color: #ffaa00;
                color: black;
                font-size: 30px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ffcc33;
            }
        """)
        self.btn_toggle_pause.clicked.connect(self.toggle_pause_icon)
        btn_layout.addWidget(self.btn_toggle_pause)


        # Cancelar
        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.setCursor(Qt.PointingHandCursor)
        self.btn_cancel.setMinimumWidth(180)
        self.btn_cancel.setMinimumHeight(self.btn_start_scan.sizeHint().height())  # <-- Esta línea iguala la altura
        self.btn_cancel.setStyleSheet("""
            QPushButton {
                background-color: #aa0033;
                color: white;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ff3355;
                color: black;
            }
        """)
        btn_layout.addWidget(self.btn_cancel)

        btn_layout.addStretch()
        main_layout.addLayout(btn_layout)


        # Cuadro de logs/proceso debajo del botón
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMinimumHeight(500)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #111;
                color: #fff;
                border-radius: 8px;
                border: 2px solid #444;
                font-family: 'Consolas', monospace;
                font-size: 14px;
                padding: 8px;
            }
        """)
        main_layout.addWidget(self.log_text)

        main_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # --- NUEVO: Envolver el layout en un QWidget y luego en QScrollArea ---
        content_widget = QWidget()
        content_widget.setLayout(main_layout)

        # Cambia estas líneas:
        # scroll_area = QScrollArea()
        # self.scroll_area = scroll_area  # <-- Guarda como atributo de instancia
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(content_widget)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }

            QScrollBar:vertical {
                background: #333;
                width: 12px;
                margin: 0px 0px 0px 0px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background: #888;
                min-height: 30px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background: #aaa;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
                subcontrol-origin: margin;
                subcontrol-position: top left;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }

            QScrollBar:horizontal {
                background: #333;
                height: 12px;
                margin: 0px 0px 0px 0px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal {
                background: #888;
                min-width: 30px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #aaa;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
                subcontrol-origin: margin;
                subcontrol-position: left top;
            }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                background: none;
            }
        """)

        # Limpiar el layout principal y agregar el scroll_area
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(self.scroll_area)
        self.setLayout(outer_layout)

    def get_selected_target_ip(self):
        if self.radio_current_ip.isChecked():
            return FastScanType.get_current_ip()
        elif self.radio_manual_ip.isChecked():
            return self.input_manual_ip.text().strip()
        elif self.radio_saved_list.isChecked():
            return self.combo_saved_targets.currentText().strip()
        return None

    def append_log(self, message):
        self.log_text.append(message)

    def on_start_scan(self):
        target_ip = self.get_selected_target_ip()
        if not target_ip:
            self.append_log("Por favor, selecciona o ingresa una IP válida.")
            return

        protocol = self.combo_scan_type.currentText()
        ping_sweep = self.check_ping_sweep.isChecked()
        common_ports = self.check_common_ports.isChecked()
        fast_scan = self.check_fast_scan.isChecked()
        top_ports = self.input_top_ports.text().strip()
        min_rate = self.input_min_rate.text().strip()
        max_rate = self.input_max_rate.text().strip()

        # Validar que top_ports, min_rate, max_rate sean números si no están vacíos
        try:
            top_ports_num = int(top_ports) if top_ports else None
        except ValueError:
            self.append_log("Valor inválido para 'top N puertos'. Debe ser un número.")
            return

        try:
            min_rate_num = int(min_rate) if min_rate else None
        except ValueError:
            self.append_log("Valor inválido para 'min rate'. Debe ser un número.")
            return

        try:
            max_rate_num = int(max_rate) if max_rate else None
        except ValueError:
            self.append_log("Valor inválido para 'max rate'. Debe ser un número.")
            return

        try:
            self.append_log(f"Iniciando escaneo a {target_ip} con protocolo {protocol}...")
            scanner = FastScanType(
                target_ip=target_ip,
                protocol=protocol,
                ping_sweep=ping_sweep,
                common_ports=common_ports,
                fast_scan=fast_scan,
                top_ports=top_ports_num,
                min_rate=min_rate_num,
                max_rate=max_rate_num,
            )
            self.scan_thread = ScanThread(scanner)
            self.scan_thread.result_ready.connect(self.handle_scan_result)
            self.scan_thread.error.connect(self.handle_scan_error)
            self.scan_thread.start()
        except Exception as e:
            self.append_log(f"Error al iniciar el escaneo: {e}")

    def handle_scan_result(self, result):
        self.append_log("Escaneo completado.")
        self.append_log(str(result))

    def handle_scan_error(self, error_msg):
        self.append_log(f"Error durante el escaneo: {error_msg}")

    # --- NUEVO: Sobrescribe resizeEvent ---
    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.window().isMaximized():
            self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        else:
            self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # Reset scroll position
        self.scroll_area.verticalScrollBar().setValue(0)
        self.scroll_area.horizontalScrollBar().setValue(0)
    
    def toggle_pause_icon(self):
        current_text = self.btn_toggle_pause.text()
        if current_text == "⏸":
            self.btn_toggle_pause.setText("▶")  # Cambia a Reanudar
        else:
            self.btn_toggle_pause.setText("⏸")  # Cambia a Pausa
