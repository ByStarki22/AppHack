from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QRadioButton, QComboBox,
    QPushButton, QCheckBox, QGroupBox, QButtonGroup, QLineEdit, QFrame, QSizePolicy, QSpacerItem, QTextEdit,
    QScrollArea
)
from PySide6.QtCore import Qt, QThread, Signal, QEvent, QTimer
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.advance_widgets_ui.advance_firewall_evasion_spoofing_ui import FirewallEvasionOptionsUI
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.advance_widgets_ui.advance_host_discovery_ui import HostDiscoveryOptionsUI
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.advance_widgets_ui.advance_miscellaneous_ui import MiscellaneousOptionsUI
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.advance_widgets_ui.advance_os_detection_ui import OSDetectionSelectorUI
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.advance_widgets_ui.advance_port_specification_ui import PortSpecificationUI
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.advance_widgets_ui.advance_service_version_detection_ui import ServiceVersionDetectionUI
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.advance_widgets_ui.advance_target_specification_ui import TargetSelectorUI
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.advance_widgets_ui.advance_timing_performance_ui import TimingPerformanceSelectorUI
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.advance_widgets_ui.advance_timing_switches_ui import TimingPerformanceSwitchesUI
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.advance_widgets_ui.advanced_type_scan_ui import ScanTechniquesUI
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


class AdvanceScanTypeUI(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
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

        self.btn_start_scan.clicked.connect(self.on_start_scan_clicked)

        # Connect the message signal to the append_log method
        self.target_selector.message_signal.connect(self.append_log)

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

        self.target_selector = TargetSelectorUI()
        self.port_specification = PortSpecificationUI()  # Aquí el nuevo widget
        self.scan_techniques = ScanTechniquesUI()
        self.host_discovery = HostDiscoveryOptionsUI()
        self.service_version_detection = ServiceVersionDetectionUI()
        self.os_detection = OSDetectionSelectorUI()
        self.timing_performance = TimingPerformanceSelectorUI()
        self.timing_switches = TimingPerformanceSwitchesUI()
        self.firewall_evasion_spoofing = FirewallEvasionOptionsUI()
        self.miscellaneous_options = MiscellaneousOptionsUI()


        # Ajustar políticas de tamaño
        self.target_selector.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.port_specification.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.scan_techniques.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.host_discovery.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.service_version_detection.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.os_detection.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.timing_performance.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.timing_switches.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.firewall_evasion_spoofing.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.miscellaneous_options.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        # Layout principal horizontal
        top_layout = QHBoxLayout()

        # Columna izquierda: selector de IP y port specification
        left_column_layout = QVBoxLayout()
        left_column_layout.addWidget(self.target_selector)
        left_column_layout.addWidget(self.port_specification)
        left_column_layout.addWidget(self.service_version_detection)
        left_column_layout.addWidget(self.miscellaneous_options)

        # Columna derecha: otras opciones
        right_column_layout = QVBoxLayout()
        right_column_layout.addWidget(self.scan_techniques)
        right_column_layout.addWidget(self.host_discovery)
        right_column_layout.addWidget(self.os_detection)
        right_column_layout.addWidget(self.timing_performance)
        right_column_layout.addWidget(self.timing_switches)
        right_column_layout.addWidget(self.firewall_evasion_spoofing)

        # Agregar columnas al layout principal
        top_layout.addLayout(left_column_layout)
        top_layout.addLayout(right_column_layout)

        # Finalmente añadir el layout al main_layout (el layout general principal)
        main_layout.addLayout(top_layout)

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
        self.btn_toggle_pause = QPushButton("▮▮")
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

    def on_start_scan_clicked(self):
        # Llama al método de escaneo del target_selector y muestra los mensajes en el log
        self.log_text.clear()
        self.target_selector.on_scan_button_clicked()

    def append_log(self, message):
        self.log_text.append(message)

    # --- NUEVO: Sobrescribe resizeEvent ---
    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.window().isMaximized():
            self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        else:
            self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

    def toggle_pause_icon(self):
        current_text = self.btn_toggle_pause.text()
        if current_text == "▮▮":
            self.btn_toggle_pause.setText("▶")  # Cambia a Reanudar
        else:
            self.btn_toggle_pause.setText("▮▮")  # Cambia a Pausa
