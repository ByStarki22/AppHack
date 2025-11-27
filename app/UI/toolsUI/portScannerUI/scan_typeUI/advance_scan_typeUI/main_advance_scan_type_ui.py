from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QRadioButton, QComboBox,
    QPushButton, QCheckBox, QGroupBox, QButtonGroup, QLineEdit, QFrame, QSizePolicy, QSpacerItem, QTextEdit,
    QScrollArea, QStyle
)
from PySide6.QtCore import Qt, QThread, Signal, QEvent, QTimer, QObject
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
import asyncio
import socket
import time

from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets import advance_target_specification as adv_scan_logic

class ScanWorker(QObject):
    progress = Signal(str)
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, params):
        super().__init__()
        self.params = params
        self._stop = False
        self._paused = False

    def stop(self):
        self._stop = True
        self._paused = False

    def pause(self):
        if not self._stop:
            self._paused = True

    def resume(self):
        self._paused = False

    def _pause_check(self):
        while self._paused and not self._stop:
            QThread.msleep(100)

    def _run_async(self, coro):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(coro)
            return result
        finally:
            try:
                loop.close()
            except Exception:
                pass

    def run(self):
        try:
            result = self._do_scan()
            if not self._stop:
                self.finished.emit(result)
            else:
                self.finished.emit({"status": "cancelled"})
        except Exception as e:
            self.error.emit(str(e))

    def _do_scan(self):
        p = self.params
        # Determinar tipo de escaneo según flags
        exclude_list = self._build_exclude_list(p)
        # Orden de prioridad similar al UI original
        if p['single_ip']:
            ip = p['single_ip_value']
            if not ip:
                self.progress.emit("Debes ingresar una IP válida.")
                return {}
            self.progress.emit(f"Escaneando IP única: {ip}")
            return {ip: self._scan_common_ports_interruptible(ip, exclude_list=exclude_list)}

        if p['multiple_ips']:
            raw = p['multiple_ips_value']
            ip_list = [ip.strip() for ip in raw.replace(',', ' ').split() if ip.strip()]
            self.progress.emit(f"Escaneando múltiples IPs: {', '.join(ip_list)}")
            results = {}
            for ip in ip_list:
                if self._stop:
                    break
                self._pause_check()
                self.progress.emit(f"→ IP {ip}")
                results[ip] = self._scan_common_ports_interruptible(ip, exclude_list=exclude_list)
            return results

        if p['ip_ranges']:
            ranges_str = p['ip_ranges_value']
            self.progress.emit(f"Escaneando rangos: {ranges_str}")
            # Re-implementa para permitir pausa/cancel
            ranges = [r.strip() for r in ranges_str.split(',') if r.strip()]
            ip_list = []
            for r in ranges:
                if '-' not in r:
                    continue
                base, end = r.split('-')
                base_parts = base.strip().split('.')
                if len(base_parts) != 4:
                    continue
                try:
                    start = int(base_parts[3])
                    end_oct = int(end.strip())
                    if not (0 <= start <= 255 and 0 <= end_oct <= 255 and start <= end_oct):
                        continue
                    for last_octet in range(start, end_oct + 1):
                        ip = '.'.join(base_parts[:3] + [str(last_octet)])
                        ip_list.append(ip)
                except Exception:
                    continue
            # Excluir
            if exclude_list:
                ip_list = [i for i in ip_list if i not in exclude_list]
            results = {}
            for ip in ip_list:
                if self._stop:
                    break
                self._pause_check()
                self.progress.emit(f"→ IP {ip}")
                results[ip] = self._scan_common_ports_interruptible(ip, exclude_list=exclude_list)
            return results

        if p['cidr']:
            cidr_str = p['cidr_value']
            self.progress.emit(f"Escaneando CIDR: {cidr_str}")
            # Implementación manual para pausa/cancel
            results = {}
            try:
                ip_part, prefix = cidr_str.split('/')
                prefix = int(prefix)
                if not (24 <= prefix <= 32):
                    self.progress.emit("El prefijo debe estar entre /24 y /32.")
                    return results
                def ip_to_int(ip):
                    return sum(int(part) << (8 * (3 - i)) for i, part in enumerate(ip.split('.')))
                def int_to_ip(num):
                    return '.'.join(str((num >> (8 * (3 - i))) & 0xFF) for i in range(4))
                start_ip_int = ip_to_int(ip_part.strip())
                num_hosts = 2 ** (32 - prefix)
                end_ip_int = start_ip_int + num_hosts - 1
                ip_list = [int_to_ip(ip_int) for ip_int in range(start_ip_int, end_ip_int + 1)]
                if exclude_list:
                    ip_list = [i for i in ip_list if i not in exclude_list]
                for ip in ip_list:
                    if self._stop:
                        break
                    self._pause_check()
                    self.progress.emit(f"→ IP {ip}")
                    results[ip] = self._scan_common_ports_interruptible(ip, exclude_list=exclude_list)
            except Exception as e:
                self.progress.emit(f"Error CIDR: {e}")
            return results

        if p['domain']:
            domain = p['domain_value']
            if not domain:
                self.progress.emit("Debes ingresar un dominio válido.")
                return {}
            self.progress.emit(f"Escaneando dominio (interruptible): {domain}")
            ports = self._scan_domain_interruptible(domain, exclude_list=exclude_list)
            return {domain: ports}

        if p['from_file']:
            path = p['from_file_value']
            if not path:
                self.progress.emit("Debes seleccionar un archivo válido.")
                return {}
            self.progress.emit(f"Escaneando objetivos desde archivo: {path}")
            results = {}
            try:
                with open(path, 'r') as f:
                    lines = [line.strip() for line in f if line.strip()]
                for target in lines:
                    if self._stop:
                        break
                    self._pause_check()
                    self.progress.emit(f"→ Objetivo {target}")
                    if '/' in target:
                        # CIDR
                        sub_params = dict(p)
                        sub_params.update({'cidr': True, 'cidr_value': target})
                        # Reutiliza parte CIDR llamando recursivamente (simple)
                        # Para evitar duplicar lógica puedes llamar a scan_cidr directamente (sin pausa interna)
                        # Procesar CIDR de forma interruptible
                        cidr_results = {}
                        try:
                            ip_part, prefix = target.split('/')
                            prefix = int(prefix)
                            if not (24 <= prefix <= 32):
                                self.progress.emit(f"Prefijo inválido en {target}")
                            else:
                                def ip_to_int(ip):
                                    return sum(int(part) << (8 * (3 - i)) for i, part in enumerate(ip.split('.')))
                                def int_to_ip(num):
                                    return '.'.join(str((num >> (8 * (3 - i))) & 0xFF) for i in range(4))
                                start_ip_int = ip_to_int(ip_part.strip())
                                num_hosts = 2 ** (32 - prefix)
                                end_ip_int = start_ip_int + num_hosts - 1
                                ip_list = [int_to_ip(ip_int) for ip_int in range(start_ip_int, end_ip_int + 1)]
                                if exclude_list:
                                    ip_list = [i for i in ip_list if i not in exclude_list]
                                for ip_cidr in ip_list:
                                    if self._stop:
                                        break
                                    self._pause_check()
                                    cidr_results[ip_cidr] = self._scan_common_ports_interruptible(ip_cidr, exclude_list=exclude_list)
                        except Exception as e:
                            self.progress.emit(f"Error CIDR {target}: {e}")
                        results[target] = cidr_results
                    elif '-' in target:
                        range_results = {}
                        try:
                            base, end_octet = target.split('-')
                            base_parts = base.strip().split('.')
                            start_oct = int(base_parts[3])
                            end_oct = int(end_octet.strip())
                            for last_octet in range(start_oct, end_oct + 1):
                                ip_rng = '.'.join(base_parts[:3] + [str(last_octet)])
                                if exclude_list and ip_rng in exclude_list:
                                    continue
                                if self._stop:
                                    break
                                self._pause_check()
                                range_results[ip_rng] = self._scan_common_ports_interruptible(ip_rng, exclude_list=exclude_list)
                        except Exception as e:
                            self.progress.emit(f"Error rango {target}: {e}")
                        results[target] = range_results
                    elif all(c.isdigit() or c == '.' for c in target):
                        if exclude_list and target in exclude_list:
                            continue
                        results[target] = self._scan_common_ports_interruptible(target, exclude_list=exclude_list)
                    else:
                        results[target] = self._scan_domain_interruptible(target, exclude_list=exclude_list)
            except Exception as e:
                self.progress.emit(f"Error archivo: {e}")
            return results

        if p['random']:
            count = p['random_value'] or 10
            try:
                count_int = int(count)
            except ValueError:
                self.progress.emit("Cantidad aleatoria inválida, usando 10.")
                count_int = 10
            self.progress.emit(f"Escaneando {count_int} IPs aleatorias")
            results = {}
            scanned = set()
            generated = 0
            while generated < count_int and not self._stop:
                self._pause_check()
                ip = adv_scan_logic.generate_random_ip()
                if ip in scanned or (exclude_list and ip in exclude_list):
                    continue
                scanned.add(ip)
                self.progress.emit(f"→ IP aleatoria {ip}")
                results[ip] = self._scan_common_ports_interruptible(ip, exclude_list=exclude_list)
                generated += 1
            return results

        self.progress.emit("Debes seleccionar al menos una opción de objetivo.")
        return {}

    def _build_exclude_list(self, p):
        exclude_list = []
        # Manual exclude
        if p['exclude'] and p['exclude_value']:
            exclude_list += [ip.strip() for ip in p['exclude_value'].replace(',', ' ').split() if ip.strip()]
        # From file
        if p['excludefile'] and p['excludefile_value']:
            try:
                with open(p['excludefile_value'], 'r') as f:
                    exclude_list += [line.strip() for line in f if line.strip()]
            except Exception:
                self.progress.emit("No se pudo leer archivo de exclusión.")
        return exclude_list

    def _scan_common_ports_interruptible(self, ip, exclude_list=None):
        if exclude_list and ip in exclude_list:
            self.progress.emit(f"IP {ip} excluida.")
            return []
        try:
            resolved_ip = socket.gethostbyname(ip)
        except Exception:
            self.progress.emit(f"No se pudo resolver {ip}")
            return []
        port_states = []
        start_time = time.time()
        from concurrent.futures import ThreadPoolExecutor, as_completed
        futures = {}
        max_workers = 150
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for port, proto in adv_scan_logic.COMMON_PORTS:
                if self._stop:
                    break
                futures[executor.submit(adv_scan_logic.scan_tcp_port, resolved_ip, port)] = (port, proto)
            for future in as_completed(futures):
                if self._stop:
                    break
                self._pause_check()
                port, proto = futures[future]
                try:
                    port_num, state = future.result()
                except Exception:
                    port_num, state = port, 'filtered'
                service = adv_scan_logic.get_service_name(port_num, proto.lower())
                port_states.append((port, proto, service, state))
                if state == 'open':
                    self.progress.emit(f"{ip} {port}/{proto} ({service}): open")
        elapsed = time.time() - start_time
        if self._stop:
            self.progress.emit(f"Cancelado {ip} en {elapsed:.2f}s")
        else:
            self.progress.emit(f"Completado {ip} en {elapsed:.2f}s")
        return port_states

    def _scan_domain_interruptible(self, domain, exclude_list=None):
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            self.progress.emit(f"No se pudo resolver dominio {domain}")
            return []
        if exclude_list and (domain in exclude_list or ip in exclude_list):
            self.progress.emit(f"Dominio {domain} excluido")
            return []
        start_time = time.time()
        port_states = []
        for port, proto in adv_scan_logic.COMMON_PORTS:
            if self._stop:
                break
            self._pause_check()
            state = self._scan_single_tcp_port(ip, port)
            service = adv_scan_logic.get_service_name(port, proto.lower())
            port_states.append((port, proto, service, state))
            if state == 'open':
                self.progress.emit(f"{domain} {port}/{proto} ({service}): open")
        elapsed = time.time() - start_time
        if self._stop:
            self.progress.emit(f"Dominio {domain} cancelado en {elapsed:.2f}s")
        else:
            self.progress.emit(f"Dominio {domain} completado en {elapsed:.2f}s")
        return port_states

    def _scan_single_tcp_port(self, ip, port, timeout=0.3):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    return 'open'
                elif result in (111, 10061):
                    return 'closed'
                else:
                    return 'filtered'
        except Exception:
            return 'filtered'

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


class QTextEditLogger(logging.Handler, QObject):
    log_signal = Signal(str)
    def __init__(self, text_edit: QTextEdit):
        logging.Handler.__init__(self)
        QObject.__init__(self)
        self.text_edit = text_edit
        self.log_signal.connect(self.text_edit.append)

    def emit(self, record):
        msg = self.format(record)
        self.log_signal.emit(msg)


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
        # Conectar botón cancelar directamente
        self.btn_cancel.clicked.connect(self._cancel_scan)

        # Nuevo botón limpiar consola (papelera)
        self.btn_clear_console = QPushButton()
        self.btn_clear_console.setCursor(Qt.PointingHandCursor)
        self.btn_clear_console.setFixedSize(60, 60)
        self.btn_clear_console.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
        self.btn_clear_console.setStyleSheet("""
            QPushButton {
                background-color: #444;
                color: white;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #666;
            }
        """)
        self.btn_clear_console.setToolTip("Limpiar consola")
        self.btn_clear_console.clicked.connect(self.clear_console)
        btn_layout.addWidget(self.btn_clear_console)

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
        # Si ya hay un hilo corriendo, evitar nuevo
        if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.isRunning():
            self.append_log("Ya hay un escaneo en progreso.")
            return
        self.log_text.clear()
        params = self._collect_params()
        self.append_log("Iniciando escaneo en segundo plano...")
        self.scan_thread = QThread()
        self.worker = ScanWorker(params)
        self.worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.append_log)
        self.worker.error.connect(self._handle_worker_error)
        self.worker.finished.connect(self._handle_worker_finished)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.start()

    def _collect_params(self):
        t = self.target_selector
        return {
            'single_ip': t.checkbox_single_ip.isChecked(),
            'single_ip_value': t.input_single_ip.text().strip(),
            'multiple_ips': t.checkbox_multiple_ips.isChecked(),
            'multiple_ips_value': t.input_multiple_ips.text().strip(),
            'ip_ranges': t.checkbox_ip_range.isChecked(),
            'ip_ranges_value': t.input_ip_ranges.text().strip(),
            'cidr': t.checkbox_cidr.isChecked(),
            'cidr_value': t.input_cidr.text().strip(),
            'domain': t.checkbox_domain.isChecked(),
            'domain_value': t.input_domain.text().strip(),
            'from_file': t.checkbox_from_file.isChecked(),
            'from_file_value': t.input_from_file.text().strip(),
            'random': t.checkbox_random.isChecked(),
            'random_value': t.input_random.text().strip(),
            'exclude': t.checkbox_exclude.isChecked(),
            'exclude_value': t.input_exclude.text().strip(),
            'excludefile': t.checkbox_excludefile.isChecked(),
            'excludefile_value': t.input_excludefile.text().strip(),
        }

    def _handle_worker_error(self, msg):
        self.append_log(f"Error: {msg}")
        if self.scan_thread:
            self.scan_thread.quit()

    def _handle_worker_finished(self, result):
        self.append_log("Escaneo finalizado.")
        self.append_log(str(result))
        if self.scan_thread:
            self.scan_thread.quit()

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
        if not hasattr(self, 'worker'):
            return
        if current_text == "▮▮":
            self.btn_toggle_pause.setText("▶")
            self.append_log("Pausa solicitada.")
            self.worker.pause()
        else:
            self.btn_toggle_pause.setText("▮▮")
            self.append_log("Reanudando.")
            self.worker.resume()

    def clear_console(self):
        self.log_text.clear()

    def _setup_cancel(self):
        if hasattr(self, 'btn_cancel'):
            try:
                self.btn_cancel.clicked.disconnect()
            except Exception:
                pass
            self.btn_cancel.clicked.connect(self._cancel_scan)

    def _cancel_scan(self):
        if hasattr(self, 'worker') and hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            self.append_log("Cancelando escaneo...")
            self.worker.stop()
            # Intentar terminar el hilo después de cancelar
            # El worker saldrá de sus bucles rápidamente por timeouts cortos
            QTimer.singleShot(500, self._force_quit_thread_if_needed)
        else:
            self.append_log("No hay escaneo en curso para cancelar.")

    # Llamar setup cancel después de UI init

    def _force_quit_thread_if_needed(self):
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning() and getattr(self.worker, '_stop', False):
            # Forzar finalización si aún sigue vivo
            try:
                self.scan_thread.requestInterruption()
            except Exception:
                pass
            # Si sigue, llamar quit (solo terminará cuando run retorne)
            self.scan_thread.quit()
            self.append_log("Forzado cierre de hilo tras cancelación.")
