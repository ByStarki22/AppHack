from PySide6.QtWidgets import (
    QGroupBox, QVBoxLayout, QHBoxLayout, QCheckBox, QLineEdit,
    QPushButton, QFileDialog, QLabel
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon
from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets.advance_target_specification import scan_common_ports
import re
import asyncio

class TargetSelectorUI(QGroupBox):
    # Add a signal to emit messages
    message_signal = Signal(str)

    def __init__(self, parent=None):
        super().__init__("Seleccionar objetivo", parent)
        self.init_ui()

    def init_ui(self):
        self.setCursor(Qt.ArrowCursor)
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Checkboxes e inputs existentes
        self.checkbox_single_ip = QCheckBox("Escanear una IP")
        self.checkbox_single_ip.setCursor(Qt.PointingHandCursor)
        self.input_single_ip = QLineEdit()
        self.input_single_ip.setEnabled(False)
        self.input_single_ip.setPlaceholderText("Ej: 192.168.1.10")

        self.checkbox_multiple_ips = QCheckBox("Escanear IPs específicas")
        self.checkbox_multiple_ips.setCursor(Qt.PointingHandCursor)
        self.input_multiple_ips = QLineEdit()
        self.input_multiple_ips.setEnabled(False)
        self.input_multiple_ips.setPlaceholderText("Ej: 192.168.1.10 192.168.1.11")

        self.checkbox_ip_range = QCheckBox("Escanear rangos de IPs")
        self.checkbox_ip_range.setCursor(Qt.PointingHandCursor)
        self.input_ip_ranges = QLineEdit()
        self.input_ip_ranges.setPlaceholderText("Ej: 192.168.1.100-120,192.168.1.200-210")
        self.input_ip_ranges.setEnabled(False)

        self.checkbox_cidr = QCheckBox("Escanear con notación CIDR")
        self.checkbox_cidr.setCursor(Qt.PointingHandCursor)
        self.input_cidr = QLineEdit()
        self.input_cidr.setEnabled(False)
        self.input_cidr.setPlaceholderText("Ej: 192.168.1.0/24")

        self.checkbox_domain = QCheckBox("Escanear un dominio")
        self.checkbox_domain.setCursor(Qt.PointingHandCursor)
        self.input_domain = QLineEdit()
        self.input_domain.setEnabled(False)
        self.input_domain.setPlaceholderText("Ej: ejemplo.com")

        self.checkbox_from_file = QCheckBox("Escanear desde archivo (-iL)")
        self.checkbox_from_file.setCursor(Qt.PointingHandCursor)
        self.input_from_file = QLineEdit()
        self.input_from_file.setPlaceholderText("Ruta al archivo")
        self.input_from_file.setEnabled(False)
        self.btn_browse_file = QPushButton()
        self.btn_browse_file.setIcon(QIcon.fromTheme("folder"))
        self.btn_browse_file.setEnabled(False)
        self.btn_browse_file.setCursor(Qt.PointingHandCursor)
        self.btn_browse_file.setFixedWidth(30)

        self.checkbox_random = QCheckBox("Escanear hosts aleatorios (-iR)")
        self.checkbox_random.setCursor(Qt.PointingHandCursor)
        self.input_random = QLineEdit()
        self.input_random.setPlaceholderText("Ej: 10")
        self.input_random.setEnabled(False)

        self.checkbox_exclude = QCheckBox("Excluir IPs (--exclude)")
        self.checkbox_exclude.setCursor(Qt.PointingHandCursor)
        self.input_exclude = QLineEdit()
        self.input_exclude.setPlaceholderText("Ej: 192.168.1.1 www.ejemplo.com")
        self.input_exclude.setEnabled(False)

        # Nuevas opciones añadidas

        self.checkbox_excludefile = QCheckBox("Excluir desde archivo (--excludefile)")
        self.checkbox_excludefile.setCursor(Qt.PointingHandCursor)
        self.input_excludefile = QLineEdit()
        self.input_excludefile.setPlaceholderText("Ruta al archivo")
        self.input_excludefile.setEnabled(False)
        self.btn_browse_excludefile = QPushButton()
        self.btn_browse_excludefile.setIcon(QIcon.fromTheme("folder"))
        self.btn_browse_excludefile.setEnabled(False)
        self.btn_browse_excludefile.setCursor(Qt.PointingHandCursor)
        self.btn_browse_excludefile.setFixedWidth(30)

        self.checkbox_no_reverse_dns = QCheckBox("No reverse DNS (-n)")
        self.checkbox_no_reverse_dns.setCursor(Qt.PointingHandCursor)

        self.checkbox_reverse_dns_all = QCheckBox("Reverse DNS para todos (-R)")
        self.checkbox_reverse_dns_all.setCursor(Qt.PointingHandCursor)

        self.checkbox_resolve_all = QCheckBox("Escanear todas las direcciones (--resolve-all)")
        self.checkbox_resolve_all.setCursor(Qt.PointingHandCursor)

        self.checkbox_unique = QCheckBox("Escanear cada IP una vez (--unique)")
        self.checkbox_unique.setCursor(Qt.PointingHandCursor)

        self.checkbox_system_dns = QCheckBox("Usar resolver DNS del sistema (--system-dns)")
        self.checkbox_system_dns.setCursor(Qt.PointingHandCursor)

        self.checkbox_dns_servers = QCheckBox("Servidores DNS (--dns-servers)")
        self.checkbox_dns_servers.setCursor(Qt.PointingHandCursor)
        self.input_dns_servers = QLineEdit()
        self.input_dns_servers.setPlaceholderText("Ej: 8.8.8.8,1.1.1.1")
        self.input_dns_servers.setEnabled(False)

        # Lista para alinear checkboxes
        self.checkboxes = [
            self.checkbox_single_ip,
            self.checkbox_multiple_ips,
            self.checkbox_ip_range,
            self.checkbox_cidr,
            self.checkbox_domain,
            self.checkbox_from_file,
            self.checkbox_random,
            self.checkbox_exclude,
            self.checkbox_excludefile,
            self.checkbox_no_reverse_dns,
            self.checkbox_reverse_dns_all,
            self.checkbox_resolve_all,
            self.checkbox_unique,
            self.checkbox_system_dns,
            self.checkbox_dns_servers,
        ]
        self._align_checkboxes_width()

        # Layouts y adiciones al layout principal

        layout.addLayout(self._hbox(self.checkbox_single_ip, self.input_single_ip))
        layout.addLayout(self._hbox(self.checkbox_multiple_ips, self.input_multiple_ips))

        hbox_range = QHBoxLayout()
        hbox_range.addWidget(self.checkbox_ip_range)
        hbox_range.addWidget(self.input_ip_ranges)
        hbox_range.setStretch(0, 0)
        hbox_range.setStretch(1, 1)
        layout.addLayout(hbox_range)

        layout.addLayout(self._hbox(self.checkbox_cidr, self.input_cidr))
        layout.addLayout(self._hbox(self.checkbox_domain, self.input_domain))

        hbox_file = QHBoxLayout()
        hbox_file.addWidget(self.checkbox_from_file)
        hbox_file.addWidget(self.input_from_file)
        hbox_file.addWidget(self.btn_browse_file)
        hbox_file.setStretch(0, 0)
        hbox_file.setStretch(1, 1)
        hbox_file.setStretch(2, 0)
        layout.addLayout(hbox_file)

        layout.addLayout(self._hbox(self.checkbox_random, self.input_random))
        layout.addLayout(self._hbox(self.checkbox_exclude, self.input_exclude))

        hbox_excludefile = QHBoxLayout()
        hbox_excludefile.addWidget(self.checkbox_excludefile)
        hbox_excludefile.addWidget(self.input_excludefile)
        hbox_excludefile.addWidget(self.btn_browse_excludefile)
        hbox_excludefile.setStretch(0, 0)
        hbox_excludefile.setStretch(1, 1)
        hbox_excludefile.setStretch(2, 0)
        layout.addLayout(hbox_excludefile)

        layout.addWidget(self.checkbox_no_reverse_dns)
        layout.addWidget(self.checkbox_reverse_dns_all)
        layout.addWidget(self.checkbox_resolve_all)
        layout.addWidget(self.checkbox_unique)
        layout.addWidget(self.checkbox_system_dns)

        layout.addLayout(self._hbox(self.checkbox_dns_servers, self.input_dns_servers))

        self.setLayout(layout)

        # Conexiones para habilitar inputs
        self.checkbox_single_ip.toggled.connect(lambda c: self.enable_input(self.input_single_ip, c))
        self.checkbox_multiple_ips.toggled.connect(lambda c: self.enable_input(self.input_multiple_ips, c))
        self.checkbox_ip_range.toggled.connect(lambda c: self.enable_input(self.input_ip_ranges, c))
        self.checkbox_cidr.toggled.connect(lambda c: self.enable_input(self.input_cidr, c))
        self.checkbox_domain.toggled.connect(lambda c: self.enable_input(self.input_domain, c))
        self.checkbox_from_file.toggled.connect(self.toggle_from_file_input)
        self.checkbox_random.toggled.connect(lambda c: self.enable_input(self.input_random, c))
        self.checkbox_exclude.toggled.connect(lambda c: self.enable_input(self.input_exclude, c))
        self.checkbox_excludefile.toggled.connect(self.toggle_excludefile_input)
        self.checkbox_dns_servers.toggled.connect(lambda c: self.enable_input(self.input_dns_servers, c))
        self.checkbox_excludefile.toggled.connect(lambda c: self.btn_browse_excludefile.setEnabled(c))
        self.checkbox_from_file.toggled.connect(lambda c: self.btn_browse_file.setEnabled(c))

        inputs = [
            self.input_single_ip, self.input_multiple_ips,
            self.input_ip_ranges,  # Cambiado aquí
            self.input_cidr,       # <-- Agregado aquí
            self.input_domain, self.input_from_file,
            self.input_random, self.input_exclude, self.input_excludefile,
            self.input_dns_servers
        ]
        for inp in inputs:
            inp.textChanged.connect(lambda _, i=inp: self.update_input_style(i))

        self.btn_browse_file.clicked.connect(self.open_file_dialog)
        self.btn_browse_excludefile.clicked.connect(self.open_excludefile_dialog)

    def _hbox(self, *widgets):
        box = QHBoxLayout()
        for i, w in enumerate(widgets):
            box.addWidget(w)
            box.setStretch(i, 1 if i > 0 else 0)
        return box

    def _align_checkboxes_width(self):
        max_width = max(cb.sizeHint().width() for cb in self.checkboxes)
        max_width += 60
        for cb in self.checkboxes:
            cb.setFixedWidth(max_width)

    def enable_input(self, input_widget, enable):
        input_widget.setEnabled(enable)
        self.update_input_style(input_widget)

    def toggle_ip_range_inputs(self, checked):
        self.input_ip_ranges.setEnabled(checked)
        self.update_input_style(self.input_ip_ranges)

    def toggle_from_file_input(self, checked):
        self.input_from_file.setEnabled(checked)
        self.btn_browse_file.setEnabled(checked)
        self.update_input_style(self.input_from_file)

    def toggle_excludefile_input(self, checked):
        self.input_excludefile.setEnabled(checked)
        self.btn_browse_excludefile.setEnabled(checked)
        self.update_input_style(self.input_excludefile)

    def is_valid_ip(self, ip):
        # Validación simple de IPv4
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not pattern.match(ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)

    def is_valid_cidr(self, cidr):
        # Validación simple de notación CIDR IPv4
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")
        if not pattern.match(cidr):
            return False
        ip, prefix = cidr.split('/')
        if not self.is_valid_ip(ip):
            return False
        try:
            prefix = int(prefix)
            return 0 <= prefix <= 32
        except ValueError:
            return False

    def update_input_style(self, input_widget):
        # Borde rojo si la IP no es válida y está habilitado el escaneo de una IP
        if input_widget == self.input_single_ip and self.checkbox_single_ip.isChecked():
            ip = input_widget.text().strip()
            if ip and not self.is_valid_ip(ip):
                input_widget.setStyleSheet("border: 2px solid red;")
                return
        # Validación para input_multiple_ips: solo espacios como separador y todas IPs válidas
        if input_widget == self.input_multiple_ips and self.checkbox_multiple_ips.isChecked():
            ips = input_widget.text().strip()
            if ips:
                # No debe haber comas ni otros separadores
                if ',' in ips or '\t' in ips or ';' in ips or '\n' in ips:
                    input_widget.setStyleSheet("border: 2px solid red;")
                    return
                ip_list = [ip for ip in ips.split(' ') if ip]
                if not all(self.is_valid_ip(ip) for ip in ip_list):
                    input_widget.setStyleSheet("border: 2px solid red;")
                    return
        # Validación para input_ip_ranges (nuevo)
        if input_widget == self.input_ip_ranges and self.checkbox_ip_range.isChecked():
            val = input_widget.text().strip()
            if val:
                # Validar formato: 192.168.1.100-120,192.168.1.200-210
                pattern = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3})(,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3})*$")
                if not pattern.match(val.replace(' ', '')):
                    input_widget.setStyleSheet("border: 2px solid red;")
                    return
                # Validar que en cada rango el inicio sea menor que el fin y que ambos estén en 0-255
                for r in val.replace(' ', '').split(','):
                    if '-' not in r:
                        input_widget.setStyleSheet("border: 2px solid red;")
                        return
                    base, end = r.split('-')
                    base_parts = base.split('.')
                    if len(base_parts) != 4:
                        input_widget.setStyleSheet("border: 2px solid red;")
                        return
                    try:
                        start = int(base_parts[3])
                        end = int(end)
                        if not (0 <= start <= 255 and 0 <= end <= 255):
                            input_widget.setStyleSheet("border: 2px solid red;")
                            return
                        if start > end:
                            input_widget.setStyleSheet("border: 2px solid red;")
                            return
                    except Exception:
                        input_widget.setStyleSheet("border: 2px solid red;")
                        return
            input_widget.setStyleSheet("")
        # Validación para input_ip_range_start y input_ip_range_end
        if (hasattr(self, 'input_ip_range_start') and hasattr(self, 'input_ip_range_end') and (input_widget == self.input_ip_range_start or input_widget == self.input_ip_range_end)) and self.checkbox_ip_range.isChecked():
            start = self.input_ip_range_start.text().strip()
            end = self.input_ip_range_end.text().strip()
            # Marcar en rojo si uno está lleno y el otro vacío
            if (start and not end):
                # Si el formato de start es inválido, prioriza el error de formato
                if not self.is_valid_ip(start):
                    self.input_ip_range_start.setStyleSheet("border: 2px solid red;")
                    self.input_ip_range_end.setStyleSheet("")
                else:
                    self.input_ip_range_start.setStyleSheet("")
                    self.input_ip_range_end.setStyleSheet("border: 2px solid red;")
                return
            elif (end and not start):
                if not self.is_valid_ip(end):
                    self.input_ip_range_end.setStyleSheet("border: 2px solid red;")
                    self.input_ip_range_start.setStyleSheet("")
                else:
                    self.input_ip_range_end.setStyleSheet("")
                    self.input_ip_range_start.setStyleSheet("border: 2px solid red;")
                return
            # Si ambos tienen valor, primero valida formato
            if (start and not self.is_valid_ip(start)) or (end and not self.is_valid_ip(end)):
                self.input_ip_range_start.setStyleSheet("border: 2px solid red;" if start and not self.is_valid_ip(start) else "")
                self.input_ip_range_end.setStyleSheet("border: 2px solid red;" if end and not self.is_valid_ip(end) else "")
                return
            # Nueva validación: inicio > fin
            elif start and end and self.is_valid_ip(start) and self.is_valid_ip(end):
                def ip_to_tuple(ip):
                    return tuple(int(part) for part in ip.split('.'))
                if ip_to_tuple(start) > ip_to_tuple(end):
                    self.input_ip_range_start.setStyleSheet("border: 2px solid red;")
                    self.input_ip_range_end.setStyleSheet("border: 2px solid red;")
                    return
                else:
                    self.input_ip_range_start.setStyleSheet("")
                    self.input_ip_range_end.setStyleSheet("")
            else:
                self.input_ip_range_start.setStyleSheet("")
                self.input_ip_range_end.setStyleSheet("")
        # Validación para input_cidr
        if input_widget == self.input_cidr:
            if self.checkbox_cidr.isChecked():
                cidr = input_widget.text().strip()
                if cidr:
                    # Validar formato CIDR: IP/prefijo
                    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$")
                    match = pattern.match(cidr)
                    if not match:
                        input_widget.setStyleSheet("border: 2px solid red;")
                        return
                    ip, prefix = cidr.split('/')
                    if not self.is_valid_ip(ip):
                        input_widget.setStyleSheet("border: 2px solid red;")
                        return
                    try:
                        prefix = int(prefix)
                        if not (24 <= prefix <= 32):
                            input_widget.setStyleSheet("border: 2px solid red;")
                            return
                    except ValueError:
                        input_widget.setStyleSheet("border: 2px solid red;")
                        return
                    input_widget.setStyleSheet("")
                else:
                    input_widget.setStyleSheet("")
            else:
                # Si el input está deshabilitado y tiene texto, ponlo en gris
                if not input_widget.isEnabled() and input_widget.text():
                    input_widget.setStyleSheet("color: gray;")
                else:
                    input_widget.setStyleSheet("")
        # Validación para input_ip_range_start y input_ip_range_end
        if (hasattr(self, 'input_ip_range_start') and hasattr(self, 'input_ip_range_end')):
            start = self.input_ip_range_start.text().strip()
            end = self.input_ip_range_end.text().strip()
            if start and not end:
                if not self.is_valid_ip(start):
                    self.input_ip_range_start.setStyleSheet("border: 2px solid red;")
                else:
                    self.input_ip_range_start.setStyleSheet("")
                    self.input_ip_range_end.setStyleSheet("border: 2px solid red;")
            elif end and not start:
                if not self.is_valid_ip(end):
                    self.input_ip_range_end.setStyleSheet("border: 2px solid red;")
                else:
                    self.input_ip_range_end.setStyleSheet("")
                    self.input_ip_range_start.setStyleSheet("border: 2px solid red;")
            elif start and end and self.is_valid_ip(start) and self.is_valid_ip(end):
                def ip_to_tuple(ip):
                    return tuple(int(part) for part in ip.split('.'))
                if ip_to_tuple(start) > ip_to_tuple(end):
                    self.input_ip_range_start.setStyleSheet("border: 2px solid red;")
                    self.input_ip_range_end.setStyleSheet("border: 2px solid red;")
                else:
                    self.input_ip_range_start.setStyleSheet("")
                    self.input_ip_range_end.setStyleSheet("")
            else:
                self.input_ip_range_start.setStyleSheet("")
                self.input_ip_range_end.setStyleSheet("")
        # ...existing code for other widgets...
        if not input_widget.isEnabled() and input_widget.text() and input_widget != self.input_cidr:
            input_widget.setStyleSheet("color: gray;")
        else:
            if input_widget not in [getattr(self, 'input_ip_range_start', None), getattr(self, 'input_ip_range_end', None), self.input_cidr]:
                input_widget.setStyleSheet("")

    def open_file_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo de texto",
            "",
            "Archivos de texto (*.txt)"
        )
        if file_path:
            self.input_from_file.setText(file_path)

    def open_excludefile_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo de texto para excluir",
            "",
            "Archivos de texto (*.txt)"
        )
        if file_path:
            self.input_excludefile.setText(file_path)

    def get_selected_targets(self):
        # Retorna una lista de strings con todas las opciones seleccionadas y sus inputs
        targets = []
        if self.checkbox_single_ip.isChecked():
            val = self.input_single_ip.text().strip()
            if val:
                targets.append(val)

        if self.checkbox_multiple_ips.isChecked():
            val = self.input_multiple_ips.text().strip()
            if val:
                targets.append(val)

        if self.checkbox_ip_range.isChecked():
            val = self.input_ip_ranges.text().strip()
            if val:
                targets.append(val)

        if self.checkbox_cidr.isChecked():
            val = self.input_cidr.text().strip()
            if val:
                targets.append(val)

        if self.checkbox_domain.isChecked():
            val = self.input_domain.text().strip()
            if val:
                targets.append(val)

        if self.checkbox_from_file.isChecked():
            val = self.input_from_file.text().strip()
            if val:
                targets.append(f"-iL {val}")

        if self.checkbox_random.isChecked():
            val = self.input_random.text().strip()
            if val:
                targets.append(f"-iR {val}")

        if self.checkbox_exclude.isChecked():
            val = self.input_exclude.text().strip()
            if val:
                targets.append(f"--exclude {val}")

        if self.checkbox_excludefile.isChecked():
            val = self.input_excludefile.text().strip()
            if val:
                targets.append(f"--excludefile {val}")

        if self.checkbox_no_reverse_dns.isChecked():
            targets.append("-n")

        if self.checkbox_reverse_dns_all.isChecked():
            targets.append("-R")

        if self.checkbox_resolve_all.isChecked():
            targets.append("--resolve-all")

        if self.checkbox_unique.isChecked():
            targets.append("--unique")

        if self.checkbox_system_dns.isChecked():
            targets.append("--system-dns")

        if self.checkbox_dns_servers.isChecked():
            val = self.input_dns_servers.text().strip()
            if val:
                targets.append(f"--dns-servers {val}")

        return targets
    
    def get_exclude_list(self):
        exclude_list = []
        # Excluir IPs manuales
        if self.checkbox_exclude.isChecked():
            val = self.input_exclude.text().strip()
            if val:
                exclude_list += [ip.strip() for ip in val.replace(',', ' ').split() if ip.strip()]
        # Excluir desde archivo
        if self.checkbox_excludefile.isChecked():
            file_path = self.input_excludefile.text().strip()
            if file_path:
                try:
                    with open(file_path, 'r') as f:
                        exclude_list += [line.strip() for line in f if line.strip()]
                except Exception:
                    pass  # Puedes emitir un mensaje si quieres
        return exclude_list

    def on_scan_button_clicked(self):
        # Check if at least one target selection option is enabled
        if not any([
            self.checkbox_single_ip.isChecked(),
            self.checkbox_multiple_ips.isChecked(),
            self.checkbox_ip_range.isChecked(),
            self.checkbox_cidr.isChecked(),
            self.checkbox_domain.isChecked(),
            self.checkbox_from_file.isChecked(),
            self.checkbox_random.isChecked()
        ]):
            self.message_signal.emit("Debes seleccionar al menos una opción de objetivo.")
            return

        # Escanear una IP específica
        if self.checkbox_single_ip.isChecked():
            ip = self.input_single_ip.text().strip()
            exclude_list = self.get_exclude_list()
            if ip:
                from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets.advance_target_specification import scan_common_ports
                open_ports = scan_common_ports(ip, exclude_list=exclude_list)
                # self.message_signal.emit(f"Resultado para {ip}: {open_ports}")  # Eliminado
            else:
                self.message_signal.emit("Debes ingresar una IP válida.")
            return

        exclude_list = self.get_exclude_list()

        # Escanear IPs específicas (varias separadas por coma o espacio)
        if self.checkbox_multiple_ips.isChecked():
            ips = self.input_multiple_ips.text().strip()
            if ips:
                ip_list = [ip.strip() for ip in ips.replace(',', ' ').split() if ip.strip()]
                from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets.advance_target_specification import scan_multiple_ips
                results = scan_multiple_ips(ip_list, exclude_list=exclude_list)
                # for ip, ports in results.items():
                #     self.message_signal.emit(f"Resultado para {ip}: {ports}")  # Eliminado
            else:
                self.message_signal.emit("Debes ingresar al menos una IP.")
            return

        # Escanear rangos de IPs (nuevo input)
        if self.checkbox_ip_range.isChecked():
            ranges = self.input_ip_ranges.text().strip()
            if ranges:
                try:
                    from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets.advance_target_specification import scan_multiple_ip_ranges
                    results = scan_multiple_ip_ranges(ranges, exclude_list=exclude_list)
                    if not results:
                        self.message_signal.emit(f"No se encontraron hosts con puertos abiertos en los rangos especificados.")
                    # for ip, ports in results.items():
                    #     self.message_signal.emit(f"Resultado para {ip}: {ports}")  # Eliminado
                except Exception as e:
                    self.message_signal.emit(f"Error: {str(e)}")
            else:
                self.message_signal.emit("Debes ingresar al menos un rango de IP.")
            return

        # Escanear notación CIDR
        if self.checkbox_cidr.isChecked():
            cidr = self.input_cidr.text().strip()
            if cidr:
                try:
                    from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets.advance_target_specification import scan_cidr
                    results = scan_cidr(cidr, exclude_list=exclude_list)
                    if not results:
                        self.message_signal.emit(f"No se encontraron hosts con puertos abiertos en el rango CIDR.")
                    # for ip, ports in results.items():
                    #     self.message_signal.emit(f"Resultado para {ip}: {ports}")  # Eliminado
                except Exception as e:
                    self.message_signal.emit(f"Error: {str(e)}")
            else:
                self.message_signal.emit("Debes ingresar una notación CIDR válida.")
            return

        # Escanear un dominio
        if self.checkbox_domain.isChecked():
            domain = self.input_domain.text().strip()
            exclude_list = self.get_exclude_list()
            if domain:
                try:
                    from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets.advance_target_specification import scan_domain
                    async def run_scan():
                        open_ports = await scan_domain(domain, exclude_list=exclude_list)
                        if open_ports:
                            pass
                        else:
                            self.message_signal.emit(f"No se encontraron puertos abiertos para el dominio {domain}.")
                    asyncio.run(run_scan())
                except Exception as e:
                    self.message_signal.emit(f"Error: {str(e)}")
            else:
                self.message_signal.emit("Debes ingresar un dominio válido.")
            return

        # Escanear desde archivo (-iL)
        if self.checkbox_from_file.isChecked():
            file_path = self.input_from_file.text().strip()
            if file_path:
                try:
                    from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets.advance_target_specification import scan_targets_from_file
                    results = scan_targets_from_file(file_path, exclude_list=exclude_list)
                    if not results:
                        self.message_signal.emit("No se encontraron hosts o puertos abiertos en el archivo.")
                    # Puedes emitir los resultados aquí si lo deseas
                    # for target, ports in results.items():
                    #     self.message_signal.emit(f"Resultado para {target}: {ports}")
                except Exception as e:
                    self.message_signal.emit(f"Error al escanear desde archivo: {str(e)}")
            else:
                self.message_signal.emit("Debes seleccionar un archivo de objetivos.")
            return

        # Escanear hosts aleatorios (-iR)
        if self.checkbox_random.isChecked():
            num = self.input_random.text().strip()
            if num:
                try:
                    n = int(num)
                    if n <= 0:
                        self.message_signal.emit("Debes ingresar un número mayor a 0.")
                        return
                    from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets.advance_target_specification import scan_random_ips
                    results = scan_random_ips(n, exclude_list=exclude_list)
                    if not results:
                        self.message_signal.emit(f"No se encontraron hosts con puertos abiertos en los {n} hosts aleatorios.")
                    # Puedes emitir los resultados aquí si lo deseas
                    # for ip, ports in results.items():
                    #     self.message_signal.emit(f"Resultado para {ip}: {ports}")
                except ValueError:
                    self.message_signal.emit("Debes ingresar un número válido.")
                except Exception as e:
                    self.message_signal.emit(f"Error: {str(e)}")
            else:
                self.message_signal.emit("Debes ingresar la cantidad de hosts aleatorios a escanear.")
            return

        # Puedes agregar lógica similar para otras opciones si lo deseas
        self.message_signal.emit("Funcionalidad no implementada para esta opción aún.")