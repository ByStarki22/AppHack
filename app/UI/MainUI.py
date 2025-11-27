from PySide6.QtWidgets import (
    QWidget, QPushButton, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QSizePolicy, QStackedWidget,
)
import os 
from PySide6.QtCore import Qt, QPropertyAnimation
from PySide6.QtGui import QFont

import subprocess  # <--- Añade este import al inicio del archivo
from app.UI.toolsUI.portScannerUI.scan_typeUI.main_scan_typeUI import ScanTypeWidget

class Interfaz(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Toolkit Modern UI")
        self.setMinimumSize(1400, 900)
        self.setStyleSheet("QWidget { background-color: #101010; font-family: 'Segoe UI', sans-serif; }")

        self.panel_lateral_visible = True
        self.panel_lateral_derecho_visible = True  # Nuevo
        self.ultima_altura_terminal = 500  # <-- Añade esto para guardar la última altura

        layout_principal = QHBoxLayout(self)
        layout_principal.setContentsMargins(10, 10, 10, 10)
        layout_principal.setSpacing(10)

        self.boton_activo = None
        self.boton_derecho_activo = None  # <--- Añadido

        # Panel lateral izquierdo
        self.panel_lateral = QFrame()
        self.panel_lateral.setMinimumWidth(100)
        self.panel_lateral.setMaximumWidth(240)
        self.panel_lateral.setStyleSheet("""
            QFrame {
                background-color: #1f1f1f;
                border-radius: 15px;
            }
            QPushButton {
                color: #ffffff;
                background-color: #2b2b2b;
                border-radius: 10px;
                padding: 14px 22px;
                margin: 6px 10px;
                font-size: 15px;
                font-weight: 500;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #3c3c3c;
            }
            QPushButton:pressed {
                background-color: #4c4c4c;
            }
            QPushButton[active="true"] {
                background-color: #00aa88;
                color: #ffffff;
                font-weight: bold;
            }
        """)

        layout_lateral = QVBoxLayout(self.panel_lateral)
        layout_lateral.setContentsMargins(10, 20, 10, 20)  # <--- MÁRGENES
        layout_lateral.setSpacing(10)

        # Lista de herramientas con iconos (puedes cambiar los emojis por QIcon si prefieres)
        herramientas = [
            ("Escáner de Puertos", "📡"),
            ("Fuerza Bruta", "💪"),
            ("Generador de Payloads", "🛠️"),
            ("Crack de Hashes", "🔑"),
            ("Sniffer de Paquetes", "🐍")
        ]

        self.botones = {}
        for herramienta, icono in herramientas:
            btn = QPushButton()
            btn.setProperty("active", False)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            btn.setCursor(Qt.PointingHandCursor)  # <-- Añade esta línea
            btn.clicked.connect(lambda checked, h=herramienta, b=btn: self.seleccionar_herramienta(h, b))
            btn.icono = icono  # guardamos el icono para uso posterior
            btn.setText(f"{icono}  {herramienta}")  # texto inicial con icono
            btn.setStyleSheet("text-align: left;")
            layout_lateral.addWidget(btn)
            self.botones[herramienta] = btn

        layout_lateral.addStretch()
        
        # --- Botón Casa (Home) ---
        self.boton_casa = QPushButton("\u2302")  # ⌂
        self.boton_casa.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.boton_casa.setCursor(Qt.PointingHandCursor)
        self.boton_casa.setStyleSheet("""
            QPushButton {
                color: #ffffff;
                border: none;
                font-size: 28px;
                padding: 10px 0;
                margin: 6px 0 6px 0;
            }
            QPushButton:hover {
                color: #00ffcc;
            }
        """)
        self.boton_casa.clicked.connect(self.mostrar_home)

        # --- Botón Hamburguesa ---
        self.boton_hamburguesa = QPushButton("≡")
        self.boton_hamburguesa.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.boton_hamburguesa.setCursor(Qt.PointingHandCursor)
        self.boton_hamburguesa.setStyleSheet("""
            QPushButton {
                color: #ffffff;
                border: none;
                font-size: 28px;
                padding: 10px 0;
                margin: 6px 0 6px 0;
            }
            QPushButton:hover {
                color: #00ffcc;
            }
        """)
        self.boton_hamburguesa.clicked.connect(self.toggle_panel_lateral)

        # --- Botón Terminal (simple, tipo casa) ---
        self.boton_terminal = QPushButton(">_")
        self.boton_terminal.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.boton_terminal.setCursor(Qt.PointingHandCursor)
        self.boton_terminal.setStyleSheet("""
            QPushButton {
                color: #ffffff;
                border: none;
                font-size: 28px;
                padding: 10px 0;
                margin: 6px 0 6px 0;
            }
            QPushButton:hover {
                color: #00ffcc;
            }
        """)
        self.boton_terminal.clicked.connect(self.abrir_terminal)  # <--- Activa la conexión

        # --- Contenedor para los tres botones (dinámico) ---
        self.botones_inferiores_widget = QWidget()
        self.botones_inferiores_widget.setStyleSheet("background: transparent;")
        self.botones_inferiores_layout = QHBoxLayout()
        self.botones_inferiores_layout.setContentsMargins(0, 0, 0, 0)
        self.botones_inferiores_layout.setSpacing(0)
        self.botones_inferiores_layout.addWidget(self.boton_casa, alignment=Qt.AlignCenter)
        self.botones_inferiores_layout.addSpacing(50)  # Espacio entre casa y hamburguesa
        self.botones_inferiores_layout.addWidget(self.boton_hamburguesa, alignment=Qt.AlignCenter)
        self.botones_inferiores_layout.addSpacing(50)  # Espacio entre hamburguesa y terminal
        self.botones_inferiores_layout.addWidget(self.boton_terminal, alignment=Qt.AlignRight)
        self.botones_inferiores_widget.setLayout(self.botones_inferiores_layout)
        layout_lateral.addWidget(self.botones_inferiores_widget, alignment=Qt.AlignHCenter)

        # Panel lateral derecho (usando QStackedWidget)
        self.panel_lateral_derecho_stack = QStackedWidget()
        self.panel_lateral_derecho_stack.setMinimumWidth(100)
        self.panel_lateral_derecho_stack.setMaximumWidth(240)

        self.paneles_derechos = {}
        self.botones_derecho = {}  # <--- Añadido

        # Crea un panel derecho para cada herramienta
        for herramienta, icono in herramientas:
            panel = QFrame()
            panel.setStyleSheet(self.panel_lateral.styleSheet())
            layout = QVBoxLayout(panel)
            layout.setContentsMargins(10, 20, 10, 20)
            layout.setSpacing(10)
            # Opciones del panel derecho
            if herramienta == "Escáner de Puertos":
                opciones = [
                    f"{icono} Escaneo",
                    f"{icono} Objetivos",
                    f"{icono} Historial",
                    f"{icono} Configuración",
                    f"{icono} Guía"
                ]
                for opcion in opciones:
                    btn = QPushButton(opcion)
                    btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
                    btn.setCursor(Qt.PointingHandCursor)
                    layout.addWidget(btn)
                    self.botones_derecho[opcion] = btn
                    btn.clicked.connect(lambda checked, o=opcion, b=btn, h=herramienta: self.seleccionar_opcion_derecha(h, o, b))
            else:
                for i in range(3):
                    opcion = f"{icono} Opción {i+1} de {herramienta}"
                    btn = QPushButton(opcion)
                    btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
                    btn.setCursor(Qt.PointingHandCursor)
                    layout.addWidget(btn)
                    self.botones_derecho[opcion] = btn
                    btn.clicked.connect(lambda checked, o=opcion, b=btn, h=herramienta: self.seleccionar_opcion_derecha(h, o, b))
            layout.addStretch()
            # Botón hamburguesa derecho abajo
            boton_hamburguesa_derecho = QPushButton("≡")
            boton_hamburguesa_derecho.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            boton_hamburguesa_derecho.setCursor(Qt.PointingHandCursor)
            boton_hamburguesa_derecho.setStyleSheet("""
                QPushButton {
                    color: #ffffff;
                    background: transparent;
                    border: none;
                    font-size: 28px;
                    padding: 10px 0;
                    margin: 6px 0;
                }
                QPushButton:hover {
                    color: #00ffcc;
                    background: transparent;
                }
            """)
            boton_hamburguesa_derecho.clicked.connect(self.toggle_panel_lateral_derecho)
            layout.addWidget(boton_hamburguesa_derecho, alignment=Qt.AlignHCenter | Qt.AlignBottom)
            self.panel_lateral_derecho_stack.addWidget(panel)
            self.paneles_derechos[herramienta] = panel

        # Panel derecho por defecto (si no hay selección)
        panel_default = QFrame()
        panel_default.setStyleSheet(self.panel_lateral.styleSheet())
        layout_default = QVBoxLayout(panel_default)
        layout_default.setContentsMargins(10, 20, 10, 20)
        layout_default.setSpacing(10)
        layout_default.addWidget(QLabel("Selecciona una herramienta"))
        layout_default.addStretch()
        boton_hamburguesa_derecho_default = QPushButton("≡")
        boton_hamburguesa_derecho_default.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        boton_hamburguesa_derecho_default.setCursor(Qt.PointingHandCursor)
        boton_hamburguesa_derecho_default.setStyleSheet("""
            QPushButton {
                color: #ffffff;
                background: transparent;
                border: none;
                font-size: 28px;
                padding: 10px 0;
                margin: 6px 0;
            }
            QPushButton:hover {
                color: #00ffcc;
                background: transparent;
            }
        """)
        boton_hamburguesa_derecho_default.clicked.connect(self.toggle_panel_lateral_derecho)
        layout_default.addWidget(boton_hamburguesa_derecho_default, alignment=Qt.AlignHCenter | Qt.AlignBottom)
        self.panel_lateral_derecho_stack.addWidget(panel_default)
        self.paneles_derechos["default"] = panel_default
        self.panel_lateral_derecho_stack.setCurrentWidget(panel_default)

        # Panel de contenido
        self.panel_contenido = QFrame()
        self.panel_contenido.setStyleSheet("""
            QFrame {
                background-color: #181818;
                border-radius: 20px;
            }
            QLabel {
                color: #e0e0e0;
            }
        """)
        self.panel_contenido.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout_contenido = QVBoxLayout(self.panel_contenido)
        layout_contenido.setContentsMargins(30, 30, 30, 40)  # <--- Cambia el último valor (margen inferior)
        layout_contenido.setSpacing(20)

        # Ya no agregamos el botón aquí
        # layout_contenido.addWidget(self.boton_hamburguesa, alignment=Qt.AlignLeft)

        self.label_contenido = QLabel("👋 Bienvenido al Security Toolkit")
        self.label_contenido.setFont(QFont("Segoe UI", 20, QFont.Bold))
        self.label_contenido.setStyleSheet("color: #00ffcc;")
        layout_contenido.addWidget(self.label_contenido, alignment=Qt.AlignTop)

        # Agrega los paneles al layout principal
        layout_principal.addWidget(self.panel_lateral)
        layout_principal.addWidget(self.panel_lateral_derecho_stack)  # <-- usa el stack
        layout_principal.addWidget(self.panel_contenido)

        # Oculta el panel derecho al inicio (en Home)
        self.panel_lateral_derecho_stack.hide()

        # Animaciones
        self.animacion_panel = QPropertyAnimation(self.panel_lateral, b"maximumWidth")
        self.animacion_panel.setDuration(200)

        self.animacion_panel_derecho = QPropertyAnimation(self.panel_lateral_derecho_stack, b"maximumWidth")
        self.animacion_panel_derecho.setDuration(200)

        # --- INTEGRACIÓN ---
        # self.escaner_widget = EscanerPuertosWidget()  # Eliminado
        self.panel_contenido_layout = layout_contenido  # guardar referencia al layout

        # --- QSplitter vertical para contenido central + terminal ---
        # ELIMINADO: panel_terminal, cmd_output, cmd_input, cmd_process, splitter, toggle_panel_terminal, _leer_salida_cmd, _enviar_comando_cmd

        # --- Agrega el panel_contenido directamente al layout principal ---
        layout_principal.addWidget(self.panel_contenido)

        # --- Elimina la animación del panel terminal ---
        # self.boton_terminal.clicked.connect(self.toggle_panel_terminal)  # ELIMINADO

    def toggle_panel_lateral(self):
        if self.panel_lateral_visible:
            self.animacion_panel.setStartValue(self.panel_lateral.width())
            self.animacion_panel.setEndValue(100)
            self.animacion_panel.finished.connect(self._cambiar_botones_vertical)
        else:
            self.animacion_panel.setStartValue(self.panel_lateral.width())
            self.animacion_panel.setEndValue(240)
            self.animacion_panel.finished.connect(self._cambiar_botones_horizontal)
        self.animacion_panel.start()
        self.panel_lateral_visible = not self.panel_lateral_visible

    def _cambiar_botones_vertical(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.boton_casa, alignment=Qt.AlignCenter)
        layout.addWidget(self.boton_hamburguesa, alignment=Qt.AlignCenter)
        layout.addWidget(self.boton_terminal, alignment=Qt.AlignCenter)
        QWidget().setLayout(self.botones_inferiores_widget.layout())
        self.botones_inferiores_widget.setLayout(layout)
        self.animacion_panel.finished.disconnect()

    def _cambiar_botones_horizontal(self):
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.boton_casa, alignment=Qt.AlignCenter)
        layout.addSpacing(50)  # Espacio entre casa y hamburguesa
        layout.addWidget(self.boton_hamburguesa, alignment=Qt.AlignCenter)
        layout.addSpacing(50)  # Espacio entre hamburguesa y terminal
        layout.addWidget(self.boton_terminal, alignment=Qt.AlignRight)
        QWidget().setLayout(self.botones_inferiores_widget.layout())
        self.botones_inferiores_widget.setLayout(layout)
        self.animacion_panel.finished.disconnect()

    def toggle_panel_lateral_derecho(self):
        if self.panel_lateral_derecho_visible:
            self.animacion_panel_derecho.setStartValue(self.panel_lateral_derecho_stack.width())
            self.animacion_panel_derecho.setEndValue(100)
            self.animacion_panel_derecho.finished.connect(self._ocultar_textos_derecho)
        else:
            self.animacion_panel_derecho.setStartValue(self.panel_lateral_derecho_stack.width())
            self.animacion_panel_derecho.setEndValue(240)
            self.animacion_panel_derecho.finished.connect(self._mostrar_textos_derecho)
        self.animacion_panel_derecho.start()
        self.panel_lateral_derecho_visible = not self.panel_lateral_derecho_visible

    def _ocultar_textos(self):
        for btn in self.botones.values():
            btn.setText(btn.icono)  # Solo icono
            btn.setStyleSheet("text-align: center; padding: 14px 0;")  # Centrar el icono
        # Ya no ocultamos el botón casa
        self.animacion_panel.finished.disconnect()

    def _mostrar_textos(self):
        for herramienta, btn in self.botones.items():
            btn.setText(f"{btn.icono}  {herramienta}")  # Icono + texto
            btn.setStyleSheet("text-align: left; padding: 14px 22px;")  # Alineación original
        # Ya no mostramos el botón casa porque siempre está visible
        self.animacion_panel.finished.disconnect()

    def _ocultar_textos_derecho(self):
        for btn in self.botones_derecho.values():
            btn.setText(btn.icono)  # Solo icono
            btn.setStyleSheet("text-align: center; padding: 14px 0;")  # Centrar el icono
        self.animacion_panel_derecho.finished.disconnect()

    def _mostrar_textos_derecho(self):
        for opcion, btn in self.botones_derecho.items():
            btn.setText(opcion)  # Icono + texto
            btn.setStyleSheet("text-align: left; padding: 14px 22px;")  # Alineación original
        self.animacion_panel_derecho.finished.disconnect()

    def seleccionar_herramienta(self, herramienta, boton):
        # Limpia el contenido anterior
        for i in reversed(range(self.panel_contenido_layout.count())):
            widget = self.panel_contenido_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        # Cambia el botón activo
        if self.boton_activo:
            self.boton_activo.setProperty("active", False)
            self.boton_activo.style().unpolish(self.boton_activo)
            self.boton_activo.style().polish(self.boton_activo)
        boton.setProperty("active", True)
        boton.style().unpolish(boton)
        boton.style().polish(boton)
        self.boton_activo = boton

        # Limpia selección derecha al cambiar de herramienta
        if self.boton_derecho_activo:
            self.boton_derecho_activo.setProperty("active", False)
            self.boton_derecho_activo.style().unpolish(self.boton_derecho_activo)
            self.boton_derecho_activo.style().polish(self.boton_derecho_activo)
            self.boton_derecho_activo = None

        # Mostrar el panel derecho solo si se selecciona una herramienta
        self.panel_lateral_derecho_stack.show()

        # Cambia el panel derecho mostrado
        if herramienta in self.paneles_derechos:
            self.panel_lateral_derecho_stack.setCurrentWidget(self.paneles_derechos[herramienta])
        else:
            self.panel_lateral_derecho_stack.setCurrentWidget(self.paneles_derechos["default"])

        # --- Solo muestra mensaje de selección ---
        self.label_contenido = QLabel(f"🔍 {herramienta} seleccionado...")
        self.label_contenido.setFont(QFont("Segoe UI", 20, QFont.Bold))
        self.label_contenido.setStyleSheet("color: #00ffcc;")
        self.panel_contenido_layout.addWidget(self.label_contenido, alignment=Qt.AlignTop)

    def seleccionar_opcion_derecha(self, herramienta, opcion, boton):
        # Desmarca el botón anterior
        if self.boton_derecho_activo:
            self.boton_derecho_activo.setProperty("active", False)
            self.boton_derecho_activo.style().unpolish(self.boton_derecho_activo)
            self.boton_derecho_activo.style().polish(self.boton_derecho_activo)
        # Marca el nuevo botón
        boton.setProperty("active", True)
        boton.style().unpolish(boton)
        boton.style().polish(boton)
        self.boton_derecho_activo = boton

        # Cambia el contenido central según la opción seleccionada
        for i in reversed(range(self.panel_contenido_layout.count())):
            widget = self.panel_contenido_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        # Solo para Escáner de Puertos -> Escaneo
        if herramienta == "Escáner de Puertos" and "Escaneo" in opcion:
            widget = ScanTypeWidget()
            self.panel_contenido_layout.addWidget(widget)
        else:
            label = QLabel(f"🔸 {opcion} de {herramienta} seleccionado")
            label.setFont(QFont("Segoe UI", 18, QFont.Bold))
            label.setStyleSheet("color: #00ffcc;")
            self.panel_contenido_layout.addWidget(label, alignment=Qt.AlignTop)

    def actualizar_contenido(self, texto):
        self.label_contenido.setText(texto)

    # Nuevo método para volver al Home y ocultar el panel derecho
    def mostrar_home(self):
        # Limpia el contenido anterior
        for i in reversed(range(self.panel_contenido_layout.count())):
            widget = self.panel_contenido_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
        self.label_contenido = QLabel("👋 Bienvenido al Security Toolkit")
        self.label_contenido.setFont(QFont("Segoe UI", 20, QFont.Bold))
        self.label_contenido.setStyleSheet("color: #00ffcc;")
        self.panel_contenido_layout.addWidget(self.label_contenido, alignment=Qt.AlignTop)
        self.panel_lateral_derecho_stack.hide()
        # Desactiva el botón activo
        if self.boton_activo:
            self.boton_activo.setProperty("active", False)
            self.boton_activo.style().unpolish(self.boton_activo)
            self.boton_activo.style().polish(self.boton_activo)
            self.boton_activo = None
        if self.boton_derecho_activo:
            self.boton_derecho_activo.setProperty("active", False)
            self.boton_derecho_activo.style().unpolish(self.boton_derecho_activo)
            self.boton_derecho_activo.style().polish(self.boton_derecho_activo)
            self.boton_derecho_activo = None

    def abrir_terminal(self):
        user_dir = os.path.expanduser("~")
        subprocess.Popen("start cmd", shell=True, cwd=user_dir)