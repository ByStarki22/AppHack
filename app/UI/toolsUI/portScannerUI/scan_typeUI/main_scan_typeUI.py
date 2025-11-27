from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFrame, QPushButton, QLabel, QSpacerItem, QSizePolicy, QStackedWidget, QScrollArea
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
# Agrega este import al inicio (ajusta el import según tu estructura real)
from app.UI.toolsUI.portScannerUI.scan_typeUI.fast_scan_typeUI.fast_scan_type_ui import FastScanTypeUI
from app.UI.toolsUI.portScannerUI.scan_typeUI.advance_scan_typeUI.main_advance_scan_type_ui import AdvanceScanTypeUI

class HorizontalScrollArea(QScrollArea):
    def wheelEvent(self, event):
        # Solo si hay scroll horizontal disponible
        if self.horizontalScrollBar().maximum() > 0:
            delta = event.angleDelta().y() or event.angleDelta().x()
            smooth_delta = int(delta / 4)  # Ajusta el divisor para más o menos suavidad
            self.horizontalScrollBar().setValue(
                self.horizontalScrollBar().value() - smooth_delta
            )
            event.accept()
        else:
            super().wheelEvent(event)

class ScanTypeWidget(QWidget):
    def __init__(self):
        super().__init__()
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- Contenedor para la barra de botones ---
        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background: transparent;")
        self.scroll_layout = QHBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(0, 0, 0, 0)
        self.scroll_layout.setSpacing(0)

        # --- Panel superior tipo barra horizontal ---
        self.panel_superior = QFrame()
        # Eliminado: Quitar el máximo ancho para responsividad
        # self.panel_superior.setMaximumWidth(700)
        self.panel_superior.setStyleSheet("""
            QFrame {
                background-color: #232323;
                border-radius: 10px;
            }
            QPushButton {
                color: #ffffff;
                background-color: #2b2b2b;
                border-radius: 8px;
                padding: 8px 12px;
                margin: 2px 4px;
                font-size: 15px;
                font-family: 'Segoe UI', Arial, sans-serif;
                min-width: 110px;   /* Aumenta el min-width para que soporte la negrita */
                max-width: 110px;   /* Fija el max-width igual al min-width */
                box-sizing: border-box;
            }
            QPushButton:hover {
                background-color: #3c3c3c;
            }
            QPushButton:pressed {
                background-color: #00aa88;
            }
            QPushButton[active="true"] {
                background-color: #00aa88;
                color: #ffffff;
            }
        """)
        layout_superior = QHBoxLayout(self.panel_superior)
        layout_superior.setContentsMargins(5, 5, 5, 5)
        layout_superior.setSpacing(5)

        # Eliminado: Espaciador izquierdo para centrar
        # self.left_spacer = QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Minimum)
        # layout_superior.addItem(self.left_spacer)

        fuente = QFont("Segoe UI", 12, QFont.Medium)

        self.boton_rapido = QPushButton("Rápido")
        self.boton_avanzado = QPushButton("Avanzado")
        self.boton_Programado = QPushButton("Programado")
        self.boton_Personalizado = QPushButton("Personalizado")
        self.boton_Scriptable = QPushButton("Scriptable")

        self.scan_buttons = [
            self.boton_rapido,
            self.boton_avanzado,
            self.boton_Programado,
            self.boton_Personalizado,
            self.boton_Scriptable,
        ]

        for btn in self.scan_buttons:
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("active", False)
            btn.setFont(fuente)
            btn.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Preferred)
            layout_superior.addWidget(btn)

        # Eliminado: Espaciador derecho para centrar
        # self.right_spacer = QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Minimum)
        # layout_superior.addItem(self.right_spacer)

        # --- ScrollArea para la barra de botones ---
        self.scroll_layout.addWidget(self.panel_superior, alignment=Qt.AlignCenter)
        scroll_barra = HorizontalScrollArea()
        scroll_barra.setWidgetResizable(True)
        scroll_barra.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_barra.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_barra.setFrameShape(QFrame.NoFrame)
        scroll_barra.setWidget(self.scroll_content)
        scroll_barra.setMaximumHeight(60)

        main_layout.addWidget(scroll_barra, stretch=0)

        # --- Contenido principal debajo de la barra ---
        self.stacked_widget = QStackedWidget()
        # Cambia el QLabel por el widget real
        self.page_rapido = FastScanTypeUI()
        self.page_avanzado = AdvanceScanTypeUI()
        self.page_Programado = QLabel("Contenido de Escaneo Programado")
        self.page_Personalizado = QLabel("Contenido de Escaneo Personalizado")
        self.page_Scriptable = QLabel("Contenido de Escaneo Scriptable")

        # Puedes reemplazar los QLabel por widgets Programados
        for page in [self.page_Programado, self.page_Personalizado, self.page_Scriptable]:
            page.setAlignment(Qt.AlignCenter)
            page.setStyleSheet("color: #00ffcc; font-size: 18px; font-family: 'Segoe UI', Arial, sans-serif;")


        self.stacked_widget.addWidget(self.page_rapido)
        self.stacked_widget.addWidget(self.page_avanzado)
        self.stacked_widget.addWidget(self.page_Programado)
        self.stacked_widget.addWidget(self.page_Personalizado)
        self.stacked_widget.addWidget(self.page_Scriptable)

        main_layout.addWidget(self.stacked_widget)

        self.boton_activo = None

        # Conectar botones a sus páginas
        self.boton_rapido.clicked.connect(lambda: self.seleccionar_tipo(self.boton_rapido, 0))
        self.boton_avanzado.clicked.connect(lambda: self.seleccionar_tipo(self.boton_avanzado, 1))
        self.boton_Programado.clicked.connect(lambda: self.seleccionar_tipo(self.boton_Programado, 2))
        self.boton_Personalizado.clicked.connect(lambda: self.seleccionar_tipo(self.boton_Personalizado, 3))
        self.boton_Scriptable.clicked.connect(lambda: self.seleccionar_tipo(self.boton_Scriptable, 4))

        # Selecciona por defecto la primera opción
        self.seleccionar_tipo(self.boton_rapido, 0)

    def seleccionar_tipo(self, boton, index):
        # Desactiva el botón activo anterior
        if self.boton_activo:
            self.boton_activo.setProperty("active", False)
            # Quitar negrita al botón anterior
            font = self.boton_activo.font()
            font.setBold(False)
            self.boton_activo.setFont(font)
            self.boton_activo.style().unpolish(self.boton_activo)
            self.boton_activo.style().polish(self.boton_activo)
        # Activa el nuevo botón
        boton.setProperty("active", True)
        # Poner negrita al botón seleccionado
        font = boton.font()
        font.setBold(True)
        boton.setFont(font)
        boton.style().unpolish(boton)
        boton.style().polish(boton)
        self.boton_activo = boton
        # Cambia el contenido
        self.stacked_widget.setCurrentIndex(index)