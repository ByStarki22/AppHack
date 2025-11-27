# ⭐ AppHack — Hub de herramientas

AppHack es un HUB modular de herramientas orientadas a auditoría y pruebas de seguridad. Actualmente la única herramienta implementada es un escáner de IP/puertos, pero la arquitectura está preparada para añadir más utilidades (fuzzers, enumeradores, exploits, etc.).

![DEMO](https://media0.giphy.com/media/v1.Y2lkPTc5MGI3NjExNmhtbzgzMG1tZ2kyZWtvOHNjYnE2bG56NXVhdnJwd2l4enF6NjFicSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/vP58u1sUl2zknS7OBy/giphy.gif)

---

## ⚠️ Aviso Legal
Este proyecto está destinado para fines estrictamente éticos y educativos. Utiliza AppHack únicamente para pruebas en sistemas y redes para las que tengas autorización explícita. Los autores no se hacen responsables del mal uso de esta herramienta.

---

## ✨ Características Principales

- **Interfaz Gráfica Modular:** Construida con PySide6, con una clara separación entre la Lógica (backend) y la Interfaz de Usuario (frontend).
- **Escáner de Puertos Avanzado:**
  - **Modo Rápido:** Para escaneos sencillos y preconfigurados.
  - **Modo Avanzado:** Ofrece un control granular sobre el escaneo, similar a herramientas como Nmap, incluyendo:
    - **Especificación de Objetivos:** Escaneo de IPs individuales, rangos, notación CIDR, dominios y listas desde archivos.
    - **Técnicas de Escaneo:** Soporte para TCP SYN, Connect, UDP, SCTP, NULL, FIN, Xmas y más.
    - **Detección:** Identificación de servicios y versiones (`-sV`), y detección de sistema operativo (`-O`).
    - **Rendimiento:** Ajuste de plantillas de tiempo (`-T0` a `-T5`) y control de la tasa de envío de paquetes.
    - **Evasión de Firewall/IDS:** Técnicas como paquetes fragmentados, spoofing de IP y MAC.
- **Ejecución Asíncrona:** Utiliza `asyncio` y `QThread` para mantener la interfaz de usuario responsiva durante los escaneos.
- **Diseño Extensible:** La arquitectura permite añadir nuevas herramientas (como fuzzers, crackers de hashes, etc.) sin modificar el núcleo de la aplicación.
- **Terminal Integrado:** Muestra los logs y resultados del escaneo en tiempo real en un panel dedicado.

---

## 🏗️ Estructura del Proyecto

El proyecto sigue una arquitectura que separa la interfaz de usuario de la lógica de negocio.

- `main.py`: Punto de entrada de la aplicación.
- `requirements.txt`: Lista de dependencias del proyecto.
- `app/`: Directorio principal de la aplicación.
  - `UI/`: Contiene todos los componentes de la interfaz gráfica (Widgets de PySide6).
    - `MainUI.py`: Define la ventana principal y la disposición de los paneles.
    - `toolsUI/`: Contiene las interfaces específicas para cada herramienta, como el escáner de puertos.
      - `fast_scan_typeUI/`: UI para el modo de escaneo rápido.
      - `advance_scan_typeUI/`: UI para el modo de escaneo avanzado, con todos sus sub-widgets.
  - `logic/`: Contiene la lógica de negocio y las implementaciones de las herramientas.
    - `toolsLogic/`: Contiene la lógica específica para cada herramienta.
      - `portSscanner/`: Implementación de los diferentes tipos de escaneo (rápido, avanzado).
      - `advance_widgets/`: Lógica para las funciones de escaneo avanzadas (manejo de objetivos, puertos, etc.).

---

## 🚀 Requisitos e Instalación

Se recomienda utilizar Python 3.8 o superior en un entorno virtual.

1.  **Clona el repositorio:**
    ```bash
    git clone https://github.com/ByStarki22/AppHack.git
    cd AppHack
    ```

2.  **Crea y activa un entorno virtual:**
    ```powershell
    # Windows (PowerShell)
    python -m venv env
    .\env\Scripts\activate
    ```
    *Nota: Si encuentras problemas con la ejecución de scripts, puedes usar el siguiente comando en PowerShell:*
    `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`

3.  **Instala las dependencias:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Ejecuta la aplicación:**
    ```bash
    python main.py
    ```

> **Importante:** Algunas funcionalidades, como los escaneos SYN (`-sS`) o la detección de OS (`-O`), pueden requerir privilegios de administrador para funcionar correctamente, ya que utilizan raw sockets.