#!/usr/bin/env python3
"""Abre una página de la app en una ventana Qt a pantalla completa para grim.

Uso:
  LAB_PASSWORD='...' python3 scripts/ver_app.py URL [usuario]

Variables opcionales:
  LAB_FULLSCREEN=1   pide fullscreen al compositor (dwl lo acepta).
  LAB_READY_FILE     archivo marcador que se escribe cuando la página terminó
                     de cargar y pintar; evita dormir un tiempo fijo.
  LAB_ZOOM           factor de zoom (por ejemplo 1.1).

La contraseña se lee de LAB_PASSWORD y nunca se guarda. La ventana permanece
abierta hasta que se cierra el proceso.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

os.environ.setdefault("QT_QPA_PLATFORM", "wayland")

import requests
from PyQt6.QtCore import QTimer, QUrl
from PyQt6.QtNetwork import QNetworkCookie
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineWidgets import QWebEngineView


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Uso: ver_app.py URL [usuario]")
    url = sys.argv[1]
    usuario = sys.argv[2] if len(sys.argv) > 2 else ""
    password = os.environ.get("LAB_PASSWORD", "")
    if usuario and not password:
        raise SystemExit("Defina LAB_PASSWORD para iniciar sesión")

    session = requests.Session()
    if usuario:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        pagina = session.get(f"{base}/login", timeout=10)
        datos = {"username": usuario, "password": password}
        token = re.search(r'name="csrf_token"\s+value="([^"]+)"', pagina.text)
        if token:
            datos["csrf_token"] = token.group(1)
        r = session.post(f"{base}/login", data=datos, timeout=10)
        if r.status_code != 200 or "Salir" not in r.text:
            raise SystemExit(f"No se pudo autenticar como {usuario}")

    ready = os.environ.get("LAB_READY_FILE", "")
    if ready:
        Path(ready).unlink(missing_ok=True)

    def marcar_listo(ok: bool) -> None:
        if not ready:
            return
        # Un pequeño margen permite el último repintado antes de que grim lea.
        QTimer.singleShot(
            800,
            lambda: Path(ready).write_text("ok\n" if ok else "error\n", encoding="utf-8"),
        )

    app = QApplication(sys.argv)
    view = QWebEngineView()
    view.setWindowTitle("Laboratorio · Ramírez & Asociados")
    view.setGeometry(0, 0, 1920, 1080)
    view.loadFinished.connect(marcar_listo)

    zoom = os.environ.get("LAB_ZOOM", "")
    if zoom:
        view.setZoomFactor(float(zoom))

    cookie_value = session.cookies.get("session")
    if cookie_value:
        cookie = QNetworkCookie(b"session", cookie_value.encode())
        parsed = urlparse(url)
        cookie.setDomain(parsed.hostname or "127.0.0.1")
        cookie.setPath("/")
        view.page().profile().cookieStore().setCookie(cookie)

    view.load(QUrl(url))
    if os.environ.get("LAB_FULLSCREEN") == "1":
        view.showFullScreen()
    else:
        view.show()
    app.exec()


if __name__ == "__main__":
    main()
