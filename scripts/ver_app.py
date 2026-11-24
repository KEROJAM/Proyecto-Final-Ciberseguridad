#!/usr/bin/env python3
"""Abre una página de la app en una ventana Qt para tomar capturas con grim.

Uso:
  LAB_PASSWORD='...' python3 scripts/ver_app.py URL [usuario]

Si se indica usuario, se inicia sesión con requests y se copia la cookie de
sesión al perfil de Qt. La contraseña se lee de LAB_PASSWORD y nunca se guarda.
La ventana permanece abierta hasta que se cierra el proceso.
"""

from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

import requests
from PyQt6.QtCore import QUrl
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
        r = session.post(
            f"{base}/login",
            data={"username": usuario, "password": password},
            timeout=10,
        )
        if r.status_code != 200 or "Salir" not in r.text:
            raise SystemExit(f"No se pudo autenticar como {usuario}")

    app = QApplication(sys.argv)
    view = QWebEngineView()
    view.setWindowTitle("Laboratorio · Ramírez & Asociados")
    view.setGeometry(100, 60, 1440, 900)

    cookie_value = session.cookies.get("session")
    if cookie_value:
        cookie = QNetworkCookie(b"session", cookie_value.encode())
        parsed = urlparse(url)
        cookie.setDomain(parsed.hostname or "127.0.0.1")
        cookie.setPath("/")
        view.page().profile().cookieStore().setCookie(cookie)

    view.load(QUrl(url))
    view.show()
    app.exec()


if __name__ == "__main__":
    main()
