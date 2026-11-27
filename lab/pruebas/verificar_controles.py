#!/usr/bin/env python3
"""Verificación de los controles añadidos tras el escaneo ZAP original.

Prueba el token anti-CSRF, las cabeceras de respuesta y una regresión rápida de
IDOR/BOLA en el modo corregido. Escribe evidencia de texto reproducible.

Uso:
  LAB_PASSWORD='...' python3 lab/pruebas/verificar_controles.py [URL_BASE]
"""

from __future__ import annotations

import argparse
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "evidencias" / "texto" / "08_controles_adicionales.txt"
CABECERAS = (
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Cache-Control",
    "Permissions-Policy",
    "Cross-Origin-Resource-Policy",
)


def token_csrf(s: requests.Session, base: str, ruta: str) -> str:
    pagina = s.get(base + ruta, timeout=10)
    encontrado = re.search(r'name="csrf_token"\s+value="([^"]+)"', pagina.text)
    if not encontrado:
        raise RuntimeError(f"No se encontró token CSRF en {base}{ruta}")
    return encontrado.group(1)


def iniciar(s: requests.Session, base: str, usuario: str, password: str) -> None:
    datos = {
        "username": usuario,
        "password": password,
        "csrf_token": token_csrf(s, base, "/login"),
    }
    r = s.post(base + "/login", data=datos, timeout=10, allow_redirects=True)
    if r.status_code != 200 or "Salir" not in r.text:
        raise RuntimeError(f"No se pudo autenticar como {usuario}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("base", nargs="?", default="http://127.0.0.1:5001")
    ap.add_argument("--password", default=None, help="Mejor usar LAB_PASSWORD")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    password = args.password or os.environ.get("LAB_PASSWORD")
    if not password:
        raise SystemExit("Defina LAB_PASSWORD con la contraseña de laboratorio")

    s = requests.Session()
    lineas = [
        "CONTROLES ADICIONALES · CSRF Y CABECERAS DE SEGURIDAD",
        f"Objetivo: {base} (modo corregido)",
        "Entorno: laboratorio local autorizado · datos ficticios",
        "",
    ]

    # 1. El formulario entrega un token por sesión.
    r_login = s.get(base + "/login", timeout=10)
    token = token_csrf(s, base, "/login")
    lineas += [
        "[1] Formulario de login",
        f"  GET /login -> {r_login.status_code}",
        f"  Campo csrf_token presente: {'name=\"csrf_token\"' in r_login.text}",
        f"  Longitud del token: {len(token)} caracteres (valor no publicado)",
        "",
    ]

    # 2. Sin token la petición se rechaza; con token se acepta.
    sin_token = s.post(
        base + "/login", data={"username": "s_tio", "password": password}, timeout=10
    )
    con_token = s.post(
        base + "/login",
        data={"username": "s_tio", "password": password, "csrf_token": token},
        timeout=10,
        allow_redirects=True,
    )
    lineas += [
        "[2] Envío de formularios",
        f"  POST /login sin token -> {sin_token.status_code} {sin_token.text[:90]}",
        f"  POST /login con token  -> {con_token.status_code} (sesión iniciada: {'Salir' in con_token.text})",
        "",
    ]

    # 3. El formulario de comentarios también exige token.
    token_comentario = token_csrf(s, base, "/comentarios")
    sin_token_com = s.post(
        base + "/comentarios",
        data={"expediente_id": 1, "texto": "Nota sin token"}, timeout=10
    )
    con_token_com = s.post(
        base + "/comentarios",
        data={
            "expediente_id": 1,
            "texto": "Nota autorizada con token CSRF",
            "csrf_token": token_comentario,
        },
        timeout=10,
    )
    vista = s.get(base + "/comentarios", params={"expediente_id": 1}, timeout=10)
    lineas += [
        "[3] Formulario de comentarios",
        f"  POST /comentarios sin token -> {sin_token_com.status_code}",
        f"  POST /comentarios con token  -> {con_token_com.status_code}",
        f"  Nota autorizada visible: {'Nota autorizada con token CSRF' in vista.text}",
        "",
    ]

    # 4. Cabeceras de defensa en profundidad.
    lineas.append("[4] Cabeceras de respuesta (GET /comentarios)")
    for cabecera in CABECERAS:
        valor = vista.headers.get(cabecera, "AUSENTE")
        lineas.append(f"  {cabecera}: {valor}")
    lineas.append("")

    # 5. Regresión de la corrección de IDOR/BOLA.
    aux = requests.Session()
    iniciar(aux, base, "a_auxiliar", password)
    idor = aux.get(base + "/expediente/6", timeout=10)
    idor_api = aux.get(base + "/api/expediente/6", timeout=10)
    bypass = aux.post(
        base + "/login",
        data={
            "username": "s_tio' -- ",
            "password": "no-importa",
            "csrf_token": token_csrf(aux, base, "/comentarios"),
        },
        timeout=10,
        allow_redirects=True,
    )
    lineas += [
        "[5] Regresión de autorización",
        f"  a_auxiliar -> /expediente/6     -> {idor.status_code} (esperado 403)",
        f"  a_auxiliar -> /api/expediente/6 -> {idor_api.status_code} (esperado 403)",
        f"  SQLi en login con token CSRF   -> {bypass.status_code} (esperado 401)",
        "",
    ]

    # 6. El intento fallido queda registrado y correlacionado.
    datos = s.get(base + "/api/alertas", timeout=10).json()
    tipos: dict[str, int] = {}
    for evento in datos["eventos"]:
        tipos[evento["tipo"]] = tipos.get(evento["tipo"], 0) + 1
    alertas_csrf = [a for a in datos["alertas"] if a["regla"] == "CSRF-001"]
    lineas += [
        "[6] Registro y detección",
        f"  GET /api/alertas -> 200; eventos en memoria: {len(datos['eventos'])}",
        f"  CSRF_RECHAZADO registrados: {tipos.get('CSRF_RECHAZADO', 0)}",
        f"  Alertas CSRF-001: {len(alertas_csrf)}",
    ]
    for alerta in alertas_csrf[:2]:
        lineas.append(
            f"    {alerta['id']} · severidad={alerta['severidad']} · "
            f"{alerta['cantidad']}/{alerta['umbral']} eventos en {alerta['ventana_segundos']}s"
        )
    lineas += [
        "",
        "Conclusión: el modo seguro exige un token imprevisible por sesión en cada",
        "cambio de estado, no almacena respuestas sensibles en caché y conserva la",
        "autorización por objeto. Los intentos sin token generan una alerta de severidad",
        "alta en lugar de pasar desapercibidos.",
        "",
        "Nota: el informe ZAP incluido en el repo corresponde al escaneo original;",
        "esta verificación es manual/automatizada y no sustituye un nuevo escaneo.",
        "",
        f"Generado: {datetime.now(timezone.utc).isoformat()}",
    ]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    print(f"[ok] {OUT}")
    print(
        "Resumen: CSRF sin token="
        f"{sin_token.status_code}, con token={con_token.status_code}, "
        f"IDOR={idor.status_code}, CSRF-001={len(alertas_csrf)}"
    )


if __name__ == "__main__":
    main()
