#!/usr/bin/env python3
"""Pruebas manuales reproducibles contra las dos versiones de la aplicación.

Uso:
  LAB_PASSWORD='...' python3 lab/pruebas/probar.py \
      --vulnerable http://127.0.0.1:5000 --secure http://127.0.0.1:5001

Escribe evidencias de texto en evidencias/texto/. No imprime credenciales.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "evidencias" / "texto"
XSS = "<script>alert('XSS-PROYECTO-FINAL')</script>"
SQLI = "Delta' OR '1'='1' --"


def guardar(nombre: str, lineas: list[str]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    cabecera = [
        "=" * 72,
        f"Evidencia generada: {datetime.now(timezone.utc).isoformat()}",
        "Entorno: laboratorio local autorizado · datos ficticios",
        "=" * 72,
        "",
    ]
    (OUT / nombre).write_text("\n".join(cabecera + lineas) + "\n", encoding="utf-8")
    print(f"[ok] {OUT / nombre}")


def filas(html: str) -> int:
    return len(re.findall(r'<a href="/expediente/\d+"', html))


def login(base: str, password: str, usuario: str) -> requests.Session:
    s = requests.Session()
    r = s.post(
        f"{base}/login",
        data={"username": usuario, "password": password},
        timeout=10,
        allow_redirects=True,
    )
    if r.status_code != 200 or "Salir" not in r.text:
        raise RuntimeError(f"No se pudo iniciar sesión como {usuario} en {base}")
    return s


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vulnerable", default="http://127.0.0.1:5000")
    ap.add_argument("--secure", default="http://127.0.0.1:5001")
    ap.add_argument("--password", default=None, help="Solo para uso local; mejor usar LAB_PASSWORD")
    args = ap.parse_args()
    password = args.password or __import__("os").environ.get("LAB_PASSWORD")
    if not password:
        raise SystemExit("Defina LAB_PASSWORD con la contraseña de laboratorio")

    vuln, seg = args.vulnerable.rstrip("/"), args.secure.rstrip("/")

    # --- Actividad 1: entornos y endpoints ---------------------------------
    lineas = ["ACTIVIDAD 1 · PREPARACIÓN Y VERIFICACIÓN DE ENDPOINTS", ""]
    for nombre, base in (("VULNERABLE", vuln), ("CORREGIDO", seg)):
        lineas.append(f"[{nombre}] base={base}")
        for ruta in ("/", "/health", "/login", "/buscar?q=Delta", "/comentarios"):
            r = requests.get(base + ruta, timeout=10)
            lineas.append(f"  GET {ruta:<22} -> {r.status_code}  ({len(r.content)} bytes)")
        h = requests.get(base + "/health", timeout=10).json()
        lineas.append(f"  /health JSON: {json.dumps(h, ensure_ascii=False)}")
        lineas.append("")
    guardar("01_entorno_endpoints.txt", lineas)

    # --- SQLi ---------------------------------------------------------------
    base_lineas = [
        "ACTIVIDAD 2/4 · SQL INJECTION",
        f"Payload: q={SQLI}",
        "Endpoint: GET /buscar",
        "",
    ]
    rv = requests.get(f"{vuln}/buscar", params={"q": SQLI}, timeout=10)
    lineas = base_lineas + [
        "[ANTES · modo vulnerable]",
        f"  URL: {rv.url}",
        f"  Estado HTTP: {rv.status_code}",
        f"  Filas devueltas: {filas(rv.text)} (esperado vulnerable: 5)",
        "  Fragmento de la respuesta:",
    ]
    lineas += ["    " + l.strip() for l in rv.text.splitlines() if "expediente/" in l][:6]
    lineas += [
        "",
        "  Observación: la concatenación de la entrada modifica el WHERE y devuelve",
        "  todos los expedientes, incluidos los que no coinciden con 'Delta'.",
        "",
    ]
    rs = requests.get(f"{seg}/buscar", params={"q": SQLI}, timeout=10)
    lineas += [
        "[DESPUÉS · modo corregido]",
        f"  URL: {rs.url}",
        f"  Estado HTTP: {rs.status_code}",
        f"  Filas devueltas: {filas(rs.text)} (esperado seguro: 0)",
        "  Mensaje visible: " + ("Sin resultados" if "Sin resultados" in rs.text else "revisar"),
        "  Cambio aplicado: consulta parametrizada con LIKE ? y límite de longitud.",
        "  Riesgo reducido: el payload se trata como dato, no como código SQL.",
    ]
    guardar("02_sqli_validacion.txt", lineas)

    # --- XSS ----------------------------------------------------------------
    sv = login(vuln, password, "s_tio")
    sv.post(f"{vuln}/comentarios", data={"texto": XSS}, timeout=10)
    rv = sv.get(f"{vuln}/comentarios", timeout=10)
    lineas = [
        "ACTIVIDAD 2/4 · CROSS-SITE SCRIPTING (XSS)",
        f"Payload publicado: {XSS}",
        "Endpoint: POST/GET /comentarios",
        "",
        "[ANTES · modo vulnerable]",
        f"  GET /comentarios -> {rv.status_code}",
        f"  Script sin escapar presente en el HTML: {XSS in rv.text}",
        "  Fragmento: " + (re.search(r".{0,40}<script>alert\('XSS-PROYECTO-FINAL'\).{0,60}", rv.text).group(0) if XSS in rv.text else "no encontrado"),
        "  Observación: el navegador interpreta la etiqueta como JavaScript.",
        "",
    ]
    ss = login(seg, password, "s_tio")
    ss.post(f"{seg}/comentarios", data={"texto": XSS}, timeout=10)
    rs = ss.get(f"{seg}/comentarios", timeout=10)
    lineas += [
        "[DESPUÉS · modo corregido]",
        f"  GET /comentarios -> {rs.status_code}",
        f"  Script sin escapar presente en el HTML: {XSS in rs.text}",
        f"  Contenido escapado (&lt;script&gt;) presente: {'&lt;script&gt;' in rs.text}",
        f"  Cabecera CSP: {rs.headers.get('Content-Security-Policy', 'AUSENTE')}",
        "  Cambio aplicado: autoescape de Jinja en la plantilla + CSP restrictiva.",
        "  Riesgo reducido: el contenido se representa como texto inerte.",
    ]
    guardar("03_xss_validacion.txt", lineas)

    # --- IDOR / BOLA --------------------------------------------------------
    av = login(vuln, password, "a_auxiliar")
    rv = av.get(f"{vuln}/expediente/1", timeout=10)
    rv_api = av.get(f"{vuln}/api/expediente/1", timeout=10)
    lineas = [
        "ACTIVIDAD 2/4 · CONTROL DE ACCESO ROTO (IDOR/BOLA)",
        "Endpoint: GET /expediente/<id> y GET /api/expediente/<id>",
        "Usuario autenticado: a_auxiliar · recurso solicitado: expediente 1 (propietario s_tio)",
        "",
        "[ANTES · modo vulnerable]",
        f"  GET /expediente/1 -> {rv.status_code}",
        f"  Datos ajenos visibles: {'Constructora Delta' in rv.text and 's_tio' in rv.text}",
        f"  GET /api/expediente/1 -> {rv_api.status_code} {rv_api.text[:160]}",
        "  Observación: no hay comprobación de propiedad ni de rol en el servidor.",
        "",
    ]
    aa = login(seg, password, "a_auxiliar")
    ra = aa.get(f"{seg}/expediente/1", timeout=10)
    ra_api = aa.get(f"{seg}/api/expediente/1", timeout=10)
    propio = aa.get(f"{seg}/expediente/5", timeout=10)
    admin = login(seg, password, "s_tio").get(f"{seg}/expediente/1", timeout=10)
    lineas += [
        "[DESPUÉS · modo corregido]",
        f"  GET /expediente/1 como a_auxiliar -> {ra.status_code} (esperado 403)",
        f"  GET /api/expediente/1 como a_auxiliar -> {ra_api.status_code} {ra_api.text[:120]}",
        f"  GET /expediente/5 (propio) -> {propio.status_code} (esperado 200)",
        f"  GET /expediente/1 como s_tio -> {admin.status_code} (esperado 200)",
        "  Cambio aplicado: autorización por owner_id o rol socio antes de entregar el recurso.",
        "  Riesgo reducido: denegación por defecto y registro del intento.",
    ]
    guardar("04_idor_validacion.txt", lineas)

    # --- Actividad 5 + Parte B: registros y detección -----------------------
    ses = login(seg, password, "s_tio")
    for _ in range(3):
        requests.post(
            f"{seg}/login", data={"username": "s_tio", "password": "incorrecta"}, timeout=10
        )
    requests.get(f"{seg}/buscar", params={"q": SQLI}, timeout=10)
    ses.post(f"{seg}/comentarios", data={"texto": XSS}, timeout=10)
    aa.get(f"{seg}/expediente/1", timeout=10)
    aa.get(f"{seg}/expediente/2", timeout=10)
    datos = ses.get(f"{seg}/api/alertas", timeout=10).json()
    panel = ses.get(f"{seg}/alertas", timeout=10)
    tipos: dict[str, int] = {}
    for e in datos["eventos"]:
        tipos[e["tipo"]] = tipos.get(e["tipo"], 0) + 1
    lineas = [
        "ACTIVIDAD 5 Y PARTE B · ANÁLISIS DE REGISTROS Y DETECCIÓN",
        "Eventos controlados generados: 3 login fallidos, 1 patrón SQLi, 1 patrón XSS,",
        "2 accesos denegados a expedientes ajenos.",
        "",
        f"GET /api/alertas -> {ses.get(f'{seg}/api/alertas', timeout=10).status_code}",
        f"GET /alertas (panel HTML) -> {panel.status_code}",
        f"Eventos en memoria: {len(datos['eventos'])}",
        "Conteo por tipo: " + json.dumps(tipos, ensure_ascii=False, sort_keys=True),
        "",
        "Alertas correlacionadas:",
    ]
    for a in datos["alertas"]:
        lineas.append(
            f"  {a['id']} · {a['titulo']} · severidad={a['severidad']} · "
            f"{a['cantidad']}/{a['umbral']} eventos en {a['ventana_segundos']}s"
        )
    lineas += [
        "",
        "Muestra de eventos (últimos 6):",
    ]
    for e in datos["eventos"][:6]:
        lineas.append(
            f"  {e['timestamp'][11:19]} {e['tipo']:<16} {e['severidad']:<7} "
            f"{e['usuario']:<12} {e['ruta']} -> {e['estado']}"
        )
    lineas += [
        "",
        "Lectura para detección: los patrones SQLi/XSS se registran aunque el ataque",
        "sea bloqueado; los fallos de login y las denegaciones se correlacionan por",
        "ventana temporal. Esto permite priorizar la investigación y reconstruir",
        "la secuencia de un incidente sin depender solo del resultado HTTP.",
    ]
    guardar("05_registros_monitoreo.txt", lineas)

    print("[ok] todas las pruebas terminaron")


if __name__ == "__main__":
    main()
