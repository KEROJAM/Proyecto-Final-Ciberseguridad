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
SQLI_LOGIN = "s_tio' -- "


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


def token_csrf(s: requests.Session, base: str, ruta: str) -> str:
    """Lee el token anti-CSRF del formulario del modo seguro."""
    r = s.get(base + ruta, timeout=10)
    coincidencia = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    if not coincidencia:
        raise RuntimeError(f"No se encontró token CSRF en {base}{ruta}")
    return coincidencia.group(1)


def login(base: str, password: str, usuario: str, seguro: bool = False) -> requests.Session:
    s = requests.Session()
    datos = {"username": usuario, "password": password}
    if seguro:
        datos["csrf_token"] = token_csrf(s, base, "/login")
    r = s.post(
        f"{base}/login",
        data=datos,
        timeout=10,
        allow_redirects=True,
    )
    if r.status_code != 200 or "Salir" not in r.text:
        raise RuntimeError(f"No se pudo iniciar sesión como {usuario} en {base}")
    return s


def publicar(s: requests.Session, base: str, texto: str, seguro: bool = False):
    """Publica una nota en el expediente 1; en modo seguro adjunta el token CSRF."""
    datos = {"expediente_id": 1, "texto": texto}
    if seguro:
        datos["csrf_token"] = token_csrf(s, base, "/comentarios")
    return s.post(f"{base}/comentarios", data=datos, timeout=10)


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
    sv = login(vuln, password, "s_tio")
    ss = login(seg, password, "s_tio", seguro=True)

    # --- Actividad 1: entornos y endpoints ---------------------------------
    lineas = ["ACTIVIDAD 1 · PREPARACIÓN Y VERIFICACIÓN DE ENDPOINTS", ""]
    lineas += [
        "Acceso global: las rutas de aplicación redirigen a /login sin sesión;",
        "las peticiones siguientes usan una sesión autenticada.",
        "",
    ]
    for nombre, base, sesion in (("VULNERABLE", vuln, sv), ("CORREGIDO", seg, ss)):
        lineas.append(f"[{nombre}] base={base}")
        for ruta in ("/", "/health", "/login", "/buscar?q=Delta",
                     "/comentarios?expediente_id=1"):
            r = sesion.get(base + ruta, timeout=10)
            lineas.append(f"  GET {ruta:<26} -> {r.status_code}  ({len(r.content)} bytes)")
        sin_sesion = requests.get(base + "/", timeout=10, allow_redirects=False)
        lineas.append(f"  GET / sin sesión -> {sin_sesion.status_code} "
                      f"(redirige a {sin_sesion.headers.get('Location', '?')})")
        h = requests.get(base + "/health", timeout=10).json()
        lineas.append(f"  /health JSON: {json.dumps(h, ensure_ascii=False)}")
        lineas.append("")
    guardar("01_entorno_endpoints.txt", lineas)

    # --- SQLi ---------------------------------------------------------------
    base_lineas = [
        "ACTIVIDAD 2/4 · SQL INJECTION",
        f"Payload en búsqueda: q={SQLI}",
        f"Payload en login: usuario={SQLI_LOGIN!r} · contraseña arbitraria",
        "Endpoints: GET /buscar y POST /login",
        "",
    ]
    rv = sv.get(f"{vuln}/buscar", params={"q": SQLI}, timeout=10)
    lineas = base_lineas + [
        "[ANTES · modo vulnerable]",
        f"  URL: {rv.url}",
        f"  Estado HTTP: {rv.status_code}",
        f"  Filas devueltas: {filas(rv.text)} (esperado vulnerable: 6)",
        "  Fragmento de la respuesta:",
    ]
    lineas += ["    " + l.strip() for l in rv.text.splitlines() if "expediente/" in l][:6]
    lineas += [
        "",
        "  Observación: la concatenación de la entrada modifica el WHERE y devuelve",
        "  todos los expedientes, incluidos los que no coinciden con 'Delta'.",
        "",
    ]
    rs = ss.get(f"{seg}/buscar", params={"q": SQLI}, timeout=10)
    lineas += [
        "[DESPUÉS · modo corregido]",
        f"  URL: {rs.url}",
        f"  Estado HTTP: {rs.status_code}",
        f"  Filas devueltas: {filas(rs.text)} (esperado seguro: 0)",
        "  Mensaje visible: " + ("Sin resultados" if "Sin resultados" in rs.text else "revisar"),
        "  Cambio aplicado: consulta parametrizada con LIKE ? y límite de longitud.",
        "  Riesgo reducido: el payload se trata como dato, no como código SQL.",
        "",
    ]

    # Inyección en el propio formulario de acceso (autenticación bypass).
    bypass = requests.Session()
    rv_login = bypass.post(
        f"{vuln}/login",
        data={"username": SQLI_LOGIN, "password": "no-importa"},
        timeout=10,
        allow_redirects=True,
    )
    entro = "s_tio" in rv_login.text and "Salir" in rv_login.text
    intento_seguro = requests.Session()
    datos_login = {"username": SQLI_LOGIN, "password": "no-importa"}
    datos_login["csrf_token"] = token_csrf(intento_seguro, seg, "/login")
    rs_login = intento_seguro.post(
        f"{seg}/login", data=datos_login, timeout=10, allow_redirects=True
    )
    lineas += [
        "[LOGIN · modo vulnerable]",
        f"  POST /login con usuario {SQLI_LOGIN!r} -> {rv_login.status_code}",
        f"  Sesión iniciada sin contraseña válida: {entro}",
        "  Observación: la concatenación SQL comentó la comparación de contraseña.",
        "",
        "[LOGIN · modo corregido]",
        f"  POST /login con el mismo payload -> {rs_login.status_code}",
        f"  Sesión iniciada: {'s_tio' in rs_login.text and 'Salir' in rs_login.text}",
        "  Cambio aplicado: consulta parametrizada y verificación de password_hash.",
    ]
    guardar("02_sqli_validacion.txt", lineas)

    # --- XSS ----------------------------------------------------------------
    publicar(sv, vuln, XSS)
    rv = sv.get(f"{vuln}/comentarios", params={"expediente_id": 1}, timeout=10)
    lineas = [
        "ACTIVIDAD 2/4 · CROSS-SITE SCRIPTING (XSS)",
        f"Payload publicado: {XSS}",
        "Endpoint: POST/GET /comentarios?expediente_id=1 (nota ligada al expediente 1)",
        "",
        "[ANTES · modo vulnerable]",
        f"  GET /comentarios -> {rv.status_code}",
        f"  Script sin escapar presente en el HTML: {XSS in rv.text}",
        "  Fragmento: " + (re.search(r".{0,40}<script>alert\('XSS-PROYECTO-FINAL'\).{0,60}", rv.text).group(0) if XSS in rv.text else "no encontrado"),
        "  Observación: el navegador interpreta la etiqueta como JavaScript.",
        "",
    ]
    publicar(ss, seg, XSS, seguro=True)
    rs = ss.get(f"{seg}/comentarios", params={"expediente_id": 1}, timeout=10)
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
    rv = av.get(f"{vuln}/expediente/6", timeout=10)
    rv_api = av.get(f"{vuln}/api/expediente/6", timeout=10)
    lineas = [
        "ACTIVIDAD 2/4 · CONTROL DE ACCESO ROTO (IDOR/BOLA)",
        "Endpoint: GET /expediente/<id> y GET /api/expediente/<id>",
        "Usuario autenticado: a_auxiliar · recurso solicitado: expediente 6 (reservado al socio s_tio)",
        "",
        "[ANTES · modo vulnerable]",
        f"  GET /expediente/6 -> {rv.status_code}",
        f"  Datos ajenos visibles: {'Inversiones Ébano' in rv.text and 's_tio' in rv.text}",
        f"  GET /api/expediente/6 -> {rv_api.status_code} {rv_api.text[:160]}",
        "  Observación: no hay comprobación de propiedad ni de rol en el servidor.",
        "",
    ]
    aa = login(seg, password, "a_auxiliar", seguro=True)
    ra = aa.get(f"{seg}/expediente/6", timeout=10)
    ra_api = aa.get(f"{seg}/api/expediente/6", timeout=10)
    propio = aa.get(f"{seg}/expediente/5", timeout=10)
    admin = login(seg, password, "s_tio", seguro=True).get(f"{seg}/expediente/6", timeout=10)
    lineas += [
        "[DESPUÉS · modo corregido]",
        f"  GET /expediente/6 como a_auxiliar -> {ra.status_code} (esperado 403)",
        f"  GET /api/expediente/6 como a_auxiliar -> {ra_api.status_code} {ra_api.text[:120]}",
        f"  GET /expediente/5 (propio) -> {propio.status_code} (esperado 200)",
        f"  GET /expediente/6 como s_tio -> {admin.status_code} (esperado 200)",
        "  Cambio aplicado: autorización por owner_id o rol socio antes de entregar el recurso.",
        "  Riesgo reducido: denegación por defecto y registro del intento.",
    ]
    guardar("04_idor_validacion.txt", lineas)

    # --- Actividad 5 + Parte B: registros y detección -----------------------
    ses = login(seg, password, "s_tio", seguro=True)
    token_login = token_csrf(ses, seg, "/login")
    for _ in range(3):
        ses.post(
            f"{seg}/login",
            data={
                "username": "s_tio",
                "password": "incorrecta",
                "csrf_token": token_login,
            },
            timeout=10,
        )
    ss.get(f"{seg}/buscar", params={"q": SQLI}, timeout=10)
    publicar(ses, seg, XSS, seguro=True)
    aa.get(f"{seg}/expediente/1", timeout=10)
    aa.get(f"{seg}/expediente/2", timeout=10)
    datos = ses.get(f"{seg}/api/alertas", timeout=10).json()
    panel = ses.get(f"{seg}/alertas", timeout=10)
    tipos: dict[str, int] = {}
    for e in datos["eventos"]:
        tipos[e["tipo"]] = tipos.get(e["tipo"], 0) + 1
    lineas = [
        "ACTIVIDAD 5 Y PARTE B · ANÁLISIS DE REGISTROS Y DETECCIÓN",
        "Eventos controlados generados: accesos sin sesión, 3 login fallidos,",
        "patrones SQLi en búsqueda y login, 1 patrón XSS, 2 accesos denegados,",
        "1 nota con contenido sospechoso.",
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
