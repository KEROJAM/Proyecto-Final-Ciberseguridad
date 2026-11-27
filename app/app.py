#!/usr/bin/env python3
"""Aplicación de laboratorio para el proyecto final de ciberseguridad.

La misma base de código puede ejecutarse en dos modos:

* ``LAB_MODE=vulnerable``: contiene SQLi, XSS e IDOR/BOLA deliberados.
* ``LAB_MODE=secure``: incluye las tres correcciones y el mecanismo de
  monitoreo/detección de la Parte B (Opción B).

Solo se usan datos ficticios y direcciones de loopback. No debe exponerse a Internet.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
DB_PATH = Path(os.environ.get("LAB_DB", BASE_DIR / "lab.sqlite3"))
LOG_DIR = Path(os.environ.get("LAB_LOG_DIR", ROOT_DIR / "logs"))
LOG_FILE = LOG_DIR / "security.jsonl"
ALERT_LOG_FILE = LOG_DIR / "alertas.jsonl"
RULES_FILE = ROOT_DIR / "lab" / "monitoreo" / "reglas.json"

MODO = os.environ.get("LAB_MODE", "vulnerable").strip().lower()
if MODO not in {"vulnerable", "secure"}:
    raise SystemExit("LAB_MODE debe ser 'vulnerable' o 'secure'")

app = Flask(__name__)
_secret = os.environ.get("LAB_SECRET_KEY")
if not _secret:
    _secret = secrets.token_hex(32)
    print("[lab] LAB_SECRET_KEY no definida: se genera una clave efímera de laboratorio")
app.secret_key = _secret
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

_lock = Lock()
_eventos: list[dict[str, Any]] = []
_alertas: list[dict[str, Any]] = []
_intentos_login: dict[str, list[datetime]] = {}

PATRON_SQLI = re.compile(
    r"('|\")?\s*(or|and)\s+('?\d+'?\s*=\s*'?\d+'?|'[^']*'\s*=\s*'[^']*')|union\s+select|(--|#)\s*$",
    re.IGNORECASE,
)
PATRON_XSS = re.compile(
    r"<\s*script|javascript:|on(error|load|click|focus)\s*=|<\s*img[^>]*src\s*=",
    re.IGNORECASE,
)
CSRF_CAMPO = "csrf_token"
# Acceso global: solo estas rutas se sirven sin sesión, en ambos modos.
RUTAS_PUBLICAS = frozenset({"/login", "/logout", "/health", "/favicon.ico"})


# ---------------------------------------------------------------------------
# Base de datos de laboratorio
# ---------------------------------------------------------------------------
def conectar() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    password = os.environ.get("LAB_USER_PASSWORD") or secrets.token_urlsafe(14)
    if not os.environ.get("LAB_USER_PASSWORD"):
        print(f"[lab] LAB_USER_PASSWORD no definida; contraseña efímera: {password}")
    hash_usuarios = generate_password_hash(password)
    with conectar() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                rol TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                -- Solo para la demo de inyección SQL en /login del modo vulnerable.
                password TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS expedientes (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL REFERENCES usuarios(id),
                cliente TEXT NOT NULL,
                descripcion TEXT NOT NULL,
                importe REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS comentarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                expediente_id INTEGER NOT NULL REFERENCES expedientes(id),
                usuario TEXT NOT NULL,
                texto TEXT NOT NULL,
                creado TEXT NOT NULL
            );
            """
        )
        # Migraciones ligeras para bases creadas antes de añadir la demo de
        # SQLi en /login y la asociación de notas a expedientes.
        columnas_usuarios = {
            fila["name"] for fila in conn.execute("PRAGMA table_info(usuarios)")
        }
        if "password" not in columnas_usuarios:
            conn.execute("ALTER TABLE usuarios ADD COLUMN password TEXT")
            conn.execute("UPDATE usuarios SET password = ?", (password,))
        columnas = {
            fila["name"] for fila in conn.execute("PRAGMA table_info(comentarios)")
        }
        if "expediente_id" not in columnas:
            conn.execute(
                "ALTER TABLE comentarios ADD COLUMN expediente_id "
                "INTEGER NOT NULL DEFAULT 1 REFERENCES expedientes(id)"
            )
        if conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO usuarios "
                "(id, username, rol, password_hash, password) VALUES (?,?,?,?,?)",
                [
                    (1, "s_tio", "socio", hash_usuarios, password),
                    (2, "c_contador", "abogado", hash_usuarios, password),
                    (3, "a_auxiliar", "asistente", hash_usuarios, password),
                ],
            )
        if conn.execute("SELECT COUNT(*) FROM expedientes").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO expedientes (id, owner_id, cliente, descripcion, importe) "
                "VALUES (?,?,?,?,?)",
                [
                    (1, 1, "Constructora Delta", "Declaración fiscal 2026", 12500.0),
                    (2, 1, "Comercial Aurora", "Dictamen legal", 8300.0),
                    (3, 2, "Servicios Norte", "Nómina mayo 2026", 4700.0),
                    (4, 2, "Inmobiliaria Sur", "Expediente contable", 9100.0),
                    (5, 3, "Distribuidora Este", "Facturas por revisar", 2150.0),
                ],
            )
        # Asunto reservado al socio: permite mostrar IDOR (ficha HTML) y BOLA
        # (API del mismo objeto) con un expediente claramente ajeno al asistente.
        if not conn.execute("SELECT 1 FROM expedientes WHERE id = 6").fetchone():
            conn.execute(
                "INSERT INTO expedientes (id, owner_id, cliente, descripcion, importe) "
                "VALUES (?,?,?,?,?)",
                (
                    6, 1, "Inversiones Ébano",
                    "Due diligence confidencial · asunto reservado al socio", 15800.0,
                ),
            )
        if conn.execute("SELECT COUNT(*) FROM comentarios").fetchone()[0] == 0:
            conn.execute(
                "INSERT INTO comentarios (expediente_id, usuario, texto, creado) "
                "VALUES (?,?,?,?)",
                (
                    1,
                    "s_tio",
                    "Nota inicial del expediente: revisar la declaración fiscal.",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        if not conn.execute(
            "SELECT 1 FROM comentarios WHERE expediente_id = 6"
        ).fetchone():
            conn.execute(
                "INSERT INTO comentarios (expediente_id, usuario, texto, creado) "
                "VALUES (?,?,?,?)",
                (
                    6,
                    "s_tio",
                    "Nota reservada: revisar la cláusula de confidencialidad.",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )


# ---------------------------------------------------------------------------
# Registro de eventos y detección (Parte B, Opción B)
# ---------------------------------------------------------------------------
def _cargar_reglas() -> list[dict[str, Any]]:
    try:
        return json.loads(RULES_FILE.read_text(encoding="utf-8"))["reglas"]
    except (OSError, ValueError, KeyError):
        return []


def evaluar_alertas(evento: dict[str, Any], ahora: datetime) -> None:
    """Aplica reglas de correlación simple sobre la ventana temporal."""
    for regla in _cargar_reglas():
        coincide = [e for e in _eventos if e["tipo"] == regla["tipo"]]
        ventana = [
            e
            for e in coincide
            if (ahora - datetime.fromisoformat(e["timestamp"])).total_seconds()
            <= regla["ventana_segundos"]
        ]
        if len(ventana) < regla["umbral"]:
            continue
        clave = regla["id"]
        activa = next(
            (
                a
                for a in _alertas
                if a["regla"] == clave
                and (ahora - datetime.fromisoformat(a["fin"])).total_seconds() < 120
            ),
            None,
        )
        if activa:
            activa["cantidad"] = len(ventana)
            activa["fin"] = ahora.isoformat()
            activa["eventos"] = [e["id"] for e in ventana[-5:]]
            continue
        alerta = {
            "id": f"AL-{secrets.token_hex(4).upper()}",
            "regla": clave,
            "severidad": regla["severidad"],
            "titulo": regla["titulo"],
            "cantidad": len(ventana),
            "umbral": regla["umbral"],
            "ventana_segundos": regla["ventana_segundos"],
            "inicio": ventana[0]["timestamp"],
            "fin": ahora.isoformat(),
            "eventos": [e["id"] for e in ventana[-5:]],
        }
        _alertas.insert(0, alerta)
        del _alertas[100:]
        _append_jsonl(ALERT_LOG_FILE, {"tipo": "ALERTA", **alerta})


def _append_jsonl(ruta: Path, dato: dict[str, Any]) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with ruta.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(dato, ensure_ascii=False) + "\n")


def registrar_evento(
    tipo: str,
    severidad: str,
    mensaje: str,
    *,
    usuario: str | None = None,
    estado: int | None = None,
) -> None:
    ahora = datetime.now(timezone.utc)
    evento = {
        "id": f"EV-{secrets.token_hex(5).upper()}",
        "timestamp": ahora.isoformat(),
        "modo": MODO,
        "tipo": tipo,
        "severidad": severidad,
        "mensaje": mensaje,
        "ip": request.remote_addr or "desconocida",
        "metodo": request.method,
        "ruta": request.path,
        "user_agent": (request.user_agent.string or "")[:180],
        "usuario": usuario or session.get("usuario", "anónimo"),
        "estado": estado,
    }
    with _lock:
        _eventos.insert(0, evento)
        del _eventos[500:]
        _append_jsonl(LOG_FILE, evento)
        evaluar_alertas(evento, ahora)


def usuario_actual() -> sqlite3.Row | None:
    uid = session.get("uid")
    if uid is None:
        return None
    with conectar() as conn:
        return conn.execute("SELECT * FROM usuarios WHERE id = ?", (uid,)).fetchone()


def puede_leer_expediente(fila: sqlite3.Row | None, usuario: sqlite3.Row | None) -> bool:
    """Autorización centralizada por objeto: propietario o rol socio."""
    return bool(
        fila
        and usuario
        and (fila["owner_id"] == usuario["id"] or usuario["rol"] == "socio")
    )


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if usuario_actual() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def _destino_seguro(destino: str | None) -> str:
    """Evita redirecciones abiertas tras el login."""
    if destino:
        destino = destino.strip()
        partes = urlsplit(destino)
        if (
            destino.startswith("/")
            and not destino.startswith("//")
            and not partes.scheme
            and not partes.netloc
            and "\\" not in destino
        ):
            return destino
    return url_for("indice")


# ---------------------------------------------------------------------------
# Cabeceras y control de acceso
# ---------------------------------------------------------------------------
@app.after_request
def cabeceras(respuesta):
    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    respuesta.headers["Referrer-Policy"] = "no-referrer"
    if MODO == "secure":
        respuesta.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        respuesta.headers["X-Frame-Options"] = "DENY"
        respuesta.headers["Cache-Control"] = "no-store"
        respuesta.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        respuesta.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    else:
        # intencional: sin CSP para permitir la demostración de XSS
        respuesta.headers["X-Lab-Mode"] = "vulnerable"
    return respuesta


@app.before_request
def exigir_login():
    """Puerta de acceso global, en los dos modos.

    El modo vulnerable sigue siéndolo: la autenticación solo decide quién entra,
    no corrige SQLi, XSS ni la autorización por objeto.
    """
    if request.endpoint == "static" or request.path in RUTAS_PUBLICAS:
        return None
    if usuario_actual() is not None:
        return None
    destino = request.full_path if request.query_string else request.path
    registrar_evento(
        "ACCESO_NO_AUTENTICADO", "medio",
        f"Solicitud sin sesión a {request.path}", estado=302,
    )
    return redirect(url_for("login", next=destino))


@app.before_request
def validar_csrf():
    """Exige token por sesión en toda petición que cambie estado (modo seguro)."""
    if MODO != "secure" or request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    recibido = request.form.get(
        CSRF_CAMPO, request.headers.get("X-CSRF-Token", "")
    )
    esperado = session.get(CSRF_CAMPO, "")
    if esperado and hmac.compare_digest(str(recibido), str(esperado)):
        return None
    registrar_evento(
        "CSRF_RECHAZADO",
        "alto",
        f"Petición {request.method} {request.path} sin token CSRF válido",
        estado=403,
    )
    return jsonify(error="Token CSRF inválido o ausente"), 403


@app.before_request
def limitar_login():
    if MODO != "secure" or request.path != "/login" or request.method != "POST":
        return None
    ahora = datetime.now(timezone.utc)
    ip = request.remote_addr or "desconocida"
    con = _intentos_login.setdefault(ip, [])
    con[:] = [t for t in con if (ahora - t).total_seconds() < 60]
    # Valor por defecto 10; se puede subir solo para la generación de capturas.
    limite = int(os.environ.get("LAB_LOGIN_LIMIT", "10"))
    if len(con) >= limite:
        registrar_evento(
            "RATE_LIMIT",
            "medio",
            "Límite de 10 intentos de login por minuto alcanzado",
            estado=429,
        )
        return jsonify(error="Demasiados intentos. Intente de nuevo en un minuto."), 429
    con.append(ahora)
    return None


@app.context_processor
def tema_plantillas():
    """Tema ejecutivo opcional, solo para las capturas de presentación."""
    tema = "ejecutivo" if request.args.get("tema") == "ejecutivo" else "laboratorio"
    return {"tema": tema}


@app.context_processor
def csrf_contexto():
    """Expone un token por sesión a los formularios del modo seguro."""

    def token_csrf() -> str:
        if MODO != "secure":
            return ""
        if CSRF_CAMPO not in session:
            session[CSRF_CAMPO] = secrets.token_urlsafe(32)
        return session[CSRF_CAMPO]

    return {"csrf_token": token_csrf}


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------
@app.route("/")
def indice():
    return render_template(
        "indice.html",
        modo=MODO,
        endpoint=[
            ("/", "Inicio del portal"),
            ("/login", "Acceso del personal (SQLi en vulnerable)"),
            ("/buscar?q=", "Consulta de expedientes (SQLi)"),
            ("/expediente/<id>", "Ficha del asunto (IDOR/BOLA)"),
            ("/comentarios?expediente_id=", "Notas del expediente (XSS)"),
            ("/alertas", "Seguridad del portal (Opción B)"),
            ("/health", "Estado del servicio"),
        ],
    )


@app.route("/health")
def health():
    return jsonify(ok=True, modo=MODO, eventos=len(_eventos), alertas=len(_alertas))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if PATRON_SQLI.search(username) or PATRON_SQLI.search(password):
            registrar_evento(
                "SQLI_DETECTADO", "alto",
                f"Patrón de inyección SQL en /login: {username[:80]!r}",
                estado=401,
            )
        with conectar() as conn:
            if MODO == "vulnerable":
                # VULNERABILIDAD 4: concatenación directa en la autenticación.
                # 's_tio' --  comenta la comparación de contraseña y entra sin clave.
                sql = (
                    "SELECT * FROM usuarios WHERE username = "
                    f"'{username}' AND password = '{password}'"
                )
                fila = conn.execute(sql).fetchone()
                valido = bool(fila)
            else:
                # CORRECCIÓN 4: parámetros + verificación del hash.
                fila = conn.execute(
                    "SELECT * FROM usuarios WHERE username = ?", (username,)
                ).fetchone()
                valido = bool(
                    fila and check_password_hash(fila["password_hash"], password)
                )
        if valido:
            session.clear()
            if MODO == "secure":
                # Rotación del token anti-CSRF al cambiar de identidad.
                session[CSRF_CAMPO] = secrets.token_urlsafe(32)
            session["uid"] = fila["id"]
            session["usuario"] = fila["username"]
            session["rol"] = fila["rol"]
            registrar_evento("LOGIN_OK", "bajo", "Inicio de sesión correcto", estado=200)
            return redirect(_destino_seguro(request.form.get("next")))
        registrar_evento("LOGIN_FALLIDO", "medio", "Credenciales rechazadas", estado=401)
        return render_template(
            "login.html", modo=MODO, error="Credenciales inválidas",
            next=request.form.get("next", ""), prefill=username,
        ), 401
    return render_template(
        "login.html", modo=MODO, error=None,
        next=request.args.get("next", ""), prefill=request.args.get("u", ""),
    )


@app.route("/logout")
def logout():
    registrar_evento("LOGOUT", "bajo", "Cierre de sesión")
    session.clear()
    return redirect(url_for("indice"))


@app.route("/buscar")
def buscar():
    q = request.args.get("q", "")
    if PATRON_SQLI.search(q):
        registrar_evento(
            "SQLI_DETECTADO",
            "alto",
            f"Patrón de inyección SQL en parámetro q: {q[:120]!r}",
            estado=200,
        )
    with conectar() as conn:
        if MODO == "vulnerable":
            # VULNERABILIDAD 1: concatenación directa de entrada no confiable.
            sql = (
                "SELECT id, cliente, descripcion, importe FROM expedientes "
                f"WHERE cliente LIKE '%{q}%'"
            )
            filas = conn.execute(sql).fetchall()
        else:
            # CORRECCIÓN 1: consulta parametrizada + validación de longitud.
            if len(q) > 80:
                registrar_evento(
                    "INPUT_INVALIDO", "bajo", "Parámetro q demasiado largo", estado=400
                )
                abort(400)
            filas = conn.execute(
                "SELECT id, cliente, descripcion, importe FROM expedientes "
                "WHERE cliente LIKE ?",
                (f"%{q}%",),
            ).fetchall()
    return render_template(
        "buscar.html", modo=MODO, q=q, resultados=[dict(f) for f in filas]
    )


@app.route("/expediente/<int:expediente_id>")
@login_required
def expediente(expediente_id: int):
    with conectar() as conn:
        fila = conn.execute(
            "SELECT e.id, e.cliente, e.descripcion, e.importe, e.owner_id, u.username "
            "FROM expedientes e JOIN usuarios u ON u.id = e.owner_id WHERE e.id = ?",
            (expediente_id,),
        ).fetchone()
    usuario = usuario_actual()
    if MODO == "secure":
        # CORRECCIÓN 3: autorización en servidor (owner o rol socio).
        if not puede_leer_expediente(fila, usuario):
            registrar_evento(
                "ACCESO_DENEGADO",
                "alto",
                f"El usuario intentó leer el expediente {expediente_id} sin permiso",
                estado=403,
            )
            abort(403)
        registrar_evento(
            "ACCESO_PERMITIDO",
            "info",
            f"Expediente {expediente_id} autorizado",
            estado=200,
        )
    elif fila is None:
        abort(404)
    # VULNERABILIDAD 3: en modo vulnerable no se verifica propiedad ni rol.
    return render_template("expediente.html", modo=MODO, expediente=dict(fila))


@app.route("/api/expediente/<int:expediente_id>")
@login_required
def api_expediente(expediente_id: int):
    with conectar() as conn:
        fila = conn.execute(
            "SELECT id, owner_id, cliente, descripcion, importe FROM expedientes WHERE id = ?",
            (expediente_id,),
        ).fetchone()
    usuario = usuario_actual()
    if MODO == "secure":
        if not puede_leer_expediente(fila, usuario):
            registrar_evento(
                "ACCESO_DENEGADO",
                "alto",
                f"API: acceso denegado al expediente {expediente_id}",
                estado=403,
            )
            return jsonify(error="No autorizado"), 403
    if fila is None:
        return jsonify(error="No encontrado"), 404
    return jsonify(dict(fila))


@app.route("/comentarios", methods=["GET", "POST"])
def comentarios():
    """Notas adjuntas a un expediente; ya no es un buzón genérico."""
    usuario = usuario_actual()
    id_solicitado = request.values.get("expediente_id", type=int)
    with conectar() as conn:
        visibles = [
            dict(f)
            for f in conn.execute(
                "SELECT id, owner_id, cliente FROM expedientes ORDER BY id"
            )
            if MODO != "secure" or puede_leer_expediente(f, usuario)
        ]
        # La entrada desde la barra de navegación abre el primer asunto que el
        # usuario puede ver; las notas siempre pertenecen a un expediente.
        if id_solicitado is None:
            if request.method == "POST":
                abort(400)
            if not visibles:
                abort(404)
            return redirect(url_for("comentarios", expediente_id=visibles[0]["id"]))
        expediente_id = id_solicitado
        expediente = conn.execute(
            "SELECT id, owner_id, cliente FROM expedientes WHERE id = ?",
            (expediente_id,),
        ).fetchone()
    if expediente is None:
        abort(404)
    if MODO == "secure" and not puede_leer_expediente(expediente, usuario):
        registrar_evento(
            "ACCESO_DENEGADO", "alto",
            f"Comentarios del expediente {expediente_id} denegados", estado=403,
        )
        abort(403)
    if expediente is None:
        abort(404)

    if request.method == "POST":
        texto = request.form.get("texto", "")
        if PATRON_XSS.search(texto):
            registrar_evento(
                "XSS_DETECTADO", "alto",
                f"Etiqueta o handler sospechoso en comentario del expediente "
                f"{expediente_id}: {texto[:120]!r}",
                estado=200,
            )
        if MODO == "secure" and len(texto) > 500:
            registrar_evento(
                "INPUT_INVALIDO", "bajo", "Comentario demasiado largo", estado=400
            )
            abort(400)
        with conectar() as conn:
            conn.execute(
                "INSERT INTO comentarios "
                "(expediente_id, usuario, texto, creado) VALUES (?,?,?,?)",
                (
                    expediente_id,
                    session.get("usuario", "anónimo"),
                    texto,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        registrar_evento(
            "COMENTARIO_PUBLICADO", "bajo",
            f"Comentario añadido al expediente {expediente_id}", estado=302,
        )
        return redirect(url_for("comentarios", expediente_id=expediente_id))

    with conectar() as conn:
        filas = conn.execute(
            "SELECT id, usuario, texto, creado FROM comentarios "
            "WHERE expediente_id = ? ORDER BY id DESC LIMIT 20",
            (expediente_id,),
        ).fetchall()
    # VULNERABILIDAD 2: en modo vulnerable la plantilla usa |safe.
    # CORRECCIÓN 2: en modo seguro se usa autoescape de Jinja + CSP.
    return render_template(
        "comentarios.html", modo=MODO, comentarios=[dict(f) for f in filas],
        expediente=dict(expediente), visibles=visibles,
    )


@app.route("/alertas")
@login_required
def alertas():
    usuario = usuario_actual()
    if MODO == "secure" and usuario["rol"] != "socio":
        registrar_evento(
            "ACCESO_DENEGADO",
            "alto",
            "Intento de consultar el panel de alertas sin rol socio",
            estado=403,
        )
        abort(403)
    with conectar() as conn:
        total_eventos = conn.execute("SELECT COUNT(*) FROM comentarios").fetchone()[0]
    return render_template(
        "alertas.html",
        modo=MODO,
        eventos=_eventos[:40],
        alertas=_alertas[:20],
        total_comentarios=total_eventos,
    )


@app.route("/api/alertas")
@login_required
def api_alertas():
    usuario = usuario_actual()
    if MODO == "secure" and usuario["rol"] != "socio":
        return jsonify(error="No autorizado"), 403
    return jsonify(modo=MODO, eventos=_eventos[:100], alertas=_alertas[:50])


if __name__ == "__main__":
    init_db()
    puerto = int(os.environ.get("LAB_PORT", "5000" if MODO == "vulnerable" else "5001"))
    print(
        f"[lab] modo={MODO} puerto={puerto} db={DB_PATH} log={LOG_FILE}",
        flush=True,
    )
    app.run(host="127.0.0.1", port=puerto, debug=False, threaded=True)
