#!/usr/bin/env bash
# Regenera TODAS las capturas a pantalla completa con el tema ejecutivo.
# Requiere: app vulnerable en :5000, app corregida en :5001, grim, slurp,
# PyQt6, dwl con IPC v2 y LAB_PASSWORD con la contraseña de laboratorio.
set -euo pipefail

BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE"

: "${LAB_PASSWORD:?Defina LAB_PASSWORD}"
export LAB_PASSWORD LAB_FULLSCREEN=1
TMP=/tmp/opencode/proyecto-final
mkdir -p "$TMP" capturas/documento capturas/presentacion evidencias/texto
READY="$TMP/ready_captura"
SQLI='Delta%27%20OR%20%271%27%3D%271%27%20--'
ZAP="file://$BASE/evidencias/zap/zap_report.html"

# El XSS de las pruebas automáticas es una etiqueta <script> (no deja texto
# visible). Se añade un payload visual para que la captura sea legible.
python3 - <<'PY'
import os, re, requests
s = requests.Session()
datos = {'username': 's_tio', 'password': os.environ['LAB_PASSWORD']}
token = re.search(r'name="csrf_token"\s+value="([^"]+)"',
                  s.get('http://127.0.0.1:5000/login', timeout=10).text)
if token:
    datos['csrf_token'] = token.group(1)
s.post('http://127.0.0.1:5000/login', data=datos, timeout=10)
datos = {'texto': "<img src=x onerror=\"this.insertAdjacentHTML('afterend','<h2 style=color:#ff8292>XSS EJECUTADO EN EL NAVEGADOR</h2>')\">"}
token = re.search(r'name="csrf_token"\s+value="([^"]+)"',
                  s.get('http://127.0.0.1:5000/comentarios', timeout=10).text)
if token:
    datos['csrf_token'] = token.group(1)
s.post('http://127.0.0.1:5000/comentarios', data=datos, timeout=10)
PY

: > evidencias/texto/07_capturas.txt
printf 'Capturas regeneradas con grim -o eDP-1 y ventana a pantalla completa.\n' \
  >> evidencias/texto/07_capturas.txt
printf 'Geometría verificada con el IPC de dwl (scripts/ipc_geometria.sh).\n\n' \
  >> evidencias/texto/07_capturas.txt

cerrar() {
  if [[ -n ${PID:-} ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  # Anclado al inicio para no matar otras shells que mencionen ese archivo.
  pkill -f '^python3 scripts/ver_app.py' 2>/dev/null || true
  sleep 0.4
}
trap cerrar EXIT

con_tema() {
  case "$1" in
    *\?*) printf '%s&tema=ejecutivo\n' "$1" ;;
    *)    printf '%s?tema=ejecutivo\n' "$1" ;;
  esac
}

cap() {
  local archivo="$1" url="$2" usuario="${3:-}"
  rm -f "$READY"
  cerrar
  if [[ -n "$usuario" ]]; then
    LAB_READY_FILE="$READY" python3 scripts/ver_app.py "$url" "$usuario" \
      > "$TMP/ver_app.log" 2>&1 &
  else
    LAB_READY_FILE="$READY" python3 scripts/ver_app.py "$url" \
      > "$TMP/ver_app.log" 2>&1 &
  fi
  PID=$!
  if ! timeout 25 bash -c "until [ -f '$READY' ]; do sleep 0.2; done"; then
    echo "ERROR: la página no terminó de cargar: $url" >&2
    cat "$TMP/ver_app.log" >&2
    exit 1
  fi
  local estado geom
  estado=$(cat "$READY")
  geom=$(scripts/ipc_geometria.sh || printf 'IPC_NO_DISPONIBLE')
  if [[ "$geom" != '0,0 1920x1080' ]]; then
    echo "AVISO: geometría inesperada ($geom) en $archivo" >&2
  fi
  SLURP_OUTPUT=eDP-1 scripts/capturar.sh "$archivo"
  printf '%-42s %-8s %s %s\n' "$archivo" "$estado" "$geom" "$url" \
    >> evidencias/texto/07_capturas.txt
  echo "[ok] $archivo  ($geom)"
}

# --- Documento (ilustran INFORME.org) -------------------------------------
cap capturas/documento/01_endpoints.png       "$(con_tema 'http://127.0.0.1:5000/')"
cap capturas/documento/02_sqli_vulnerable.png "$(con_tema "http://127.0.0.1:5000/buscar?q=$SQLI")"
cap capturas/documento/03_xss_vulnerable.png  "$(con_tema 'http://127.0.0.1:5000/comentarios')"
cap capturas/documento/04_idor_vulnerable.png "$(con_tema 'http://127.0.0.1:5000/expediente/1')" a_auxiliar
cap capturas/documento/05_zap_hallazgos.png   "$ZAP"
cap capturas/documento/06_sqli_corregido.png  "$(con_tema "http://127.0.0.1:5001/buscar?q=$SQLI")"
cap capturas/documento/07_xss_corregido.png   "$(con_tema 'http://127.0.0.1:5001/comentarios')" s_tio
cap capturas/documento/08_idor_corregido.png  "$(con_tema 'http://127.0.0.1:5001/expediente/1')" a_auxiliar
cap capturas/documento/09_alertas_monitoreo.png "$(con_tema 'http://127.0.0.1:5001/alertas')" s_tio

# --- Presentación (mismo tema ejecutivo, carpetas separadas) --------------
cap capturas/presentacion/01_contexto.png        "$(con_tema 'http://127.0.0.1:5001/')"
cap capturas/presentacion/02_vulnerabilidades.png "$(con_tema "http://127.0.0.1:5000/buscar?q=$SQLI")"
cap capturas/presentacion/03_correciones.png     "$(con_tema "http://127.0.0.1:5001/buscar?q=$SQLI")"
cap capturas/presentacion/04_monitoreo.png       "$(con_tema 'http://127.0.0.1:5001/alertas')" s_tio
cap capturas/presentacion/05_hallazgos_zap.png   "$ZAP"

cerrar
echo 'Capturas terminadas.'
