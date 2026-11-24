#!/usr/bin/env bash
# Arranca una de las dos versiones de la aplicación de laboratorio.
# Uso: lab/run.sh vulnerable 5000 | lab/run.sh secure 5001
set -euo pipefail
cd "$(dirname "$0")/.."

MODO="${1:-vulnerable}"
PUERTO="${2:-5000}"

if [[ "$MODO" != "vulnerable" && "$MODO" != "secure" ]]; then
  echo "Uso: $0 vulnerable|secure [puerto]" >&2
  exit 2
fi

# El password y la clave de sesión se generan aquí y NO se guardan en el repo.
if [[ -z "${LAB_USER_PASSWORD:-}" ]]; then
  export LAB_USER_PASSWORD="Lab$(openssl rand -hex 6)!"
  echo "[run] contraseña de laboratorio generada: $LAB_USER_PASSWORD" >&2
fi
export LAB_SECRET_KEY="${LAB_SECRET_KEY:-$(openssl rand -hex 32)}"
export LAB_MODE="$MODO"
export LAB_PORT="$PUERTO"
export LAB_DB="${LAB_DB:-app/lab_${MODO}.sqlite3}"

echo "[run] http://127.0.0.1:$PUERTO  modo=$MODO" >&2
exec python3 app/app.py
