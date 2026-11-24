#!/usr/bin/env bash
# Escaneo OWASP ZAP en modo daemon contra una URL base.
# Uso: ./lab/zap/scan.sh [URL_BASE] [OUTPUT_DIR]
# Por defecto: URL_BASE=http://127.0.0.1:5000  OUTPUT_DIR=<lab/zap>/salida
#
# Variables opcionales:
#   ZAP_SH, ZAP_PORT, ZAP_SPIDER_TIMEOUT, ZAP_ASCAN_TIMEOUT, ZAP_PSCAN_TIMEOUT
# La API key se genera al azar en cada ejecución y se borra al terminar.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

usage() {
  cat <<EOF
Uso: $0 [URL_BASE] [OUTPUT_DIR]
  URL_BASE   (por defecto http://127.0.0.1:5000)
  OUTPUT_DIR (por defecto ${SCRIPT_DIR}/salida)
Ejemplo: $0 http://127.0.0.1:5000 /tmp/opencode/zap_app
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

URL_BASE="${1:-${ZAP_TARGET_URL:-http://127.0.0.1:5000}}"
OUT_DIR="${2:-${ZAP_OUT_DIR:-${SCRIPT_DIR}/salida}}"
ZAP_SPIDER_TIMEOUT="${ZAP_SPIDER_TIMEOUT:-300}"
ZAP_ASCAN_TIMEOUT="${ZAP_ASCAN_TIMEOUT:-900}"
ZAP_PSCAN_TIMEOUT="${ZAP_PSCAN_TIMEOUT:-180}"

mkdir -p "$OUT_DIR" /tmp/opencode
OUT_DIR="$(cd -- "$OUT_DIR" && pwd)"
LOG="${OUT_DIR}/scan.log"
: >"$LOG"

log() { printf '[scan] %s\n' "$*" | tee -a "$LOG"; }

find_zap() {
  if [[ -n "${ZAP_SH:-}" ]]; then
    [[ -x "$ZAP_SH" ]] && { printf '%s\n' "$ZAP_SH"; return 0; }
    log "ZAP_SH no ejecutable: $ZAP_SH" >&2
    return 1
  fi
  local d
  shopt -s nullglob
  for d in "$HOME/.local/zap"/ZAP_* "$REPO_ROOT/tools"/zap/ZAP_* "$REPO_ROOT/tools"/ZAP_*; do
    if [[ -x "$d/zap.sh" ]]; then printf '%s\n' "$d/zap.sh"; shopt -u nullglob; return 0; fi
  done
  shopt -u nullglob
  log "No se encontró zap.sh; ejecuta primero instalar_zap.sh" >&2
  return 1
}

ZAP_SH="$(find_zap)"
ZAP_HOME_DIR="$(cd -- "$(dirname -- "$ZAP_SH")/.." && pwd)"
log "ZAP: ${ZAP_SH}"
log "Objetivo: ${URL_BASE}"
log "Salida: ${OUT_DIR}"

WORK_DIR="$(mktemp -d /tmp/opencode/zap-scan.XXXXXX)"
chmod 700 "$WORK_DIR"
KEY_FILE="${WORK_DIR}/api.key"
ZAP_PID=""

cleanup() {
  local rc=$?
  if [[ -n "$ZAP_PID" ]] && kill -0 "$ZAP_PID" 2>/dev/null; then
    log "Deteniendo ZAP (PID ${ZAP_PID}) ..."
    kill "$ZAP_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$ZAP_PID" 2>/dev/null || break
      sleep 0.5
    done
    kill -9 "$ZAP_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
  return "$rc"
}
trap cleanup EXIT INT TERM

# API key aleatoria (nunca se escribe en los informes ni en los logs).
API_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))' 2>/dev/null \
  || openssl rand -hex 32 2>/dev/null \
  || od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
printf '%s' "$API_KEY" >"$KEY_FILE"
chmod 600 "$KEY_FILE"
unset API_KEY

if [[ -n "${ZAP_PORT:-}" ]]; then
  PORT="$ZAP_PORT"
else
  PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
fi
log "Puerto API ZAP: ${PORT}"

SESSION_DIR="${WORK_DIR}/session"
mkdir -p "$SESSION_DIR"

"$ZAP_SH" -Xmx1g -daemon -host 127.0.0.1 -port "$PORT" \
  -dir "$SESSION_DIR" \
  -config api.key="$(cat "$KEY_FILE")" \
  -config api.addrs.addr.name=127.0.0.1 \
  -config api.addrs.addr.regex=true \
  >"${OUT_DIR}/zap_daemon.log" 2>&1 &
ZAP_PID=$!

READY=0
for _ in $(seq 1 180); do
  if ! kill -0 "$ZAP_PID" 2>/dev/null; then
    log "ERROR: el proceso ZAP terminó antes de arrancar. Ver zap_daemon.log" >&2
    tail -n 30 "${OUT_DIR}/zap_daemon.log" >>"$LOG" 2>/dev/null || true
    exit 1
  fi
  if curl -fsS --max-time 3 -H "X-ZAP-API-Key: $(cat "$KEY_FILE")" \
      "http://127.0.0.1:${PORT}/JSON/core/view/version/" 2>/dev/null | grep -q '"version"'; then
    READY=1
    break
  fi
  sleep 1
done
if [[ "$READY" -ne 1 ]]; then
  log "ERROR: timeout esperando la API de ZAP. Ver zap_daemon.log" >&2
  tail -n 30 "${OUT_DIR}/zap_daemon.log" >>"$LOG" 2>/dev/null || true
  exit 1
fi
log "API de ZAP lista."

python3 - "$URL_BASE" "$PORT" "$KEY_FILE" "$OUT_DIR" "$ZAP_HOME_DIR" \
  "$ZAP_SPIDER_TIMEOUT" "$ZAP_ASCAN_TIMEOUT" "$ZAP_PSCAN_TIMEOUT" <<'PY'
import json
import pathlib
import re
import shutil
import sys
import time
from datetime import datetime, timezone

import requests

target, port, keyfile, outdir, zap_home, spider_to, ascan_to, pscan_to = sys.argv[1:9]
outdir = pathlib.Path(outdir)
key = pathlib.Path(keyfile).read_text().strip()
base = f"http://127.0.0.1:{port}"
spider_to, ascan_to, pscan_to = int(spider_to), int(ascan_to), int(pscan_to)

session = requests.Session()
session.headers.update({"X-ZAP-API-Key": key, "Accept": "application/json"})


def say(msg):
    print(f"[python] {msg}", flush=True)


def api(component, path, kind="JSON", **params):
    url = f"{base}/{kind}/{component}/{path}/"
    r = session.get(url, params=params, timeout=(5, 40))
    r.raise_for_status()
    if kind != "JSON":
        return r.content
    try:
        data = r.json()
    except ValueError as exc:
        raise RuntimeError(f"Respuesta no JSON de {url}: {r.text[:300]}") from exc
    if isinstance(data, dict) and {"code", "message"} <= set(data) and data.get("code") not in (None, "OK", 200, "200"):
        raise RuntimeError(f"Error API {component}/{path}: {data}")
    return data


def as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return -1


def wait_status(component, scan_id, limit, label):
    """Espera a que termine un scan; en timeout lo detiene y avisa (informe parcial)."""
    end = time.monotonic() + limit
    last = None
    while time.monotonic() < end:
        data = api(component, "view/status", scanId=scan_id)
        last = as_int(data.get("status")) if isinstance(data, dict) else -1
        if last >= 100:
            say(f"{label} completado (scanId={scan_id}).")
            return True
        time.sleep(2)
    say(f"AVISO: timeout de {limit}s en {label} (scanId={scan_id}, último estado={last}); se detiene y se informa lo parcial.")
    try:
        api(component, "action/stop", scanId=scan_id)
    except Exception as exc:
        say(f"AVISO: no se pudo detener {label}: {exc}")
    time.sleep(2)
    return False


version = api("core", "view/version").get("version", "desconocida")
say(f"Versión ZAP detectada: {version}")

# Sembrar el árbol de sitios con la URL base.
try:
    api("core", "action/accessUrl", url=target)
    say(f"URL sembrada: {target}")
except Exception as exc:
    say(f"AVISO: no se pudo acceder a {target} desde ZAP: {exc}")

# Alcance: el objetivo y todo lo que cuelgue de él.
try:
    context_name = "zap-scan-lab"
    names = api("context", "view/contextList").get("contextList", [])
    if context_name not in names:
        api("context", "action/newContext", contextName=context_name)
    api("context", "action/includeInContext", contextName=context_name,
        regex=re.escape(target) + ".*")
    api("context", "action/setContextInScope", contextName=context_name,
        booleanInScope="true")
    say(f"Alcance fijado en contexto '{context_name}'.")
except Exception as exc:
    say(f"AVISO: no se pudo fijar el alcance: {exc}")

# Spider.
try:
    spider_id = as_int(api("spider", "action/scan", url=target, maxChildren="500",
                           recurse="true", subtreeOnly="false").get("scan"))
    say(f"Spider iniciado (scanId={spider_id}).")
    if spider_id >= 0:
        wait_status("spider", spider_id, spider_to, "Spider")
except Exception as exc:
    say(f"AVISO: fallo al iniciar spider: {exc}")

# Passive scan (para que las alertas pasivas estén listas antes del activo).
end = time.monotonic() + pscan_to
while time.monotonic() < end:
    try:
        pending = as_int(api("pscan", "view/recordsToScan").get("recordsToScan", "0"))
    except Exception as exc:
        say(f"AVISO: no se pudo consultar pscan: {exc}")
        break
    if pending <= 0:
        say("Passive scan al día.")
        break
    time.sleep(2)
else:
    say(f"AVISO: timeout de {pscan_to}s esperando passive scan; se continúa.")

# Active scan.
try:
    ascan_id = as_int(api("ascan", "action/scan", url=target, recurse="true",
                          inScopeOnly="false").get("scan"))
    say(f"Active scan iniciado (scanId={ascan_id}).")
    if ascan_id >= 0:
        wait_status("ascan", ascan_id, ascan_to, "Active scan")
except Exception as exc:
    say(f"AVISO: fallo al iniciar active scan: {exc}")

# Alertas, sitios y URLs.
alerts_data = api("core", "view/alerts")
alerts = alerts_data.get("alerts", []) if isinstance(alerts_data, dict) else []
(outdir / "zap_alertas.json").write_text(
    json.dumps(alerts_data, indent=2, ensure_ascii=False), encoding="utf-8")
try:
    sites = api("core", "view/sites").get("sites", [])
except Exception:
    sites = []
try:
    urls = api("core", "view/urls").get("urls", [])
except Exception:
    urls = []
(outdir / "zap_urls.txt").write_text(
    "\n".join(x if isinstance(x, str) else json.dumps(x, ensure_ascii=False) for x in urls) + "\n",
    encoding="utf-8")

# Informes JSON y HTML mediante el componente 'reports' (con fallback legendario).
def template_ids(data):
    found = []

    def walk(node):
        if isinstance(node, str):
            found.append(node)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in ("id", "name", "templateid", "key"):
                    walk(v)

    walk(data.get("templates", data) if isinstance(data, dict) else data)
    return found


try:
    ids = template_ids(api("reports", "view/templates"))
except Exception as exc:
    say(f"AVISO: no se pudo listar plantillas: {exc}")
    ids = []

say(f"Plantillas disponibles: {sorted(set(ids))}")


def pick_template(kind):
    prefs = (["traditional-json", "sarif-json", "json"] if kind == "json"
             else ["traditional-html", "modern", "html"])
    lower = {i.lower(): i for i in ids}
    for pref in prefs:
        if pref in lower:
            return lower[pref]
    for i in ids:
        if kind in i.lower():
            return i
    return None


def make_report(kind, fallback_path):
    final = outdir / f"zap_reporte.{kind}"
    template = pick_template(kind)
    generated = []
    if template:
        try:
            api("reports", "action/generate", title=f"ZAP - {target}", template=template,
                reportDir=str(outdir), reportFileName=f"zap_reporte_{kind}", display="false")
            generated = sorted(outdir.glob(f"zap_reporte_{kind}*"))
            say(f"Informe {kind.upper()} generado con plantilla '{template}': {[p.name for p in generated]}")
        except Exception as exc:
            say(f"AVISO: falló generate ({kind}, plantilla {template}): {exc}")
    if not generated:
        try:
            payload = api("core", f"other/{fallback_path}", kind="OTHER")
            final.write_bytes(payload)
            generated = [final]
            say(f"Informe {kind.upper()} generado con endpoint OTHER/{fallback_path}.")
        except Exception as exc:
            say(f"ERROR: no se pudo generar informe {kind.upper()}: {exc}")
            return False
    # Normalizar el nombre canónico sin importar el sufijo que añada ZAP.
    source = next((p for p in generated if p != final and p.stat().st_size > 0), None)
    if source and (not final.exists() or final.stat().st_size == 0):
        shutil.copyfile(source, final)
    for p in generated:
        if p != final and p.exists():
            p.unlink()
    return final.exists() and final.stat().st_size > 0


ok_json = make_report("json", "jsonreport")
ok_html = make_report("html", "htmlreport")

# Resumen legible, agrupado por riskcode con sitios/URLs afectados.
risk_names = {3: "High", 2: "Medium", 1: "Low", 0: "Informational", -1: "Unknown"}
risk_by_name = {v.lower(): k for k, v in risk_names.items()}
by_risk = {}
for alert in alerts:
    raw = alert.get("riskcode", alert.get("riskCode"))
    code = as_int(raw) if raw not in (None, "") else None
    mapped = risk_by_name.get(str(alert.get("risk", "")).lower())
    if mapped is not None and (code not in risk_names or code == -1):
        code = mapped
    if code not in risk_names:
        code = -1
    by_risk.setdefault(code, []).append(alert)

lines = [
    "Resumen de escaneo OWASP ZAP",
    "=" * 40,
    f"Fecha (UTC) : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
    f"Objetivo    : {target}",
    f"Versión ZAP : {version}",
    f"Informes    : zap_reporte.json ({'OK' if ok_json else 'FALLO'}), "
    f"zap_reporte.html ({'OK' if ok_html else 'FALLO'})",
    "",
    "Alertas agrupadas por riskcode",
    "-" * 40,
]
for code in sorted(by_risk, reverse=True):
    group = by_risk[code]
    lines.append(f"[{code}] {risk_names.get(code, 'Desconocido')}: {len(group)} alerta(s)")
    names = {}
    for alert in group:
        name = alert.get("name", alert.get("alert", "?"))
        names.setdefault(name, []).append(alert)
    for name, items in sorted(names.items()):
        lines.append(f"  * {name} ({len(items)}) [pluginId={items[0].get('pluginId', '?')}]")
        seen = set()
        for alert in items:
            url = alert.get("url", "")
            if url and url not in seen:
                seen.add(url)
                lines.append(f"      - {url}")
            else:
                lines.append(f"      - {url}")
        param = items[0].get("param")
        if param:
            lines.append(f"      Parámetro: {param}")
        evidence = items[0].get("evidence")
        if evidence:
            lines.append(f"      Evidencia: {str(evidence)[:200]}")
    lines.append("")
if not by_risk:
    lines.append("(sin alertas)")
    lines.append("")

lines += ["Sitios descubiertos", "-" * 40]
lines += [f"  - {s if isinstance(s, str) else json.dumps(s, ensure_ascii=False)}" for s in sites] or ["  (ninguno)"]
lines += ["", "URLs descubiertas", "-" * 40]
lines += [f"  - {u if isinstance(u, str) else json.dumps(u, ensure_ascii=False)}" for u in urls] or ["  (ninguna)"]
lines.append("")
(outdir / "zap_resumen.txt").write_text("\n".join(lines), encoding="utf-8")
say(f"Resumen escrito en {outdir / 'zap_resumen.txt'}")
say("Total alertas por nivel: " + ", ".join(
    f"{risk_names.get(c, c)}={len(v)}" for c, v in sorted(by_risk.items(), reverse=True)) or "0")
PY

log "Escaneo terminado. Informes en ${OUT_DIR}:"
ls -lh "$OUT_DIR"/zap_reporte.json "$OUT_DIR"/zap_reporte.html "$OUT_DIR"/zap_resumen.txt 2>&1 | tee -a "$LOG"
