#!/usr/bin/env bash
# Instala OWASP ZAP (release Linux) de forma idempotente bajo ~/.local/zap.
# Uso: ./lab/zap/instalar_zap.sh [VER_VERSION]
# Variables opcionales: ZAP_INSTALL_DIR, ZAP_VERSION, ZAP_SHA256, ZAP_URL, ZAP_SH.
set -euo pipefail

ZAP_VERSION="${ZAP_VERSION:-${1:-2.17.0}}"
ZAP_SHA256="${ZAP_SHA256:-efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a}"
ZAP_URL="${ZAP_URL:-https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz}"
INSTALL_DIR="${ZAP_INSTALL_DIR:-${HOME}/.local/zap}"
TARGET_DIR="${INSTALL_DIR}/ZAP_${ZAP_VERSION}"

log() { printf '[instalar_zap] %s\n' "$*"; }

version_of() {
  local sh="$1"
  "$sh" -version 2>/dev/null | tail -n 1 | tr -d '\r[:space:]'
}

if [[ -n "${ZAP_SH:-}" && -x "${ZAP_SH}" ]]; then
  log "Usando ZAP_SH=${ZAP_SH}"
  exit 0
fi
if [[ -x "${TARGET_DIR}/zap.sh" ]]; then
  current="$(version_of "${TARGET_DIR}/zap.sh")"
  if [[ "$current" == "$ZAP_VERSION" ]]; then
    log "ZAP ${ZAP_VERSION} ya instalado en ${TARGET_DIR} (idempotente)."
    exit 0
  fi
  log "Versión instalada (${current}) != ${ZAP_VERSION}; reinstalando."
fi

for cmd in curl tar sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || { log "Falta el comando: $cmd" >&2; exit 1; }
done

mkdir -p "$INSTALL_DIR" /tmp/opencode
WORK="$(mktemp -d /tmp/opencode/zap-install.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

ARCHIVE="${WORK}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
log "Descargando ${ZAP_URL} ..."
curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 900 -o "$ARCHIVE" "$ZAP_URL"

if [[ -n "$ZAP_SHA256" ]]; then
  echo "${ZAP_SHA256}  ${ARCHIVE}" | sha256sum -c - || { log "SHA256 no coincide" >&2; exit 1; }
  log "SHA256 verificado."
else
  log "AVISO: no se verificó SHA256 (ZAP_SHA256 vacío)."
fi

log "Descomprimiendo en ${INSTALL_DIR} ..."
tar -xzf "$ARCHIVE" -C "$INSTALL_DIR"

[[ -x "${TARGET_DIR}/zap.sh" ]] || { log "No se encontró ${TARGET_DIR}/zap.sh" >&2; exit 1; }
chmod +x "${TARGET_DIR}/zap.sh"
installed="$(version_of "${TARGET_DIR}/zap.sh")"
log "Versión verificada: ${installed}"
log "ZAP listo en: ${TARGET_DIR}/zap.sh"
