#!/usr/bin/env bash
# Imprime "x,y WxH" de la ventana enfocada usando el protocolo IPC de dwl.
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TMP=/tmp/opencode/ipc-dwl
mkdir -p "$TMP"

if [[ ! -f "$TMP/dwl_ipc_client.h" || ! -f "$TMP/dwl_ipc_client.c" || "$DIR/dwl-ipc-unstable-v2.xml" -nt "$TMP/dwl_ipc_client.h" ]]; then
  wayland-scanner client-header "$DIR/dwl-ipc-unstable-v2.xml" "$TMP/dwl_ipc_client.h"
  wayland-scanner private-code "$DIR/dwl-ipc-unstable-v2.xml" "$TMP/dwl_ipc_client.c"
fi
if [[ ! -x "$TMP/ipc_geometria" || "$DIR/ipc_geometria.c" -nt "$TMP/ipc_geometria" || "$TMP/dwl_ipc_client.c" -nt "$TMP/ipc_geometria" ]]; then
  gcc -O2 -Wall -I"$TMP" "$DIR/ipc_geometria.c" "$TMP/dwl_ipc_client.c" \
    -o "$TMP/ipc_geometria" $(pkg-config --cflags --libs wayland-client)
fi
"$TMP/ipc_geometria"
