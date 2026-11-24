#!/usr/bin/env bash
# Capturas de pantalla en Wayland (dwl/wlroots) con grim + slurp.
#
# Uso:
#   scripts/capturar.sh <archivo.png> [geometria]
#
# Sin geometria, se invoca slurp de verdad y se usa su seleccion con grim -g.
# Para automatizacion (sin seleccion interactiva) se puede usar:
#   SLURP_GEOMETRY='x,y ancho alto'  (o SLURP_REGION, alias)
#   SLURP_OUTPUT='nombre-output'     (captura ese output con grim -o)
#   parametro 2: geometria literal 'x,y ancho alto'
# Sin ninguna de ellas, tras el timeout se captura el escritorio completo.
set -u

prog=${0##*/}

usage() {
    printf 'Uso: %s <archivo.png> [geometria]\n' "$prog" >&2
    printf '  geometria: "x,y WxH" (o "x,y W H"; slurp imprime la primera)\n' >&2
    printf '  fallback: SLURP_GEOMETRY / SLURP_REGION / SLURP_OUTPUT\n' >&2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
    exit 2
fi
if [[ $1 == -h || $1 == --help ]]; then
    usage
    exit 0
fi

salida=$1
arg_geom=${2:-}

for herramienta in grim slurp; do
    if ! command -v "$herramienta" >/dev/null 2>&1; then
        printf '%s: falta %s en PATH\n' "$prog" "$herramienta" >&2
        exit 127
    fi
done

mkdir -p -- "$(dirname -- "$salida")" || exit 1

# slurp imprime "x,y WxH"; grim solo acepta ese formato. Tambien se acepta
# "x,y W H" por comodidad en la lineas de comandos.
normalizar_geom() {
    if [[ $1 =~ ^([0-9]+),([0-9]+)[[:space:]]+([0-9]+)[[:space:]]+([0-9]+)$ ]]; then
        printf '%s,%s %sx%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" \
            "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"
    else
        printf '%s\n' "$1"
    fi
}

geom=''
output=''
modo=''

if [[ -n $arg_geom ]]; then
    geom=$arg_geom
    modo='fallback: geometria por argumento'
elif [[ -n ${SLURP_GEOMETRY:-} ]]; then
    geom=$SLURP_GEOMETRY
    modo='fallback: SLURP_GEOMETRY'
elif [[ -n ${SLURP_REGION:-} ]]; then
    geom=$SLURP_REGION
    modo='fallback: SLURP_REGION'
elif [[ -n ${SLURP_OUTPUT:-} ]]; then
    output=$SLURP_OUTPUT
    modo="fallback: SLURP_OUTPUT=$output"
else
    # Metodo principal: slurp de verdad; su salida alimenta grim -g.
    # En terminal interactiva se espera a que la persona seleccione; en
    # automatizacion se limita el tiempo y se cae al fallback documentado.
    seleccion=''
    if [[ -t 0 && -z ${CAPTURAR_SLURP_TIMEOUT+x} ]]; then
        if ! seleccion=$(slurp); then
            printf '%s: slurp cancelado o fallo; pide una geometria o usa SLURP_OUTPUT\n' "$prog" >&2
            exit 2
        fi
    else
        espera=${CAPTURAR_SLURP_TIMEOUT:-2}
        seleccion=$(timeout "$espera" slurp 2>/dev/null) || seleccion=''
    fi

    if [[ -n ${seleccion//[[:space:]]/} ]]; then
        geom=$seleccion
        modo='slurp interactivo'
    else
        modo='fallback: pantalla completa (slurp sin seleccion)'
    fi
fi

if [[ -n $output ]]; then
    grim -o "$output" "$salida"
elif [[ -n $geom ]]; then
    geom=$(normalizar_geom "$geom")
    grim -g "$geom" "$salida"
else
    grim "$salida"
fi
rc=$?
if (( rc != 0 )); then
    printf '%s: grim fallo (codigo %d)\n' "$prog" "$rc" >&2
    exit "$rc"
fi

if [[ ! -s $salida ]]; then
    printf '%s: no se genero %s\n' "$prog" "$salida" >&2
    exit 1
fi
magic=$(od -An -tx1 -N8 -- "$salida" | tr -d ' \n')
if [[ $magic != 89504e470d0a1a0a ]]; then
    printf '%s: %s no es un PNG valido\n' "$prog" "$salida" >&2
    exit 1
fi

printf '%s: modo=%s archivo=%s\n' "$prog" "$modo" "$salida" >&2
