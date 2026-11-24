/* Consulta la geometría de la ventana enfocada mediante el protocolo IPC de
   dwl (zdwl_ipc_unstable_v2). Compilar con scripts/ipc_geometria.sh. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wayland-client.h>
#include "dwl_ipc_client.h"

static int encontrada = 0;

static void geometria(void *data, struct zdwl_ipc_output_v2 *salida,
                      int32_t x, int32_t y, int32_t ancho, int32_t alto) {
    (void)data; (void)salida;
    printf("%d,%d %dx%d\n", x, y, ancho, alto);
    encontrada = 1;
}

/* libwayland exige un manejador para cada evento del protocolo. */
static void visibilidad(void *d, struct zdwl_ipc_output_v2 *s) { (void)d; (void)s; }
static void activa(void *d, struct zdwl_ipc_output_v2 *s, uint32_t v) {
    (void)d; (void)s; (void)v;
}
static void etiqueta(void *d, struct zdwl_ipc_output_v2 *s, uint32_t tag,
                     uint32_t estado, uint32_t clientes, uint32_t enfocado) {
    (void)d; (void)s; (void)tag; (void)estado; (void)clientes; (void)enfocado;
}
static void diseno(void *d, struct zdwl_ipc_output_v2 *s, uint32_t v) {
    (void)d; (void)s; (void)v;
}
static void titulo(void *d, struct zdwl_ipc_output_v2 *s, const char *v) {
    (void)d; (void)s; (void)v;
}
static void appid(void *d, struct zdwl_ipc_output_v2 *s, const char *v) {
    (void)d; (void)s; (void)v;
}
static void simbolo(void *d, struct zdwl_ipc_output_v2 *s, const char *v) {
    (void)d; (void)s; (void)v;
}
static void cuadro(void *d, struct zdwl_ipc_output_v2 *s) { (void)d; (void)s; }
static void pantalla_completa(void *d, struct zdwl_ipc_output_v2 *s, uint32_t v) {
    (void)d; (void)s; (void)v;
}
static void flotante(void *d, struct zdwl_ipc_output_v2 *s, uint32_t v) {
    (void)d; (void)s; (void)v;
}

static const struct zdwl_ipc_output_v2_listener listener_salida = {
    .toggle_visibility = visibilidad,
    .active = activa,
    .tag = etiqueta,
    .layout = diseno,
    .title = titulo,
    .appid = appid,
    .layout_symbol = simbolo,
    .frame = cuadro,
    .fullscreen = pantalla_completa,
    .floating = flotante,
    .focused_geometry = geometria,
};

struct contexto {
    struct zdwl_ipc_manager_v2 **manager;
    struct wl_output **salida;
};

static void global(void *data, struct wl_registry *registro, uint32_t id,
                   const char *interfaz, uint32_t version) {
    struct contexto *ctx = data;
    if (strcmp(interfaz, "zdwl_ipc_manager_v2") == 0 && version >= 2) {
        *ctx->manager = wl_registry_bind(registro, id, &zdwl_ipc_manager_v2_interface, 2);
    } else if (strcmp(interfaz, "wl_output") == 0 && *ctx->salida == NULL) {
        *ctx->salida = wl_registry_bind(registro, id, &wl_output_interface, 1);
    }
}

static void global_remove(void *data, struct wl_registry *registro, uint32_t id) {
    (void)data; (void)registro; (void)id;
}

static const struct wl_registry_listener listener_registro = {
    .global = global,
    .global_remove = global_remove,
};

int main(void) {
    struct wl_display *display = wl_display_connect(NULL);
    if (!display) {
        fprintf(stderr, "ipc_geometria: no se pudo conectar a Wayland\n");
        return 1;
    }
    struct zdwl_ipc_manager_v2 *manager = NULL;
    struct wl_output *salida = NULL;
    struct contexto ctx = {&manager, &salida};
    struct wl_registry *registro = wl_display_get_registry(display);
    wl_registry_add_listener(registro, &listener_registro, &ctx);
    wl_display_roundtrip(display);
    if (!manager || !salida) {
        fprintf(stderr, "ipc_geometria: dwl no expone IPC v2 o no hay output\n");
        return 2;
    }
    struct zdwl_ipc_output_v2 *ipc_salida =
        zdwl_ipc_manager_v2_get_output(manager, salida);
    zdwl_ipc_output_v2_add_listener(ipc_salida, &listener_salida, NULL);
    wl_display_roundtrip(display);
    if (!encontrada) {
        fprintf(stderr, "ipc_geometria: no hay ventana enfocada\n");
        return 3;
    }
    return 0;
}
