/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 *
 * Bluetooth LE transport worker. Takes complete requests from the BLE link,
 * runs CTAP2 (MSG) or echoes PING, and sends keepalives while the command
 * waits for the OK button or does long work (PIN vault).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#include "ble_worker.h"

#if ZF_BLE_ENABLED && !defined(ZF_USB_ONLY) && !defined(ZF_NFC_ONLY)

#include <furi.h>
#include <string.h>

#include "ble_link.h"
#include "../zerofido_app_i.h"
#include "../zerofido_ctap.h"
#include "../zerofido_notify.h"
#include "../zerofido_trace.h"
#include "../zerofido_ui.h"

#define ZF_BLE_KEEPALIVE_MS 300U
#define ZF_BLE_POLL_MS 100U

typedef struct {
    volatile bool stopping;
    volatile bool processing;
    ZfTransportSessionId session_id;
    uint32_t last_keepalive;
} ZfBleWorkerState;

static ZfBleWorkerState g_zf_ble;

static void zf_ble_worker_keepalive(ZfBleLink *link, uint8_t status) {
    g_zf_ble.last_keepalive = furi_get_tick();
    (void)zf_ble_link_send(link, ZF_BLE_CMD_KEEPALIVE, &status, 1);
}

static void zf_ble_worker_serve(ZerofidoApp *app, ZfBleLink *link) {
    uint8_t error = zf_ble_link_take_error(link);
    uint8_t cmd = 0;
    size_t len = 0;
    size_t out = 0;

    if (error) {
        (void)zf_ble_link_send(link, ZF_BLE_CMD_ERROR, &error, 1);
    }
    if (!zf_ble_link_take_request(link, &cmd, app->transport_arena, ZF_MAX_MSG_SIZE, &len)) {
        return;
    }

    /*
     * The link is marked idle before the reply goes out: a client may send the
     * next request as soon as it sees the reply (Windows does), and frames that
     * arrive while busy are dropped. New requests land in the link's own buffer,
     * so the reply still in the arena is safe.
     */
    if (cmd == ZF_BLE_CMD_PING) {
        zf_ble_link_end_request(link);
        (void)zf_ble_link_send(link, ZF_BLE_CMD_PING, app->transport_arena, len);
    } else if (len == 0U) {
        zf_ble_link_end_request(link);
        error = ZF_BLE_ERR_INVALID_LEN;
        (void)zf_ble_link_send(link, ZF_BLE_CMD_ERROR, &error, 1);
    } else {
        uint32_t started = furi_get_tick();
        uint32_t elapsed = 0;
        uint8_t ctap_cmd = app->transport_arena[0];

        g_zf_ble.session_id++;
        g_zf_ble.processing = true;
        g_zf_ble.last_keepalive = started;
        /* Request and response share the arena, as on USB. */
        out = zerofido_handle_ctap2(app, g_zf_ble.session_id, app->transport_arena, len,
                                    app->transport_arena, ZF_MAX_MSG_SIZE);
        g_zf_ble.processing = false;
        if (zf_ble_link_cancel_requested(link)) {
            app->transport_arena[0] = ZF_CTAP_ERR_KEEPALIVE_CANCEL;
            out = 1;
        }
        elapsed = furi_get_tick() - started;
        zf_ble_link_end_request(link);
        if (out == 0U) {
            error = ZF_BLE_ERR_OTHER;
            (void)zf_ble_link_send(link, ZF_BLE_CMD_ERROR, &error, 1);
        } else {
            (void)zf_ble_link_send(link, ZF_BLE_CMD_MSG, app->transport_arena, out);
        }
        ZF_TRACE(app->storage, "BLE cmd=%02X len=%u status=%02X out=%u ms=%lu", ctap_cmd,
                 (unsigned)len, out ? app->transport_arena[0] : 0xFFU, (unsigned)out,
                 (unsigned long)elapsed);
        zerofido_ui_refresh_status(app);
    }
    zf_app_transport_arena_wipe(app);
}

int32_t zf_transport_ble_worker(void *context) {
    ZerofidoApp *app = context;
    ZfBleLink *link = app ? app->ble_link : NULL;

    memset(&g_zf_ble, 0, sizeof(g_zf_ble));
    if (!link) {
        return 0;
    }
    if (!zf_app_transport_arena_acquire(app)) {
        zerofido_ui_set_transport_connected(app, false);
        return 0;
    }
    zf_ble_link_attach_worker(link, furi_thread_get_current_id());

    while (!g_zf_ble.stopping) {
        uint32_t flags = furi_thread_flags_wait(ZF_BLE_EVT_STOP | ZF_BLE_EVT_REQUEST,
                                                FuriFlagWaitAny, ZF_BLE_POLL_MS);

        if ((flags & FuriFlagError) == 0U && (flags & ZF_BLE_EVT_STOP)) {
            break;
        }
        zf_ble_link_tick(link);
        zerofido_ui_set_transport_connected(app, zf_ble_link_is_connected(link));
        zf_ble_worker_serve(app, link);
    }

    zf_ble_link_attach_worker(link, NULL);
    zerofido_ui_set_transport_connected(app, false);
    zf_app_transport_arena_release(app);
    zerofido_notify_reset(app);
    return 0;
}

void zf_transport_ble_stop(ZerofidoApp *app) {
    FuriThreadId id = NULL;

    if (!app) {
        return;
    }
    g_zf_ble.stopping = true;
    if (app->approval.done) {
        furi_semaphore_release(app->approval.done);
    }
    if (app->worker_thread) {
        id = furi_thread_get_id(app->worker_thread);
    }
    if (id) {
        furi_thread_flags_set(id, ZF_BLE_EVT_STOP);
    }
}

void zf_transport_ble_send_dispatch_result(ZerofidoApp *app,
                                           const ZfProtocolDispatchRequest *request,
                                           const ZfProtocolDispatchResult *result) {
    uint8_t error = ZF_BLE_ERR_OTHER;

    UNUSED(request);
    if (!app || !app->ble_link || !result) {
        return;
    }
    if (result->send_transport_error || result->response_len == 0U) {
        (void)zf_ble_link_send(app->ble_link, ZF_BLE_CMD_ERROR, &error, 1);
    } else {
        (void)zf_ble_link_send(app->ble_link, ZF_BLE_CMD_MSG, result->response,
                               result->response_len);
    }
}

/* Waits for OK/deny on the Flipper, telling the PC "touch needed" meanwhile. */
bool zf_transport_ble_wait_for_interaction(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id,
                                           bool *approved) {
    ZfBleLink *link = app ? app->ble_link : NULL;

    if (!link || !approved || current_session_id != g_zf_ble.session_id) {
        return false;
    }
    zf_ble_worker_keepalive(link, ZF_BLE_KEEPALIVE_UP_NEEDED);
    while (true) {
        if (furi_semaphore_acquire(app->approval.done, ZF_BLE_POLL_MS) == FuriStatusOk) {
            break;
        }
        if (g_zf_ble.stopping || zf_ble_link_cancel_requested(link)) {
            return false;
        }
        if ((uint32_t)(furi_get_tick() - g_zf_ble.last_keepalive) >= ZF_BLE_KEEPALIVE_MS) {
            zf_ble_worker_keepalive(link, ZF_BLE_KEEPALIVE_UP_NEEDED);
        }
    }
    if (g_zf_ble.stopping) {
        return false;
    }
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    *approved = (app->approval.state == ZfApprovalApproved);
    furi_mutex_release(app->ui_mutex);
    return true;
}

void zf_transport_ble_notify_interaction_changed(ZerofidoApp *app) {
    UNUSED(app);
}

uint8_t zf_transport_ble_poll_cbor_control(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id) {
    ZfBleLink *link = app ? app->ble_link : NULL;

    if (!link || !g_zf_ble.processing || current_session_id != g_zf_ble.session_id) {
        return ZF_CTAP_SUCCESS;
    }
    if (g_zf_ble.stopping || zf_ble_link_cancel_requested(link)) {
        return ZF_CTAP_ERR_KEEPALIVE_CANCEL;
    }
    return ZF_CTAP_SUCCESS;
}

/* Long work inside a command (PIN vault stretch): "still processing". */
void zf_transport_ble_processing_keepalive(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id) {
    ZfBleLink *link = app ? app->ble_link : NULL;

    if (!link || !g_zf_ble.processing || current_session_id != g_zf_ble.session_id ||
        (uint32_t)(furi_get_tick() - g_zf_ble.last_keepalive) < ZF_BLE_KEEPALIVE_MS) {
        return;
    }
    zf_ble_worker_keepalive(link, ZF_BLE_KEEPALIVE_PROCESSING);
}

#endif
