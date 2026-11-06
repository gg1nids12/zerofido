/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 * Bluetooth LE transport adapter (CTAP over BLE), see ble_link.h.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "dispatch.h"

typedef struct ZerofidoApp ZerofidoApp;

int32_t zf_transport_ble_worker(void *context);
void zf_transport_ble_stop(ZerofidoApp *app);
void zf_transport_ble_send_dispatch_result(ZerofidoApp *app,
                                           const ZfProtocolDispatchRequest *request,
                                           const ZfProtocolDispatchResult *result);
bool zf_transport_ble_wait_for_interaction(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id,
                                           bool *approved);
void zf_transport_ble_notify_interaction_changed(ZerofidoApp *app);
uint8_t zf_transport_ble_poll_cbor_control(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id);
void zf_transport_ble_processing_keepalive(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id);
