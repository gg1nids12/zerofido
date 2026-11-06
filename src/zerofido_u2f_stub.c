/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 *
 * Builds with ZEROFIDO_U2F=0 drop the legacy U2F (CTAP1) module to fit the
 * Momentum heap (one contiguous allocation for the app code). FIDO2 still
 * covers second-factor use. These stubs keep the adapter API: U2F requests
 * get "instruction not supported" and getInfo does not advertise U2F_V2.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#include "u2f/adapter.h"
#include "u2f/apdu.h"
#include "u2f/persistence.h"

#if defined(ZF_U2F_DISABLED) && ZF_U2F_DISABLED

#include <furi.h>

bool zf_u2f_adapter_init(ZerofidoApp *app) {
    UNUSED(app);
    return true;
}

bool zf_u2f_adapter_ensure_init(ZerofidoApp *app) {
    UNUSED(app);
    return false;
}

bool zf_u2f_adapter_ensure_attestation_assets(void) {
    return true;
}

void zf_u2f_adapter_deinit(ZerofidoApp *app) {
    UNUSED(app);
}

bool zf_u2f_adapter_is_available(const ZerofidoApp *app) {
    UNUSED(app);
    return false;
}

void zf_u2f_adapter_set_connected(ZerofidoApp *app, bool connected) {
    UNUSED(app);
    UNUSED(connected);
}

size_t zf_u2f_adapter_handle_msg(ZerofidoApp *app, ZfTransportSessionId session_id,
                                 const uint8_t *request, size_t request_len, uint8_t *response,
                                 size_t response_capacity) {
    UNUSED(app);
    UNUSED(session_id);
    UNUSED(request);
    UNUSED(request_len);
    if (!response || response_capacity < 2U) {
        return 0;
    }
    response[0] = 0x6D; /* SW_INS_NOT_SUPPORTED */
    response[1] = 0x00;
    return 2;
}

void zf_u2f_adapter_wink(ZerofidoApp *app) {
    UNUSED(app);
}

/* Every U2F APDU is answered with "instruction not supported". */
uint16_t u2f_validate_request_into_response(const uint8_t *request, uint16_t request_len,
                                            uint8_t *response, uint16_t response_capacity) {
    UNUSED(request);
    UNUSED(request_len);
    if (!response || response_capacity < 2U) {
        return 0;
    }
    response[0] = 0x6D;
    response[1] = 0x00;
    return 2;
}

bool u2f_request_needs_user_presence(const uint8_t *buf, uint16_t request_len,
                                     const char **operation) {
    UNUSED(buf);
    UNUSED(request_len);
    if (operation) {
        *operation = NULL;
    }
    return false;
}

/* No U2F data of our own; the app data wipe on reset covers the folder. */
bool u2f_data_wipe(Storage *storage) {
    UNUSED(storage);
    return true;
}

#endif
