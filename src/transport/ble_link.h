/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 *
 * Bluetooth LE FIDO link (CTAP 2.x, section "Bluetooth Smart / Bluetooth Low
 * Energy Technology"). Owns the BLE profile: FIDO GATT service (0xFFFD) plus a
 * small Device Information service, its own bond storage in the app data
 * folder, and request reassembly. Requests are assembled on the BLE event
 * thread, so a request can arrive while another transport is active; the BLE
 * transport worker then takes it over.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <furi.h>

#define ZF_BLE_CMD_PING 0x81U
#define ZF_BLE_CMD_KEEPALIVE 0x82U
#define ZF_BLE_CMD_MSG 0x83U
#define ZF_BLE_CMD_CANCEL 0xBEU
#define ZF_BLE_CMD_ERROR 0xBFU

#define ZF_BLE_ERR_INVALID_CMD 0x01U
#define ZF_BLE_ERR_INVALID_LEN 0x03U
#define ZF_BLE_ERR_INVALID_SEQ 0x04U
#define ZF_BLE_ERR_REQ_TIMEOUT 0x05U
#define ZF_BLE_ERR_OTHER 0x7FU

#define ZF_BLE_KEEPALIVE_PROCESSING 0x01U
#define ZF_BLE_KEEPALIVE_UP_NEEDED 0x02U

/* Worker thread flags raised by the link (same bits as the USB worker uses). */
#define ZF_BLE_EVT_STOP (1U << 0)
#define ZF_BLE_EVT_REQUEST (1U << 3)

typedef struct ZfBleLink ZfBleLink;

/* Switches the Flipper Bluetooth to the FIDO profile. NULL if it failed. */
ZfBleLink *zf_ble_link_start(void);
/* Restores the default Flipper Bluetooth profile and frees the link. */
void zf_ble_link_stop(ZfBleLink *link);

/* Worker side. The link raises ZF_BLE_EVT_REQUEST on the attached thread. */
void zf_ble_link_attach_worker(ZfBleLink *link, FuriThreadId worker);
bool zf_ble_link_take_request(ZfBleLink *link, uint8_t *cmd, uint8_t *out, size_t out_capacity,
                              size_t *out_len);
void zf_ble_link_end_request(ZfBleLink *link);
uint8_t zf_ble_link_take_error(ZfBleLink *link);
bool zf_ble_link_cancel_requested(ZfBleLink *link);
bool zf_ble_link_send(ZfBleLink *link, uint8_t cmd, const uint8_t *data, size_t len);
void zf_ble_link_tick(ZfBleLink *link);

/* Codes only (no addresses or data), for the service trace. */
typedef struct {
    uint32_t generation; /* changes whenever a field below changes */
    uint16_t connects;
    uint16_t mtu;
    uint8_t disconnect_reason;
    uint8_t pairing_status; /* 0xFF: none yet */
    uint8_t pairing_reason;
    uint8_t encrypted;
    uint8_t revision;
    uint8_t notify_on;
    uint16_t writes;
} ZfBleLinkDiag;

void zf_ble_link_get_diag(ZfBleLink *link, ZfBleLinkDiag *out);

/* State for the UI and the automatic transport choice. */
bool zf_ble_link_is_connected(ZfBleLink *link);
bool zf_ble_link_has_work(ZfBleLink *link);
uint32_t zf_ble_link_last_activity(ZfBleLink *link);
