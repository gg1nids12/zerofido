/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 * See ble_link.h.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#include "ble_link.h"

#include <ble/core/ble_defs.h>
#include <bt/bt_service/bt.h>
#include <furi_ble/event_dispatcher.h>
#include <furi_ble/gatt.h>
#include <furi_ble/profile_interface.h>
#include <furi_hal_bt.h>
#include <furi_hal_version.h>
#include <gap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../zerofido_types.h"

#define ZF_BLE_FRAG_MIN 20U
#define ZF_BLE_FRAG_MAX 240U /* fits one HCI event / command with headers */
#define ZF_BLE_RX_TIMEOUT_MS 3000U
#define ZF_BLE_STALE_MS 5000U /* a complete request nobody took is dropped */
#define ZF_BLE_KEYS_PATH ZF_APP_DATA_DIR "/.bt_fido.keys"
#define ZF_BLE_REVISION_FIDO2 0x20U

/* HCI framing as delivered to service handlers (ST WPAN, not in the SDK). */
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t evt;
    uint8_t plen;
    uint8_t data[];
} ZfHciEvent;

typedef struct __attribute__((packed)) {
    uint16_t ecode;
    uint8_t data[];
} ZfHciVendorEvent;

#define ZF_HCI_DISCONNECTION_COMPLETE 0x05U
#define ZF_HCI_ENCRYPTION_CHANGE 0x08U
#define ZF_ACI_GAP_PAIRING_COMPLETE 0x0401U
#define ZF_HCI_LE_META 0x3EU
#define ZF_HCI_LE_CONNECTION_COMPLETE 0x01U
#define ZF_HCI_LE_ENHANCED_CONNECTION_COMPLETE 0x0AU
#define ZF_HCI_VENDOR 0xFFU
#define ZF_ACI_GATT_ATTRIBUTE_MODIFIED 0x0C01U
#define ZF_ACI_ATT_EXCHANGE_MTU_RESP 0x0C03U

typedef enum {
    ZfBleCharControlPoint = 0,
    ZfBleCharStatus,
    ZfBleCharControlPointLength,
    ZfBleCharRevisionBitfield,
    ZfBleCharCount,
} ZfBleCharId;

typedef enum {
    ZfBleDisManufacturer = 0,
    ZfBleDisModel,
    ZfBleDisFirmware,
    ZfBleDisCount,
} ZfBleDisCharId;

typedef struct {
    const uint8_t *data;
    uint16_t len;
} ZfBleFrame;

struct ZfBleLink {
    FuriMutex *mutex;
    Bt *bt;
    FuriHalBleProfileBase *profile;

    /* GATT, filled by the profile start callback on the Bluetooth thread. */
    bool gatt_ready;
    uint16_t svc_handle;
    BleGattCharacteristicInstance chars[ZfBleCharCount];
    uint16_t dis_handle;
    BleGattCharacteristicInstance dis_chars[ZfBleDisCount];
    GapSvcEventHandler *event_handler;

    /* Link state. */
    bool connected;
    uint16_t frag_size;
    uint32_t activity_tick;

    /* Request reassembly (Bluetooth thread) and hand-off (worker). */
    uint8_t *rx_buf;
    uint16_t rx_total;
    uint16_t rx_len;
    uint8_t rx_cmd;
    uint8_t rx_seq;
    bool rx_active;
    uint32_t rx_tick;
    bool msg_ready;
    bool busy;
    bool cancel;
    uint8_t pending_error;
    FuriThreadId worker;

    ZfBleLinkDiag diag;

    uint8_t tx_frame[ZF_BLE_FRAG_MAX];
};

typedef struct {
    FuriHalBleProfileBase base;
    ZfBleLink *link;
} ZfBleProfile;
_Static_assert(offsetof(ZfBleProfile, base) == 0, "profile base must come first");

/* FIDO UUIDs, little-endian: F1D0FFFx-DEAA-ECEE-B42F-C9BA7ED623BB. */
#define ZF_BLE_FIDO_UUID(x)                                                                        \
    {0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4, 0xEE, 0xEC, 0xAA, 0xDE, (x), 0xFF, 0xD0, 0xF1}

static bool zf_ble_status_data(const void *context, const uint8_t **data, uint16_t *data_len) {
    const ZfBleFrame *frame = context;

    if (!data) {
        *data_len = ZF_BLE_FRAG_MAX; /* attribute size at creation */
        return false;
    }
    *data = frame ? frame->data : NULL;
    *data_len = frame ? frame->len : 0U;
    return false;
}

static const BleGattCharacteristicParams zf_ble_chars[ZfBleCharCount] = {
    [ZfBleCharControlPoint] =
        {
            .name = "fidoControlPoint",
            .data_prop_type = FlipperGattCharacteristicDataFixed,
            .data.fixed.length = ZF_BLE_FRAG_MAX,
            .uuid.Char_UUID_128 = ZF_BLE_FIDO_UUID(0xF1),
            .uuid_type = UUID_TYPE_128,
            .char_properties = CHAR_PROP_WRITE,
            .security_permissions = ATTR_PERMISSION_AUTHEN_WRITE,
            .gatt_evt_mask = GATT_NOTIFY_ATTRIBUTE_WRITE,
            .is_variable = CHAR_VALUE_LEN_VARIABLE,
        },
    [ZfBleCharStatus] =
        {
            .name = "fidoStatus",
            .data_prop_type = FlipperGattCharacteristicDataCallback,
            .data.callback.fn = zf_ble_status_data,
            .data.callback.context = NULL,
            .uuid.Char_UUID_128 = ZF_BLE_FIDO_UUID(0xF2),
            .uuid_type = UUID_TYPE_128,
            .char_properties = CHAR_PROP_NOTIFY,
            .security_permissions = ATTR_PERMISSION_NONE,
            .gatt_evt_mask = GATT_DONT_NOTIFY_EVENTS,
            .is_variable = CHAR_VALUE_LEN_VARIABLE,
        },
    [ZfBleCharControlPointLength] =
        {
            .name = "fidoControlPointLength",
            .data_prop_type = FlipperGattCharacteristicDataFixed,
            .data.fixed.length = 2,
            .uuid.Char_UUID_128 = ZF_BLE_FIDO_UUID(0xF3),
            .uuid_type = UUID_TYPE_128,
            .char_properties = CHAR_PROP_READ,
            .security_permissions = ATTR_PERMISSION_AUTHEN_READ,
            .gatt_evt_mask = GATT_DONT_NOTIFY_EVENTS,
            .is_variable = CHAR_VALUE_LEN_CONSTANT,
        },
    [ZfBleCharRevisionBitfield] =
        {
            .name = "fidoServiceRevisionBitfield",
            .data_prop_type = FlipperGattCharacteristicDataFixed,
            .data.fixed.length = 1,
            .uuid.Char_UUID_128 = ZF_BLE_FIDO_UUID(0xF4),
            .uuid_type = UUID_TYPE_128,
            .char_properties = CHAR_PROP_READ | CHAR_PROP_WRITE,
            .security_permissions = ATTR_PERMISSION_AUTHEN_READ | ATTR_PERMISSION_AUTHEN_WRITE,
            .gatt_evt_mask = GATT_NOTIFY_ATTRIBUTE_WRITE,
            .is_variable = CHAR_VALUE_LEN_CONSTANT,
        },
};

static const char zf_ble_dis_manufacturer[] = "ZeroFIDO dev";
static const char zf_ble_dis_model[] = "Flipper Zero FIDO2";
static const char zf_ble_dis_firmware[] = "tpm-dev";

#define ZF_BLE_DIS_CHAR(uuid16, text)                                                              \
    {                                                                                              \
        .name = #uuid16, .data_prop_type = FlipperGattCharacteristicDataFixed,                     \
        .data.fixed.ptr = (const uint8_t *)(text), .data.fixed.length = sizeof(text) - 1U,         \
        .uuid.Char_UUID_16 = (uuid16), .uuid_type = UUID_TYPE_16,                                  \
        .char_properties = CHAR_PROP_READ, .security_permissions = ATTR_PERMISSION_NONE,           \
        .gatt_evt_mask = GATT_DONT_NOTIFY_EVENTS, .is_variable = CHAR_VALUE_LEN_CONSTANT,          \
    }

static const BleGattCharacteristicParams zf_ble_dis_chars[ZfBleDisCount] = {
    [ZfBleDisManufacturer] = ZF_BLE_DIS_CHAR(0x2A29, zf_ble_dis_manufacturer),
    [ZfBleDisModel] = ZF_BLE_DIS_CHAR(0x2A24, zf_ble_dis_model),
    [ZfBleDisFirmware] = ZF_BLE_DIS_CHAR(0x2A26, zf_ble_dis_firmware),
};

/* ---- helpers (caller holds the mutex unless noted) ---------------------------------------- */

static void zf_ble_signal_locked(ZfBleLink *link) {
    if (link->worker) {
        furi_thread_flags_set(link->worker, ZF_BLE_EVT_REQUEST);
    }
}

static void zf_ble_rx_drop_locked(ZfBleLink *link) {
    if (link->rx_buf) {
        memset(link->rx_buf, 0, link->rx_total);
        free(link->rx_buf);
        link->rx_buf = NULL;
    }
    link->rx_total = 0;
    link->rx_len = 0;
    link->rx_active = false;
    link->msg_ready = false;
}

static void zf_ble_rx_fail_locked(ZfBleLink *link, uint8_t error) {
    zf_ble_rx_drop_locked(link);
    link->rx_tick = furi_get_tick();
    link->pending_error = error;
    zf_ble_signal_locked(link);
}

static void zf_ble_rx_append_locked(ZfBleLink *link, const uint8_t *data, size_t len) {
    size_t room = (size_t)link->rx_total - link->rx_len;

    if (len > room) {
        len = room;
    }
    if (len > 0U) {
        memcpy(link->rx_buf + link->rx_len, data, len);
        link->rx_len += (uint16_t)len;
    }
    link->rx_tick = furi_get_tick();
    if (link->rx_len == link->rx_total) {
        link->rx_active = false;
        link->msg_ready = true;
        zf_ble_signal_locked(link);
    }
}

/* One write to fidoControlPoint: an initial frame or a continuation. */
static void zf_ble_on_control_point(ZfBleLink *link, const uint8_t *data, uint16_t len) {
    furi_mutex_acquire(link->mutex, FuriWaitForever);
    link->activity_tick = furi_get_tick();
    if (len == 0U) {
        furi_mutex_release(link->mutex);
        return;
    }
    if (data[0] & 0x80U) {
        uint8_t cmd = data[0];
        uint16_t total = 0;

        if (cmd == ZF_BLE_CMD_CANCEL) {
            if (link->busy) {
                link->cancel = true;
                zf_ble_signal_locked(link);
            } else {
                zf_ble_rx_drop_locked(link);
            }
        } else if (link->busy) {
            /* One request at a time; a well-behaved client waits. */
        } else if (len < 3U) {
            zf_ble_rx_fail_locked(link, ZF_BLE_ERR_INVALID_LEN);
        } else if (cmd != ZF_BLE_CMD_PING && cmd != ZF_BLE_CMD_MSG) {
            zf_ble_rx_fail_locked(link, ZF_BLE_ERR_INVALID_CMD);
        } else {
            total = (uint16_t)(((uint16_t)data[1] << 8) | data[2]);
            zf_ble_rx_drop_locked(link);
            if (total > ZF_MAX_MSG_SIZE) {
                zf_ble_rx_fail_locked(link, ZF_BLE_ERR_INVALID_LEN);
            } else {
                link->rx_buf = malloc(total ? total : 1U);
                link->rx_total = total;
                link->rx_cmd = cmd;
                link->rx_seq = 0;
                link->rx_active = true;
                zf_ble_rx_append_locked(link, data + 3, len - 3U);
            }
        }
    } else if (link->rx_active && !link->busy) {
        if (data[0] != link->rx_seq) {
            zf_ble_rx_fail_locked(link, ZF_BLE_ERR_INVALID_SEQ);
        } else {
            link->rx_seq = (uint8_t)((link->rx_seq + 1U) & 0x7FU);
            zf_ble_rx_append_locked(link, data + 1, len - 1U);
        }
    }
    furi_mutex_release(link->mutex);
}

static void zf_ble_set_control_point_length(ZfBleLink *link, uint16_t frag) {
    uint8_t value[2] = {(uint8_t)(frag >> 8), (uint8_t)frag};

    ble_gatt_characteristic_update(link->svc_handle, &link->chars[ZfBleCharControlPointLength],
                                   value);
}

/* Bluetooth event thread. Only our attribute writes are acknowledged. */
static BleEventAckStatus zf_ble_event_handler(void *event, void *context) {
    ZfBleLink *link = context;
    const ZfHciEvent *hci = event;

    if (hci->evt == ZF_HCI_ENCRYPTION_CHANGE) {
        furi_mutex_acquire(link->mutex, FuriWaitForever);
        link->diag.encrypted = hci->data[0] == 0x00U ? hci->data[3] : (uint8_t)(0x80U | hci->data[0]);
        link->diag.generation++;
        furi_mutex_release(link->mutex);
        return BleEventNotAck;
    }
    if (hci->evt == ZF_HCI_DISCONNECTION_COMPLETE) {
        furi_mutex_acquire(link->mutex, FuriWaitForever);
        link->diag.disconnect_reason = hci->data[3];
        link->diag.encrypted = 0;
        link->diag.generation++;
        link->connected = false;
        link->frag_size = ZF_BLE_FRAG_MIN;
        zf_ble_rx_drop_locked(link);
        if (link->busy) {
            link->cancel = true;
        }
        zf_ble_signal_locked(link);
        furi_mutex_release(link->mutex);
        return BleEventNotAck;
    }
    if (hci->evt == ZF_HCI_LE_META &&
        (hci->data[0] == ZF_HCI_LE_CONNECTION_COMPLETE ||
         hci->data[0] == ZF_HCI_LE_ENHANCED_CONNECTION_COMPLETE) &&
        hci->data[1] == 0x00U /* status: success */) {
        furi_mutex_acquire(link->mutex, FuriWaitForever);
        link->diag.connects++;
        link->diag.mtu = 23;
        link->diag.generation++;
        link->connected = true;
        link->frag_size = ZF_BLE_FRAG_MIN;
        link->activity_tick = furi_get_tick();
        furi_mutex_release(link->mutex);
        return BleEventNotAck;
    }
    if (hci->evt != ZF_HCI_VENDOR) {
        return BleEventNotAck;
    }

    const ZfHciVendorEvent *vendor = (const ZfHciVendorEvent *)hci->data;
    if (vendor->ecode == ZF_ACI_GAP_PAIRING_COMPLETE) {
        furi_mutex_acquire(link->mutex, FuriWaitForever);
        link->diag.pairing_status = vendor->data[2];
        link->diag.pairing_reason = vendor->data[3];
        link->diag.generation++;
        furi_mutex_release(link->mutex);
        return BleEventNotAck; /* GAP reports the connection */
    }
    if (vendor->ecode == ZF_ACI_ATT_EXCHANGE_MTU_RESP) {
        const aci_att_exchange_mtu_resp_event_rp0 *mtu = (const void *)vendor->data;
        uint16_t frag = mtu->Server_RX_MTU > 3U ? (uint16_t)(mtu->Server_RX_MTU - 3U) : 0U;

        if (frag < ZF_BLE_FRAG_MIN) frag = ZF_BLE_FRAG_MIN;
        if (frag > ZF_BLE_FRAG_MAX) frag = ZF_BLE_FRAG_MAX;
        furi_mutex_acquire(link->mutex, FuriWaitForever);
        link->frag_size = frag;
        link->diag.mtu = mtu->Server_RX_MTU;
        link->diag.generation++;
        furi_mutex_release(link->mutex);
        zf_ble_set_control_point_length(link, frag);
        return BleEventNotAck; /* GAP also tracks the MTU */
    }
    if (vendor->ecode != ZF_ACI_GATT_ATTRIBUTE_MODIFIED) {
        return BleEventNotAck;
    }

    const aci_gatt_attribute_modified_event_rp0 *mod = (const void *)vendor->data;
    if (mod->Attr_Handle == link->chars[ZfBleCharControlPoint].handle + 1U) {
        furi_mutex_acquire(link->mutex, FuriWaitForever);
        link->diag.writes++;
        if (link->diag.writes == 1U) {
            link->diag.generation++; /* first request only; avoid trace spam */
        }
        furi_mutex_release(link->mutex);
        zf_ble_on_control_point(link, mod->Attr_Data, mod->Attr_Data_Length);
        return BleEventAckFlowEnable;
    }
    if (mod->Attr_Handle == link->chars[ZfBleCharStatus].handle + 2U ||
        mod->Attr_Handle == link->chars[ZfBleCharRevisionBitfield].handle + 1U) {
        /* Notifications switched on, or FIDO2 selected by the client. */
        furi_mutex_acquire(link->mutex, FuriWaitForever);
        link->activity_tick = furi_get_tick();
        if (mod->Attr_Data_Length > 0U) {
            if (mod->Attr_Handle == link->chars[ZfBleCharStatus].handle + 2U) {
                link->diag.notify_on = mod->Attr_Data[0];
            } else {
                link->diag.revision = mod->Attr_Data[0];
            }
            link->diag.generation++;
        }
        furi_mutex_release(link->mutex);
        return BleEventAckFlowEnable;
    }
    return BleEventNotAck;
}

/* ---- profile (runs on the Bluetooth service thread) --------------------------------------- */

static const FuriHalBleProfileTemplate zf_ble_profile_template;

static FuriHalBleProfileBase *zf_ble_profile_start(FuriHalBleProfileParams params) {
    ZfBleLink *link = params;
    ZfBleProfile *profile = malloc(sizeof(ZfBleProfile));
    const Service_UUID_t fido_uuid = {.Service_UUID_16 = 0xFFFD};
    const Service_UUID_t dis_uuid = {.Service_UUID_16 = 0x180A};
    uint8_t revision = ZF_BLE_REVISION_FIDO2;

    profile->base.config = &zf_ble_profile_template;
    profile->link = link;
    link->gatt_ready = false;

    link->event_handler = ble_event_dispatcher_register_svc_handler(zf_ble_event_handler, link);
    if (ble_gatt_service_add(UUID_TYPE_16, &dis_uuid, PRIMARY_SERVICE, 1U + 2U * ZfBleDisCount,
                             &link->dis_handle)) {
        for (size_t i = 0; i < ZfBleDisCount; ++i) {
            ble_gatt_characteristic_init(link->dis_handle, &zf_ble_dis_chars[i],
                                         &link->dis_chars[i]);
            ble_gatt_characteristic_update(link->dis_handle, &link->dis_chars[i], NULL);
        }
    } else {
        link->dis_handle = 0;
    }
    if (ble_gatt_service_add(UUID_TYPE_16, &fido_uuid, PRIMARY_SERVICE, 12,
                             &link->svc_handle)) {
        for (size_t i = 0; i < ZfBleCharCount; ++i) {
            ble_gatt_characteristic_init(link->svc_handle, &zf_ble_chars[i], &link->chars[i]);
        }
        zf_ble_set_control_point_length(link, ZF_BLE_FRAG_MIN);
        ble_gatt_characteristic_update(link->svc_handle,
                                       &link->chars[ZfBleCharRevisionBitfield], &revision);
        link->gatt_ready = true;
    }
    return &profile->base;
}

static void zf_ble_profile_stop(FuriHalBleProfileBase *base) {
    ZfBleProfile *profile = (ZfBleProfile *)base;
    ZfBleLink *link = profile->link;

    if (link->event_handler) {
        ble_event_dispatcher_unregister_svc_handler(link->event_handler);
        link->event_handler = NULL;
    }
    if (link->gatt_ready) {
        for (size_t i = 0; i < ZfBleCharCount; ++i) {
            ble_gatt_characteristic_delete(link->svc_handle, &link->chars[i]);
        }
        ble_gatt_service_delete(link->svc_handle);
        link->gatt_ready = false;
    }
    if (link->dis_handle) {
        for (size_t i = 0; i < ZfBleDisCount; ++i) {
            ble_gatt_characteristic_delete(link->dis_handle, &link->dis_chars[i]);
        }
        ble_gatt_service_delete(link->dis_handle);
        link->dis_handle = 0;
    }
    free(profile);
}

static void zf_ble_profile_gap_config(GapConfig *config, FuriHalBleProfileParams params) {
    UNUSED(params);
    memset(config, 0, sizeof(*config));
    config->adv_service.UUID_Type = UUID_TYPE_16;
    config->adv_service.Service_UUID_16 = 0xFFFD; /* FIDO */
    config->appearance_char = 0x0000;
    config->bonding_mode = true;
    /* Numeric comparison: the code shows on the PC and on the Flipper (OK). */
    config->pairing_method = GapPairingPinCodeVerifyYesNo;
    config->conn_param.conn_int_min = 0x06; /* 7.5 ms */
    config->conn_param.conn_int_max = 0x24; /* 45 ms */
    memcpy(config->mac_address, furi_hal_version_get_ble_mac(), sizeof(config->mac_address));
    /* Own address, so Windows keeps this pairing apart from the Flipper app's. */
    config->mac_address[2] ^= 0xF1U;
    snprintf(config->adv_name, sizeof(config->adv_name), "%cFIDO %s",
             furi_hal_version_get_ble_local_device_name_ptr()[0], furi_hal_version_get_name_ptr());
}

static const FuriHalBleProfileTemplate zf_ble_profile_template = {
    .start = zf_ble_profile_start,
    .stop = zf_ble_profile_stop,
    .get_gap_config = zf_ble_profile_gap_config,
};

/* ---- public ------------------------------------------------------------------------------- */

ZfBleLink *zf_ble_link_start(void) {
    ZfBleLink *link = malloc(sizeof(ZfBleLink));

    memset(link, 0, sizeof(*link));
    link->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    link->frag_size = ZF_BLE_FRAG_MIN;
    link->diag.pairing_status = 0xFFU;
    link->bt = furi_record_open(RECORD_BT);

    bt_disconnect(link->bt);
    furi_delay_ms(200); /* let the radio core store bonds */
    bt_keys_storage_set_storage_path(link->bt, ZF_BLE_KEYS_PATH);
    link->profile = bt_profile_start(link->bt, &zf_ble_profile_template, link);
    if (!link->profile || !link->gatt_ready) {
        bt_keys_storage_set_default_path(link->bt);
        (void)bt_profile_restore_default(link->bt);
        furi_record_close(RECORD_BT);
        furi_mutex_free(link->mutex);
        free(link);
        return NULL;
    }
    furi_hal_bt_start_advertising();
    return link;
}

void zf_ble_link_stop(ZfBleLink *link) {
    if (!link) {
        return;
    }
    bt_disconnect(link->bt);
    furi_delay_ms(200);
    bt_keys_storage_set_default_path(link->bt);
    (void)bt_profile_restore_default(link->bt); /* runs zf_ble_profile_stop */
    furi_record_close(RECORD_BT);
    furi_mutex_acquire(link->mutex, FuriWaitForever);
    zf_ble_rx_drop_locked(link);
    furi_mutex_release(link->mutex);
    furi_mutex_free(link->mutex);
    memset(link, 0, sizeof(*link));
    free(link);
}

void zf_ble_link_attach_worker(ZfBleLink *link, FuriThreadId worker) {
    furi_mutex_acquire(link->mutex, FuriWaitForever);
    link->worker = worker;
    if (worker && (link->msg_ready || link->pending_error)) {
        zf_ble_signal_locked(link);
    }
    furi_mutex_release(link->mutex);
}

bool zf_ble_link_take_request(ZfBleLink *link, uint8_t *cmd, uint8_t *out, size_t out_capacity,
                              size_t *out_len) {
    bool ok = false;

    furi_mutex_acquire(link->mutex, FuriWaitForever);
    if (link->msg_ready && !link->busy && link->rx_total <= out_capacity) {
        if (link->rx_total > 0U) {
            memcpy(out, link->rx_buf, link->rx_total);
        }
        *out_len = link->rx_total;
        *cmd = link->rx_cmd;
        link->busy = true;
        link->cancel = false;
        ok = true;
    }
    if (link->msg_ready) {
        zf_ble_rx_drop_locked(link);
    }
    furi_mutex_release(link->mutex);
    return ok;
}

void zf_ble_link_end_request(ZfBleLink *link) {
    furi_mutex_acquire(link->mutex, FuriWaitForever);
    link->busy = false;
    link->cancel = false;
    link->activity_tick = furi_get_tick();
    furi_mutex_release(link->mutex);
}

uint8_t zf_ble_link_take_error(ZfBleLink *link) {
    uint8_t error = 0;

    furi_mutex_acquire(link->mutex, FuriWaitForever);
    error = link->pending_error;
    link->pending_error = 0;
    furi_mutex_release(link->mutex);
    return error;
}

bool zf_ble_link_cancel_requested(ZfBleLink *link) {
    bool cancel = false;

    furi_mutex_acquire(link->mutex, FuriWaitForever);
    cancel = link->cancel || !link->connected;
    furi_mutex_release(link->mutex);
    return cancel;
}

/* Worker thread: one response, cut into notifications of the link's fragment size. */
bool zf_ble_link_send(ZfBleLink *link, uint8_t cmd, const uint8_t *data, size_t len) {
    ZfBleFrame frame = {.data = link->tx_frame};
    uint16_t frag = 0;
    size_t offset = 0;
    size_t chunk = 0;
    uint8_t seq = 0;
    bool ok = true;

    if (len > 0xFFFFU) {
        return false;
    }
    furi_mutex_acquire(link->mutex, FuriWaitForever);
    frag = link->frag_size;
    ok = link->connected;
    link->activity_tick = furi_get_tick();
    furi_mutex_release(link->mutex);
    if (!ok) {
        return false;
    }

    link->tx_frame[0] = cmd;
    link->tx_frame[1] = (uint8_t)(len >> 8);
    link->tx_frame[2] = (uint8_t)len;
    chunk = len < (size_t)(frag - 3U) ? len : (size_t)(frag - 3U);
    if (chunk > 0U) {
        memcpy(link->tx_frame + 3, data, chunk);
    }
    frame.len = (uint16_t)(3U + chunk);
    /* ble_gatt_characteristic_update returns true on failure. */
    ok = !ble_gatt_characteristic_update(link->svc_handle, &link->chars[ZfBleCharStatus], &frame);
    offset = chunk;
    while (ok && offset < len) {
        link->tx_frame[0] = seq;
        seq = (uint8_t)((seq + 1U) & 0x7FU);
        chunk = len - offset < (size_t)(frag - 1U) ? len - offset : (size_t)(frag - 1U);
        memcpy(link->tx_frame + 1, data + offset, chunk);
        frame.len = (uint16_t)(1U + chunk);
        ok = !ble_gatt_characteristic_update(link->svc_handle, &link->chars[ZfBleCharStatus],
                                             &frame);
        offset += chunk;
    }
    memset(link->tx_frame, 0, sizeof(link->tx_frame));
    return ok;
}

/*
 * Abandons a request whose continuation frames stopped coming. Review
 * 2026-11-06: a complete request (or error) that no BLE worker took within a
 * few seconds is dropped too, so an old request cannot pop up later (called
 * from the UI tick as well, when another transport is active).
 */
void zf_ble_link_tick(ZfBleLink *link) {
    uint32_t idle = 0;

    furi_mutex_acquire(link->mutex, FuriWaitForever);
    idle = furi_get_tick() - link->rx_tick;
    if (link->rx_active && idle > ZF_BLE_RX_TIMEOUT_MS) {
        zf_ble_rx_fail_locked(link, ZF_BLE_ERR_REQ_TIMEOUT);
    } else if (!link->busy && idle > ZF_BLE_STALE_MS) {
        if (link->msg_ready) {
            zf_ble_rx_drop_locked(link);
        }
        if (!link->worker) {
            link->pending_error = 0;
        }
    }
    furi_mutex_release(link->mutex);
}

bool zf_ble_link_is_connected(ZfBleLink *link) {
    bool connected = false;

    furi_mutex_acquire(link->mutex, FuriWaitForever);
    connected = link->connected;
    furi_mutex_release(link->mutex);
    return connected;
}

bool zf_ble_link_has_work(ZfBleLink *link) {
    bool work = false;

    furi_mutex_acquire(link->mutex, FuriWaitForever);
    work = link->msg_ready || link->rx_active || link->busy || link->pending_error;
    furi_mutex_release(link->mutex);
    return work;
}

uint32_t zf_ble_link_last_activity(ZfBleLink *link) {
    uint32_t tick = 0;

    furi_mutex_acquire(link->mutex, FuriWaitForever);
    tick = link->activity_tick;
    furi_mutex_release(link->mutex);
    return tick;
}

void zf_ble_link_get_diag(ZfBleLink *link, ZfBleLinkDiag *out) {
    furi_mutex_acquire(link->mutex, FuriWaitForever);
    *out = link->diag;
    furi_mutex_release(link->mutex);
}
