/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-06: new file.
 * See nfc_xlog.h.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#include "nfc_xlog.h"

#if ZF_NFC_XLOG_ACTIVE

#include <furi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../zerofido_trace.h"

#define ZF_NFC_XLOG_LEN 64U

typedef struct {
    uint8_t type; /* 'R' request, 'T' response, 'E' event */
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t cmd;
    uint8_t flags; /* bit0 extended, bit1 chained */
    uint8_t pad;
    uint16_t v1; /* R: data length; T: status word */
    uint16_t v2; /* T: response length */
    uint16_t ms; /* since the first entry of this batch */
    const char *name;
} ZfNfcXlogEntry;

static ZfNfcXlogEntry zf_nfc_xlog_ring[ZF_NFC_XLOG_LEN];
static uint32_t zf_nfc_xlog_total;
static uint32_t zf_nfc_xlog_t0;
static volatile bool zf_nfc_xlog_pending;

/* Caller is inside FURI_CRITICAL: NFC worker and our worker both write. */
static ZfNfcXlogEntry *zf_nfc_xlog_next(char type) {
    uint32_t now = furi_get_tick();
    ZfNfcXlogEntry *entry = NULL;

    if (zf_nfc_xlog_total == 0U) {
        zf_nfc_xlog_t0 = now;
    }
    entry = &zf_nfc_xlog_ring[zf_nfc_xlog_total % ZF_NFC_XLOG_LEN];
    memset(entry, 0, sizeof(*entry));
    entry->type = (uint8_t)type;
    entry->ms = (now - zf_nfc_xlog_t0) > 0xFFFFU ? 0xFFFFU : (uint16_t)(now - zf_nfc_xlog_t0);
    zf_nfc_xlog_total++;
    return entry;
}

void zf_nfc_xlog_rx(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, size_t lc, uint8_t cmd,
                    bool extended, bool chained) {
    FURI_CRITICAL_ENTER();
    ZfNfcXlogEntry *entry = zf_nfc_xlog_next('R');
    entry->cla = cla;
    entry->ins = ins;
    entry->p1 = p1;
    entry->p2 = p2;
    entry->cmd = cmd;
    entry->flags = (uint8_t)((extended ? 1U : 0U) | (chained ? 2U : 0U));
    entry->v1 = lc > 0xFFFFU ? 0xFFFFU : (uint16_t)lc;
    FURI_CRITICAL_EXIT();
}

void zf_nfc_xlog_tx(uint16_t sw, size_t len) {
    FURI_CRITICAL_ENTER();
    ZfNfcXlogEntry *entry = zf_nfc_xlog_next('T');
    entry->v1 = sw;
    entry->v2 = len > 0xFFFFU ? 0xFFFFU : (uint16_t)len;
    FURI_CRITICAL_EXIT();
}

void zf_nfc_xlog_event(const char *name) {
    FURI_CRITICAL_ENTER();
    ZfNfcXlogEntry *entry = zf_nfc_xlog_next('E');
    entry->name = name;
    FURI_CRITICAL_EXIT();
}

void zf_nfc_xlog_session_end(void) {
    zf_nfc_xlog_pending = true;
}

static size_t zf_nfc_xlog_format(const ZfNfcXlogEntry *entry, char *out, size_t size) {
    int n = 0;

    switch (entry->type) {
    case 'R':
        n = snprintf(out, size, " >%02X%02X%02X%02X:%u", entry->cla, entry->ins, entry->p1,
                     entry->p2, entry->v1);
        if (n > 0 && (size_t)n < size && entry->ins == 0x10U && entry->v1 > 0U) {
            n += snprintf(out + n, size - (size_t)n, "/%02X", entry->cmd);
        }
        if (n > 0 && (size_t)n < size) {
            n += snprintf(out + n, size - (size_t)n, "%s%s@%u", (entry->flags & 1U) ? "e" : "",
                          (entry->flags & 2U) ? "c" : "", entry->ms);
        }
        break;
    case 'T':
        n = snprintf(out, size, " <%04X+%u", entry->v1, entry->v2);
        break;
    default: {
        n = snprintf(out, size, " !%s@%u", entry->name ? entry->name : "?", entry->ms);
        for (int i = 2; n > 0 && i < n && (size_t)i < size; ++i) {
            if (out[i] == ' ') out[i] = '-';
        }
        break;
    }
    }
    return (n > 0 && (size_t)n < size) ? (size_t)n : 0U;
}

void zf_nfc_xlog_flush(Storage *storage) {
    ZfNfcXlogEntry *copy = NULL;
    uint32_t total = 0;
    uint32_t count = 0;
    uint32_t first = 0;
    char line[96];
    size_t used = 0;

    if (!zf_nfc_xlog_pending || !storage) {
        return;
    }
    copy = malloc(sizeof(zf_nfc_xlog_ring));
    if (!copy) {
        return;
    }
    FURI_CRITICAL_ENTER();
    memcpy(copy, zf_nfc_xlog_ring, sizeof(zf_nfc_xlog_ring));
    total = zf_nfc_xlog_total;
    zf_nfc_xlog_total = 0;
    zf_nfc_xlog_pending = false;
    FURI_CRITICAL_EXIT();

    count = total < ZF_NFC_XLOG_LEN ? total : ZF_NFC_XLOG_LEN;
    first = total - count;
    if (total > count) {
        ZF_TRACE(storage, "NFC lost=%lu", (unsigned long)(total - count));
    }
    for (uint32_t i = 0; i < count; ++i) {
        char token[48];
        size_t len = zf_nfc_xlog_format(&copy[(first + i) % ZF_NFC_XLOG_LEN], token,
                                        sizeof(token));

        if (used > 0U && used + len >= sizeof(line)) {
            ZF_TRACE(storage, "NFC%s", line);
            used = 0;
        }
        memcpy(line + used, token, len);
        used += len;
        line[used] = '\0';
    }
    if (used > 0U) {
        ZF_TRACE(storage, "NFC%s", line);
    }
    free(copy);
}

#endif
