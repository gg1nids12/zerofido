/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-06: new file.
 *
 * Light NFC exchange log for release builds: per exchange only the APDU header
 * (CLA INS P1 P2), data length, the CTAP command byte, the status word, the
 * response length, a few transport events and timings. No data bytes. Kept in
 * a small RAM ring and written to the service trace after the phone leaves.
 * The full diagnostic build (ZEROFIDO_RELEASE_DIAGNOSTICS) does not fit the
 * heap in NFC mode, this one does.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef ZF_NFC_XLOG
#define ZF_NFC_XLOG 0
#endif

#if ZF_NFC_XLOG && !defined(ZF_HOST_TEST) &&                                                     \
    !(defined(ZF_RELEASE_DIAGNOSTICS) && ZF_RELEASE_DIAGNOSTICS)
#define ZF_NFC_XLOG_ACTIVE 1
#include <storage/storage.h>

void zf_nfc_xlog_rx(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, size_t lc, uint8_t cmd,
                    bool extended, bool chained);
void zf_nfc_xlog_tx(uint16_t sw, size_t len);
/* name must be a string literal (only the pointer is kept). */
void zf_nfc_xlog_event(const char *name);
void zf_nfc_xlog_session_end(void);
/* Writes pending entries to the service trace; call from a thread that may block. */
void zf_nfc_xlog_flush(Storage *storage);
#else
#define ZF_NFC_XLOG_ACTIVE 0
#define zf_nfc_xlog_rx(...) ((void)0)
#define zf_nfc_xlog_tx(...) ((void)0)
#define zf_nfc_xlog_event(...) ((void)0)
#define zf_nfc_xlog_session_end() ((void)0)
#define zf_nfc_xlog_flush(...) ((void)0)
#endif
