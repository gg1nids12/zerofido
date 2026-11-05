/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 *
 * Short troubleshooting trace on the SD card (/ext/apps_data/zerofido/trace.txt):
 * command, stage, status codes and timings only. Never logs RP IDs, user names,
 * PINs, keys or other request contents. Capped at ~4 KB.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#pragma once

#include <storage/storage.h>

#ifndef ZF_TPM_TRACE
#ifdef ZF_HOST_TEST
#define ZF_TPM_TRACE 0
#else
#define ZF_TPM_TRACE 1
#endif
#endif

#if ZF_TPM_TRACE
void zf_trace(Storage *storage, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#define ZF_TRACE(storage, ...) zf_trace((storage), __VA_ARGS__)
#else
/* Disabled: still evaluates the arguments, so callers need no #if around them. */
static inline void zf_trace_noop(Storage *storage, const char *fmt, ...) {
    (void)storage;
    (void)fmt;
}
#define ZF_TRACE(storage, ...) zf_trace_noop((storage), __VA_ARGS__)
#endif
