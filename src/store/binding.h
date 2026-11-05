/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 *
 * PIN binding of discoverable credentials. A bound record keeps its private
 * key and hmac-secret under an inner layer keyed by the vault record key, so
 * the credential is usable only after a successful PIN check.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <storage/storage.h>

#include "../zerofido_types.h"

/* Adds the inner layer. Needs an unlocked vault and a resident record. */
bool zf_store_bind_record(ZfCredentialRecord *record);

/* Removes the inner layer (PIN removal). Needs an unlocked vault. */
bool zf_store_unbind_record(ZfCredentialRecord *record);

/* Inner key for a bound record; false if the vault is locked. */
bool zf_store_record_inner_key(const ZfCredentialRecord *record, uint8_t out[32]);

/* hmac-secret CredRandom in the clear (decrypted for bound records). */
bool zf_store_record_cred_random(const ZfCredentialRecord *record, bool user_verified,
                                 uint8_t out[ZF_HMAC_SECRET_LEN]);

/*
 * Unbinds every bound record in the store and rewrites its file. Used before
 * the PIN is removed. Needs an unlocked vault. Returns false on the first
 * failure; records already rewritten stay unbound and consistent.
 */
bool zf_store_unbind_all(Storage *storage, ZfCredentialStore *store);
