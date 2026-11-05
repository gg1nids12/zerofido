/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 * See binding.h.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#include "binding.h"

#include <stdlib.h>
#include <string.h>

#include "../pin/vault.h"
#include "../zerofido_crypto.h"
#include "../zerofido_store.h"

bool zf_store_record_inner_key(const ZfCredentialRecord *record, uint8_t out[32]) {
    if (!record || !out) {
        return false;
    }
    return zf_vault_record_key(record->credential_id, record->credential_id_len, out);
}

static bool zf_store_crypt_hmac_secrets(ZfCredentialRecord *record, const uint8_t key[32],
                                        bool encrypt) {
    uint8_t tmp[ZF_HMAC_SECRET_LEN];
    bool ok = true;

    if (!record->hmac_secret) {
        return true;
    }
    ok = zf_crypto_inner_crypt(key, record->hmac_secret_without_uv, tmp, sizeof(tmp), encrypt);
    if (ok) {
        memcpy(record->hmac_secret_without_uv, tmp, sizeof(tmp));
        ok = zf_crypto_inner_crypt(key, record->hmac_secret_with_uv, tmp, sizeof(tmp), encrypt);
    }
    if (ok) {
        memcpy(record->hmac_secret_with_uv, tmp, sizeof(tmp));
    }
    zf_crypto_secure_zero(tmp, sizeof(tmp));
    return ok;
}

static bool zf_store_set_binding(ZfCredentialRecord *record, bool bind) {
    uint8_t key[32];
    ZfCredentialRecord next;
    bool ok = false;

    if (!record || record->bound == bind || (bind && !record->resident_key) ||
        !zf_store_record_inner_key(record, key)) {
        return false;
    }
    /* Work on a copy so a failure leaves the record untouched. */
    next = *record;
    if (zf_crypto_rewrap_private_key(&next, key, bind) &&
        zf_store_crypt_hmac_secrets(&next, key, bind)) {
        next.bound = bind;
        *record = next;
        ok = true;
    }
    zf_crypto_secure_zero(key, sizeof(key));
    zf_crypto_secure_zero(&next, sizeof(next));
    return ok;
}

bool zf_store_bind_record(ZfCredentialRecord *record) {
    return zf_store_set_binding(record, true);
}

bool zf_store_unbind_record(ZfCredentialRecord *record) {
    return zf_store_set_binding(record, false);
}

bool zf_store_record_cred_random(const ZfCredentialRecord *record, bool user_verified,
                                 uint8_t out[ZF_HMAC_SECRET_LEN]) {
    const uint8_t *stored = NULL;
    uint8_t key[32];
    bool ok = false;

    if (!record || !out || !record->hmac_secret) {
        return false;
    }
    stored = user_verified ? record->hmac_secret_with_uv : record->hmac_secret_without_uv;
    if (!record->bound) {
        memcpy(out, stored, ZF_HMAC_SECRET_LEN);
        return true;
    }
    if (zf_store_record_inner_key(record, key)) {
        ok = zf_crypto_inner_crypt(key, stored, out, ZF_HMAC_SECRET_LEN, false);
    }
    zf_crypto_secure_zero(key, sizeof(key));
    if (!ok) {
        zf_crypto_secure_zero(out, ZF_HMAC_SECRET_LEN);
    }
    return ok;
}

bool zf_store_unbind_all(Storage *storage, ZfCredentialStore *store) {
    uint8_t *buffer = NULL;
    ZfCredentialRecord record;
    bool ok = true;

    if (!storage || !store || !store->records) {
        return false;
    }
    if (!zf_vault_is_unlocked()) {
        for (size_t i = 0; i < store->count; ++i) {
            if (store->records[i].in_use && store->records[i].bound) {
                return false;
            }
        }
        return true;
    }
    buffer = malloc(ZF_STORE_RECORD_IO_SIZE);
    if (!buffer) {
        return false;
    }
    for (size_t i = 0; ok && i < store->count; ++i) {
        ZfCredentialIndexEntry *entry = &store->records[i];

        if (!entry->in_use || !entry->bound) {
            continue;
        }
        memset(&record, 0, sizeof(record));
        ok = zf_store_load_record_with_buffer(storage, entry, &record, buffer,
                                              ZF_STORE_RECORD_IO_SIZE) &&
             zf_store_unbind_record(&record) &&
             zf_store_write_record_file_with_buffer(storage, &record, buffer,
                                                    ZF_STORE_RECORD_IO_SIZE);
        if (ok) {
            entry->bound = false;
        }
        zf_crypto_secure_zero(&record, sizeof(record));
    }
    zf_crypto_secure_zero(buffer, ZF_STORE_RECORD_IO_SIZE);
    free(buffer);
    return ok;
}
