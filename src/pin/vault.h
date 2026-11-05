/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 *
 * PIN vault: binds discoverable credentials to the ClientPIN.
 *
 * pinHash (LEFT(SHA-256(PIN),16)) is stretched through a sequential AES-CBC
 * chain under the device-unique enclave key, so every PIN guess has to run on
 * this device at about one second per guess. The stretched value gives the
 * KEK; the KEK wraps a random passkey master key (PMK) and yields a PIN
 * verifier. No plain PIN hash is stored anywhere.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <storage/storage.h>

#include "../zerofido_types.h"

#define ZF_VAULT_FILE_PATH ZF_APP_DATA_DIR "/vault.bin"
#define ZF_VAULT_FILE_TEMP_PATH ZF_APP_DATA_DIR "/vault.tmp"
#define ZF_VAULT_KEY_LEN 32U
#define ZF_VAULT_SALT_LEN 16U
#define ZF_VAULT_VERIFIER_LEN ZF_PIN_HASH_LEN
/* About one second on a Flipper Zero (bench 2026-11-05: ~193k AES blocks/s). */
#ifndef ZF_VAULT_DEFAULT_ROUNDS
#define ZF_VAULT_DEFAULT_ROUNDS 190464UL
#endif
#define ZF_VAULT_MIN_ROUNDS 32UL
/* The PMK stays in RAM at most this long after a successful PIN check. */
#define ZF_VAULT_UNLOCK_TIMEOUT_MS (ZF_PIN_TOKEN_TIMEOUT_MS + 2000U)

typedef void (*ZfVaultProgressFn)(void *context);

/* Startup: read vault.bin. Returns false only on a malformed file. */
bool zf_vault_load(Storage *storage);
bool zf_vault_is_present(void);
bool zf_vault_is_unlocked(void);

/* Called between stretch slices (USB keepalive, cancel polling). */
void zf_vault_set_progress(ZfVaultProgressFn fn, void *context);

/* Slow. True if pin_hash opens the vault; the PMK is then unlocked. */
bool zf_vault_unlock(const uint8_t pin_hash[ZF_PIN_HASH_LEN]);

/* Slow. New salt and PMK for pin_hash; writes vault.bin; leaves it unlocked. */
bool zf_vault_create(Storage *storage, const uint8_t pin_hash[ZF_PIN_HASH_LEN],
                     uint8_t verifier_out[ZF_VAULT_VERIFIER_LEN]);

/* Slow. Same PMK under a new PIN. Requires an unlocked vault. */
bool zf_vault_rewrap(Storage *storage, const uint8_t new_pin_hash[ZF_PIN_HASH_LEN],
                     uint8_t verifier_out[ZF_VAULT_VERIFIER_LEN]);

bool zf_vault_get_verifier(uint8_t out[ZF_VAULT_VERIFIER_LEN]);

/* Deletes vault.bin and wipes RAM state. */
bool zf_vault_destroy(Storage *storage);

/* Wipes the PMK from RAM. */
void zf_vault_lock(void);

/* Locks if the unlock timeout has passed. Cheap; call from periodic code. */
void zf_vault_tick(void);

/* Per-credential key K_rec = HKDF(PMK, credential_id). Requires unlocked. */
bool zf_vault_record_key(const uint8_t *credential_id, size_t credential_id_len,
                         uint8_t out[ZF_VAULT_KEY_LEN]);

/* Wipes all RAM state (app exit, tests). */
void zf_vault_reset_runtime(void);
