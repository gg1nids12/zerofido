/*
 * ZeroFIDO — tpm branch (FlipperPasskey). Modified 2026-11-05: new file.
 *
 * PIN vault implementation. See ../vault.h for the model.
 *
 * vault.bin (124 bytes):
 *   magic, version, rounds, salt[16], verifier[16], iv[16], pmk_wrapped[32], mac[32]
 *
 *   seed     = SHA-256("zerofido-stretch-v1" || salt || pinHash)
 *   S        = last block of AES-CBC(DUK, IV = seed[:16], zeros * rounds blocks)
 *   KEK      = HKDF-SHA256(salt, S || pinHash, "zerofido-kek-v1")
 *   verifier = HMAC(KEK, "zerofido-verify-v1")[:16]
 *   pmk_wrapped = AES-256-CBC(HMAC(KEK, "zerofido-wrap-v1"), iv, PMK)
 *   mac      = HMAC(HMAC(KEK, "zerofido-mac-v1"), file bytes before mac)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#include "../vault.h"

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_random.h>
#include <stddef.h>
#include <string.h>

#include "../../zerofido_crypto.h"
#include "../../zerofido_storage.h"

#define ZF_VAULT_MAGIC 0x3156465AUL /* "ZFV1" */
#define ZF_VAULT_VERSION 1U
#define ZF_VAULT_CHUNK 512U
#define ZF_VAULT_BLOCK 16U
#define ZF_VAULT_SLICE_BLOCKS 8192UL /* ~40 ms on device between progress calls */

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t reserved[3];
    uint32_t rounds;
    uint8_t salt[ZF_VAULT_SALT_LEN];
    uint8_t verifier[ZF_VAULT_VERIFIER_LEN];
    uint8_t iv[ZF_WRAP_IV_LEN];
    uint8_t pmk_wrapped[ZF_VAULT_KEY_LEN];
    uint8_t mac[32];
} ZfVaultFile;

_Static_assert(sizeof(ZfVaultFile) == 124U, "vault file layout changed");

static struct {
    bool present;
    bool unlocked;
    ZfVaultFile file;
    ZfVaultFile alt; /* mirror copy when it differs from the primary */
    bool alt_present;
    bool repair_pending; /* the copy in use came from the mirror */
    uint8_t pmk[ZF_VAULT_KEY_LEN];
    uint32_t unlocked_at;
    ZfVaultProgressFn progress;
    void *progress_context;
} g_vault;

static const uint8_t zf_vault_zero_chunk[ZF_VAULT_CHUNK];
static uint8_t zf_vault_chunk_out[ZF_VAULT_CHUNK];

static bool zf_vault_rounds_valid(uint32_t rounds) {
    return rounds >= ZF_VAULT_MIN_ROUNDS && (rounds % (ZF_VAULT_CHUNK / ZF_VAULT_BLOCK)) == 0U;
}

/*
 * Sequential AES-CBC chain over zero blocks under the device key. The key is
 * reloaded every slice with the last ciphertext block as IV, which continues
 * the same CBC chain and releases the crypto HAL between slices.
 */
static bool zf_vault_stretch(const uint8_t pin_hash[ZF_PIN_HASH_LEN],
                             const uint8_t salt[ZF_VAULT_SALT_LEN], uint32_t rounds,
                             uint8_t out[ZF_VAULT_BLOCK]) {
    static const char label[] = "zerofido-stretch-v1";
    uint8_t material[sizeof(label) - 1U + ZF_VAULT_SALT_LEN + ZF_PIN_HASH_LEN];
    uint8_t seed[32];
    uint8_t iv[ZF_VAULT_BLOCK];
    uint32_t done = 0;
    bool ok = zf_vault_rounds_valid(rounds);

    memcpy(material, label, sizeof(label) - 1U);
    memcpy(material + sizeof(label) - 1U, salt, ZF_VAULT_SALT_LEN);
    memcpy(material + sizeof(label) - 1U + ZF_VAULT_SALT_LEN, pin_hash, ZF_PIN_HASH_LEN);
    zf_crypto_sha256(material, sizeof(material), seed);
    memcpy(iv, seed, sizeof(iv));

    while (ok && done < rounds) {
        uint32_t slice = 0;

        if (!furi_hal_crypto_enclave_load_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT, iv)) {
            ok = false;
            break;
        }
        while (done < rounds && slice < ZF_VAULT_SLICE_BLOCKS) {
            if (!furi_hal_crypto_encrypt(zf_vault_zero_chunk, zf_vault_chunk_out,
                                         ZF_VAULT_CHUNK)) {
                ok = false;
                break;
            }
            done += ZF_VAULT_CHUNK / ZF_VAULT_BLOCK;
            slice += ZF_VAULT_CHUNK / ZF_VAULT_BLOCK;
        }
        furi_hal_crypto_enclave_unload_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT);
        memcpy(iv, zf_vault_chunk_out + ZF_VAULT_CHUNK - ZF_VAULT_BLOCK, sizeof(iv));
        if (ok && done < rounds && g_vault.progress) {
            g_vault.progress(g_vault.progress_context);
        }
    }

    if (ok) {
        memcpy(out, iv, ZF_VAULT_BLOCK);
    }
    zf_crypto_secure_zero(material, sizeof(material));
    zf_crypto_secure_zero(seed, sizeof(seed));
    zf_crypto_secure_zero(iv, sizeof(iv));
    zf_crypto_secure_zero(zf_vault_chunk_out, sizeof(zf_vault_chunk_out));
    return ok;
}

static bool zf_vault_label_key(const uint8_t kek[ZF_VAULT_KEY_LEN], const char *label,
                               uint8_t out[32]) {
    return zf_crypto_hmac_sha256(kek, ZF_VAULT_KEY_LEN, (const uint8_t *)label, strlen(label),
                                 out);
}

/* KEK and the three keys derived from it, for one PIN and one vault header. */
typedef struct {
    uint8_t verifier[32];
    uint8_t wrap[32];
    uint8_t mac[32];
} ZfVaultKeys;

static bool zf_vault_derive(const uint8_t pin_hash[ZF_PIN_HASH_LEN], const ZfVaultFile *file,
                            ZfVaultKeys *keys) {
    static const char info[] = "zerofido-kek-v1";
    uint8_t stretched[ZF_VAULT_BLOCK];
    uint8_t ikm[ZF_VAULT_BLOCK + ZF_PIN_HASH_LEN];
    uint8_t kek[ZF_VAULT_KEY_LEN];
    bool ok = false;

    memset(keys, 0, sizeof(*keys));
    if (zf_vault_stretch(pin_hash, file->salt, file->rounds, stretched)) {
        memcpy(ikm, stretched, ZF_VAULT_BLOCK);
        memcpy(ikm + ZF_VAULT_BLOCK, pin_hash, ZF_PIN_HASH_LEN);
        ok = zf_crypto_hkdf_sha256(file->salt, ZF_VAULT_SALT_LEN, ikm, sizeof(ikm),
                                   (const uint8_t *)info, sizeof(info) - 1U, kek) &&
             zf_vault_label_key(kek, "zerofido-verify-v1", keys->verifier) &&
             zf_vault_label_key(kek, "zerofido-wrap-v1", keys->wrap) &&
             zf_vault_label_key(kek, "zerofido-mac-v1", keys->mac);
    }
    zf_crypto_secure_zero(stretched, sizeof(stretched));
    zf_crypto_secure_zero(ikm, sizeof(ikm));
    zf_crypto_secure_zero(kek, sizeof(kek));
    if (!ok) {
        zf_crypto_secure_zero(keys, sizeof(*keys));
    }
    return ok;
}

static bool zf_vault_file_mac(const uint8_t mac_key[32], const ZfVaultFile *file,
                              uint8_t out[32]) {
    return zf_crypto_hmac_sha256(mac_key, 32, (const uint8_t *)file, offsetof(ZfVaultFile, mac),
                                 out);
}

/* Builds a fresh vault file (new salt and IV) holding pmk under pin_hash. */
static bool zf_vault_seal(const uint8_t pin_hash[ZF_PIN_HASH_LEN],
                          const uint8_t pmk[ZF_VAULT_KEY_LEN], ZfVaultFile *out) {
    ZfVaultKeys keys;
    bool ok = false;

    memset(out, 0, sizeof(*out));
    out->magic = ZF_VAULT_MAGIC;
    out->version = ZF_VAULT_VERSION;
    out->rounds = ZF_VAULT_DEFAULT_ROUNDS;
    furi_hal_random_fill_buf(out->salt, sizeof(out->salt));
    furi_hal_random_fill_buf(out->iv, sizeof(out->iv));
    if (zf_vault_derive(pin_hash, out, &keys)) {
        memcpy(out->verifier, keys.verifier, ZF_VAULT_VERIFIER_LEN);
        ok = zf_crypto_aes256_cbc_encrypt(keys.wrap, out->iv, pmk, out->pmk_wrapped,
                                          ZF_VAULT_KEY_LEN) &&
             zf_vault_file_mac(keys.mac, out, out->mac);
    }
    zf_crypto_secure_zero(&keys, sizeof(keys));
    if (!ok) {
        zf_crypto_secure_zero(out, sizeof(*out));
    }
    return ok;
}

static bool zf_vault_write(Storage *storage, const ZfVaultFile *file) {
    bool ok = zf_storage_ensure_app_data_dir(storage) &&
              zf_storage_write_file_atomic(storage, ZF_VAULT_FILE_PATH, ZF_VAULT_FILE_TEMP_PATH,
                                           (const uint8_t *)file, sizeof(*file));
    if (ok) {
        /* The mirror is best effort; the primary decides success. */
        (void)zf_storage_write_file_atomic(storage, ZF_VAULT_MIRROR_PATH,
                                           ZF_VAULT_MIRROR_TEMP_PATH, (const uint8_t *)file,
                                           sizeof(*file));
    }
    return ok;
}

/* Reads and checks one vault file: 1 = valid, 0 = missing, -1 = malformed. */
static int zf_vault_read_one(Storage *storage, const char *path, const char *temp_path,
                             ZfVaultFile *out) {
    size_t size = 0;

    zf_storage_recover_atomic_file(storage, path, temp_path);
    if (!storage_file_exists(storage, path)) {
        return 0;
    }
    if (!zf_storage_read_file(storage, path, (uint8_t *)out, sizeof(*out), &size) ||
        size != sizeof(*out) || out->magic != ZF_VAULT_MAGIC || out->version != ZF_VAULT_VERSION ||
        !zf_vault_rounds_valid(out->rounds)) {
        zf_crypto_secure_zero(out, sizeof(*out));
        return -1;
    }
    return 1;
}

void zf_vault_reset_runtime(void) {
    ZfVaultProgressFn progress = g_vault.progress;
    void *context = g_vault.progress_context;

    zf_crypto_secure_zero(&g_vault, sizeof(g_vault));
    g_vault.progress = progress;
    g_vault.progress_context = context;
}

bool zf_vault_load(Storage *storage) {
    ZfVaultFile primary;
    ZfVaultFile mirror;
    int p = 0;
    int m = 0;

    zf_vault_reset_runtime();
    p = zf_vault_read_one(storage, ZF_VAULT_FILE_PATH, ZF_VAULT_FILE_TEMP_PATH, &primary);
    m = zf_vault_read_one(storage, ZF_VAULT_MIRROR_PATH, ZF_VAULT_MIRROR_TEMP_PATH, &mirror);
    if (p == 1) {
        g_vault.file = primary;
        g_vault.present = true;
        if (m == 1 && memcmp(&primary, &mirror, sizeof(primary)) != 0) {
            g_vault.alt = mirror;
            g_vault.alt_present = true;
        }
    } else if (m == 1) {
        g_vault.file = mirror; /* primary missing or damaged: use the mirror */
        g_vault.present = true;
        g_vault.repair_pending = true;
    }
    zf_crypto_secure_zero(&primary, sizeof(primary));
    zf_crypto_secure_zero(&mirror, sizeof(mirror));
    return g_vault.present || p == 0;
}

bool zf_vault_is_present(void) {
    return g_vault.present;
}

bool zf_vault_is_unlocked(void) {
    return g_vault.present && g_vault.unlocked;
}

void zf_vault_set_progress(ZfVaultProgressFn fn, void *context) {
    g_vault.progress = fn;
    g_vault.progress_context = context;
}

static bool zf_vault_open_file(const uint8_t pin_hash[ZF_PIN_HASH_LEN], const ZfVaultFile *file) {
    ZfVaultKeys keys;
    uint8_t mac[32];
    uint8_t pmk[ZF_VAULT_KEY_LEN];
    bool ok = false;

    if (zf_vault_derive(pin_hash, file, &keys) &&
        zf_crypto_constant_time_equal(keys.verifier, file->verifier, ZF_VAULT_VERIFIER_LEN) &&
        zf_vault_file_mac(keys.mac, file, mac) &&
        zf_crypto_constant_time_equal(mac, file->mac, sizeof(mac)) &&
        zf_crypto_aes256_cbc_decrypt(keys.wrap, file->iv, file->pmk_wrapped, pmk, sizeof(pmk))) {
        memcpy(g_vault.pmk, pmk, sizeof(pmk));
        g_vault.unlocked = true;
        g_vault.unlocked_at = furi_get_tick();
        ok = true;
    }
    zf_crypto_secure_zero(&keys, sizeof(keys));
    zf_crypto_secure_zero(mac, sizeof(mac));
    zf_crypto_secure_zero(pmk, sizeof(pmk));
    return ok;
}

bool zf_vault_unlock(const uint8_t pin_hash[ZF_PIN_HASH_LEN]) {
    if (!g_vault.present || !pin_hash) {
        return false;
    }
    if (zf_vault_open_file(pin_hash, &g_vault.file)) {
        return true;
    }
    /* Primary damaged in place (MAC fails) but the mirror opens: adopt it. */
    if (g_vault.alt_present && zf_vault_open_file(pin_hash, &g_vault.alt)) {
        g_vault.file = g_vault.alt;
        g_vault.alt_present = false;
        g_vault.repair_pending = true;
        zf_crypto_secure_zero(&g_vault.alt, sizeof(g_vault.alt));
        return true;
    }
    return false;
}

bool zf_vault_repair(Storage *storage) {
    if (!g_vault.present || !storage || !g_vault.repair_pending) {
        return true;
    }
    if (!zf_vault_write(storage, &g_vault.file)) {
        return false;
    }
    g_vault.repair_pending = false;
    return true;
}

bool zf_vault_create(Storage *storage, const uint8_t pin_hash[ZF_PIN_HASH_LEN],
                     uint8_t verifier_out[ZF_VAULT_VERIFIER_LEN]) {
    ZfVaultFile file;
    uint8_t pmk[ZF_VAULT_KEY_LEN];
    bool ok = false;

    if (!storage || !pin_hash || !verifier_out || !zf_crypto_ensure_store_key()) {
        return false;
    }
    furi_hal_random_fill_buf(pmk, sizeof(pmk));
    if (zf_vault_seal(pin_hash, pmk, &file) && zf_vault_write(storage, &file)) {
        g_vault.file = file;
        g_vault.present = true;
        memcpy(g_vault.pmk, pmk, sizeof(pmk));
        g_vault.unlocked = true;
        g_vault.unlocked_at = furi_get_tick();
        memcpy(verifier_out, file.verifier, ZF_VAULT_VERIFIER_LEN);
        ok = true;
    }
    zf_crypto_secure_zero(&file, sizeof(file));
    zf_crypto_secure_zero(pmk, sizeof(pmk));
    return ok;
}

bool zf_vault_rewrap(Storage *storage, const uint8_t new_pin_hash[ZF_PIN_HASH_LEN],
                     uint8_t verifier_out[ZF_VAULT_VERIFIER_LEN]) {
    ZfVaultFile file;
    bool ok = false;

    if (!storage || !new_pin_hash || !verifier_out || !zf_vault_is_unlocked()) {
        return false;
    }
    if (zf_vault_seal(new_pin_hash, g_vault.pmk, &file) && zf_vault_write(storage, &file)) {
        g_vault.file = file;
        g_vault.unlocked_at = furi_get_tick();
        memcpy(verifier_out, file.verifier, ZF_VAULT_VERIFIER_LEN);
        ok = true;
    }
    zf_crypto_secure_zero(&file, sizeof(file));
    return ok;
}

bool zf_vault_get_verifier(uint8_t out[ZF_VAULT_VERIFIER_LEN]) {
    if (!g_vault.present || !out) {
        return false;
    }
    memcpy(out, g_vault.file.verifier, ZF_VAULT_VERIFIER_LEN);
    return true;
}

bool zf_vault_destroy(Storage *storage) {
    bool ok = zf_storage_remove_atomic_file(storage, ZF_VAULT_FILE_PATH, ZF_VAULT_FILE_TEMP_PATH);

    (void)zf_storage_remove_atomic_file(storage, ZF_VAULT_MIRROR_PATH, ZF_VAULT_MIRROR_TEMP_PATH);

    zf_vault_reset_runtime();
    return ok;
}

void zf_vault_lock(void) {
    zf_crypto_secure_zero(g_vault.pmk, sizeof(g_vault.pmk));
    g_vault.unlocked = false;
    g_vault.unlocked_at = 0;
}

void zf_vault_tick(void) {
    if (g_vault.unlocked &&
        (int32_t)(furi_get_tick() - g_vault.unlocked_at) >= (int32_t)ZF_VAULT_UNLOCK_TIMEOUT_MS) {
        zf_vault_lock();
    }
}

bool zf_vault_record_key(const uint8_t *credential_id, size_t credential_id_len,
                         uint8_t out[ZF_VAULT_KEY_LEN]) {
    static const char salt[] = "zerofido-cred-v1";

    if (!zf_vault_is_unlocked() || !credential_id || credential_id_len == 0U || !out) {
        return false;
    }
    return zf_crypto_hkdf_sha256((const uint8_t *)salt, sizeof(salt) - 1U, g_vault.pmk,
                                 sizeof(g_vault.pmk), credential_id, credential_id_len, out);
}
