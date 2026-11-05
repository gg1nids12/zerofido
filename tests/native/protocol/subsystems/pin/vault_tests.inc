/*
 * tpm branch (FlipperPasskey), 2026-11-05: PIN vault regressions.
 * Host crypto is stubbed, so these check the vault logic and file handling,
 * not the cryptographic strength.
 */

static void test_vault_hash(const char *pin, uint8_t out[ZF_PIN_HASH_LEN]) {
    uint8_t full[32];

    zf_crypto_sha256((const uint8_t *)pin, strlen(pin), full);
    memcpy(out, full, ZF_PIN_HASH_LEN);
}

static void test_vault_create_unlock_and_wrong_pin(void) {
    Storage storage = {0};
    uint8_t good[ZF_PIN_HASH_LEN];
    uint8_t bad[ZF_PIN_HASH_LEN];
    uint8_t verifier[ZF_VAULT_VERIFIER_LEN];
    uint8_t key_a[ZF_VAULT_KEY_LEN];
    uint8_t key_b[ZF_VAULT_KEY_LEN];
    static const uint8_t cred_id[4] = {1, 2, 3, 4};

    test_storage_reset();
    test_vault_hash("correct horse", good);
    test_vault_hash("wrong pony", bad);
    expect(!zf_vault_is_present(), "vault absent before create");
    expect(zf_vault_create(&storage, good, verifier), "vault create");
    expect(zf_vault_is_present() && zf_vault_is_unlocked(), "vault unlocked after create");
    expect(zf_vault_record_key(cred_id, sizeof(cred_id), key_a), "record key while unlocked");
    zf_vault_lock();
    expect(!zf_vault_is_unlocked(), "vault locked");
    expect(!zf_vault_record_key(cred_id, sizeof(cred_id), key_b), "no record key while locked");
    expect(!zf_vault_unlock(bad), "wrong PIN must not open the vault");
    expect(!zf_vault_is_unlocked(), "wrong PIN leaves the vault locked");
    expect(zf_vault_unlock(good), "right PIN opens the vault");
    expect(zf_vault_record_key(cred_id, sizeof(cred_id), key_b), "record key after unlock");
    expect(memcmp(key_a, key_b, sizeof(key_a)) == 0, "record key is stable across unlocks");
}

static void test_vault_survives_reload_and_rewrap_keeps_pmk(void) {
    Storage storage = {0};
    uint8_t old_pin[ZF_PIN_HASH_LEN];
    uint8_t new_pin[ZF_PIN_HASH_LEN];
    uint8_t verifier[ZF_VAULT_VERIFIER_LEN];
    uint8_t verifier2[ZF_VAULT_VERIFIER_LEN];
    uint8_t key_a[ZF_VAULT_KEY_LEN];
    uint8_t key_b[ZF_VAULT_KEY_LEN];
    static const uint8_t cred_id[3] = {9, 8, 7};

    test_storage_reset();
    test_vault_hash("first pin 123", old_pin);
    test_vault_hash("second pin 456", new_pin);
    expect(zf_vault_create(&storage, old_pin, verifier), "vault create for rewrap");
    expect(zf_vault_record_key(cred_id, sizeof(cred_id), key_a), "record key before rewrap");

    zf_vault_reset_runtime();
    expect(!zf_vault_is_present(), "runtime reset forgets the vault");
    expect(zf_vault_load(&storage) && zf_vault_is_present(), "vault reloads from storage");
    expect(!zf_vault_is_unlocked(), "reloaded vault is locked");
    expect(!zf_vault_rewrap(&storage, new_pin, verifier2), "rewrap needs an unlocked vault");
    expect(zf_vault_unlock(old_pin), "old PIN opens reloaded vault");
    expect(zf_vault_rewrap(&storage, new_pin, verifier2), "rewrap to the new PIN");
    /* Verifier inequality is not asserted: the host HMAC stub folds bytes, so the
     * first half of two verifiers can collide. The checks below cover it. */
    UNUSED(verifier2);

    zf_vault_reset_runtime();
    expect(zf_vault_load(&storage), "reload after rewrap");
    expect(!zf_vault_unlock(old_pin), "old PIN no longer opens the vault");
    expect(zf_vault_unlock(new_pin), "new PIN opens the vault");
    expect(zf_vault_record_key(cred_id, sizeof(cred_id), key_b), "record key after rewrap");
    expect(memcmp(key_a, key_b, sizeof(key_a)) == 0, "rewrap keeps the same PMK");
}

static void test_vault_rejects_tampered_file(void) {
    Storage storage = {0};
    uint8_t pin[ZF_PIN_HASH_LEN];
    uint8_t verifier[ZF_VAULT_VERIFIER_LEN];
    uint8_t blob[200];
    size_t size = 0;

    test_storage_reset();
    test_vault_hash("tamper test pin", pin);
    expect(zf_vault_create(&storage, pin, verifier), "vault create for tamper");
    expect(zf_storage_read_file(&storage, ZF_VAULT_FILE_PATH, blob, sizeof(blob), &size) &&
               size == 124U,
           "read vault file");
    blob[size - 40U] ^= 0x01U; /* inside pmk_wrapped */
    expect(zf_storage_write_file_atomic(&storage, ZF_VAULT_FILE_PATH, ZF_VAULT_FILE_TEMP_PATH, blob,
                                        size),
           "write tampered vault");
    zf_vault_reset_runtime();
    expect(zf_vault_load(&storage), "tampered vault still parses");
    expect(!zf_vault_unlock(pin), "tampered vault must not open");

    blob[0] ^= 0xFFU; /* magic */
    expect(zf_storage_write_file_atomic(&storage, ZF_VAULT_FILE_PATH, ZF_VAULT_FILE_TEMP_PATH, blob,
                                        size),
           "write malformed vault");
    zf_vault_reset_runtime();
    expect(!zf_vault_load(&storage), "malformed vault is reported");
}

static void test_vault_locks_after_timeout_and_destroy_removes_file(void) {
    Storage storage = {0};
    uint8_t pin[ZF_PIN_HASH_LEN];
    uint8_t verifier[ZF_VAULT_VERIFIER_LEN];

    test_storage_reset();
    test_vault_hash("timeout pin 1", pin);
    expect(zf_vault_create(&storage, pin, verifier), "vault create for timeout");
    g_fake_tick += ZF_VAULT_UNLOCK_TIMEOUT_MS - 1U;
    zf_vault_tick();
    expect(zf_vault_is_unlocked(), "vault stays unlocked before the timeout");
    g_fake_tick += 2U;
    zf_vault_tick();
    expect(!zf_vault_is_unlocked(), "vault locks after the timeout");
    expect(zf_vault_destroy(&storage), "vault destroy");
    expect(!zf_vault_is_present(), "vault absent after destroy");
    expect(!storage_file_exists(&storage, ZF_VAULT_FILE_PATH), "vault file removed");
}

static void test_vault_pin_flow_set_check_clear(void) {
    Storage storage = {0};
    ZfClientPinState state;
    uint8_t good[ZF_PIN_HASH_LEN];
    uint8_t bad[ZF_PIN_HASH_LEN];

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for vault flow");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN creates the vault");
    expect(zf_vault_is_present(), "vault present after setPin");
    test_vault_hash("1234", good);
    test_vault_hash("9999", bad);
    expect(memcmp(state.pin_hash, good, ZF_PIN_HASH_LEN) != 0,
           "stored PIN state is not the PIN hash");
    expect(!zf_vault_is_unlocked(), "setPin leaves the vault locked (token invalidated)");
    expect(!zf_pin_check_hash(&storage, &state, bad), "wrong PIN fails the vault check");
    expect(zf_pin_check_hash(&storage, &state, good), "right PIN passes the vault check");
    expect(zf_vault_is_unlocked(), "right PIN unlocks the PMK");
    zf_pin_invalidate_token_state(&state);
    expect(!zf_vault_is_unlocked(), "token invalidation wipes the PMK");

    expect(zerofido_pin_init(&storage, &state), "re-init keeps the vault");
    expect(zf_vault_is_present(), "vault present after re-init");
    expect(zf_pin_check_hash(&storage, &state, good), "right PIN after re-init");

    expect(zerofido_pin_clear(&storage, &state), "clear PIN");
    expect(!zf_vault_is_present(), "clear PIN destroys the vault");
}

static void test_vault_migrates_legacy_pin(void) {
    Storage storage = {0};
    ZfClientPinState state;
    uint8_t good[ZF_PIN_HASH_LEN];

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for legacy migration");
    test_vault_hash("1234", good);
    state.pin_set = true;
    state.pin_retries = ZF_PIN_RETRIES_MAX;
    memcpy(state.pin_hash, good, ZF_PIN_HASH_LEN); /* pre-tpm stored hash */
    expect(!zf_vault_is_present(), "legacy state has no vault");
    expect(zf_pin_check_hash(&storage, &state, good), "legacy PIN accepted once");
    expect(zf_vault_is_present() && zf_vault_is_unlocked(), "legacy PIN migrated to a vault");
    expect(memcmp(state.pin_hash, good, ZF_PIN_HASH_LEN) != 0,
           "after migration the stored state is the verifier");
    zf_vault_lock();
    expect(zf_pin_check_hash(&storage, &state, good), "migrated PIN opens the vault");
}

static void test_vault_orphan_removed_on_init(void) {
    Storage storage = {0};
    ZfClientPinState state;
    uint8_t pin[ZF_PIN_HASH_LEN];
    uint8_t verifier[ZF_VAULT_VERIFIER_LEN];

    test_storage_reset();
    test_vault_hash("orphan pin", pin);
    expect(zf_vault_create(&storage, pin, verifier), "create orphan vault");
    expect(zerofido_pin_init(&storage, &state), "init without a PIN file");
    expect(!state.pin_set, "no PIN set");
    expect(!zf_vault_is_present(), "orphan vault removed on init");
}

static void run_vault_tests(void) {
    test_vault_create_unlock_and_wrong_pin();
    test_vault_survives_reload_and_rewrap_keeps_pmk();
    test_vault_rejects_tampered_file();
    test_vault_locks_after_timeout_and_destroy_removes_file();
    test_vault_pin_flow_set_check_clear();
    test_vault_migrates_legacy_pin();
    test_vault_orphan_removed_on_init();
}
