/*
 * tpm branch (FlipperPasskey), 2026-11-05: PIN binding regressions.
 * Host crypto is stubbed (XOR stand-ins), so these check the binding logic,
 * storage format and policy, not cryptographic strength.
 */

static void test_binding_open_vault(void) {
    static Storage vault_storage;
    uint8_t verifier[ZF_VAULT_VERIFIER_LEN];

    zf_vault_reset_runtime();
    expect(zf_vault_create(&vault_storage, test_pin_hash_1234(), verifier),
           "open a vault for binding tests");
}

static void test_binding_bind_unbind_roundtrip(void) {
    ZfCredentialRecord record;
    ZfCredentialRecord original;
    uint8_t random_out[ZF_HMAC_SECRET_LEN];

    test_storage_reset();
    fill_large_resident_hmac_secret_record(&record);
    original = record;

    expect(!zf_store_bind_record(&record), "bind refused with no vault");
    expect(!record.bound, "refused bind leaves the record unbound");

    test_binding_open_vault();
    expect(zf_store_bind_record(&record), "bind with an unlocked vault");
    expect(record.bound, "record marked bound");
    expect(memcmp(record.private_wrapped, original.private_wrapped,
                  sizeof(record.private_wrapped)) != 0,
           "bound private key differs from the device-only wrap");
    expect(memcmp(record.hmac_secret_with_uv, original.hmac_secret_with_uv,
                  sizeof(record.hmac_secret_with_uv)) != 0,
           "bound hmac-secret is not stored in the clear");
    expect(zf_store_record_cred_random(&record, true, random_out) &&
               memcmp(random_out, original.hmac_secret_with_uv, sizeof(random_out)) == 0,
           "bound CredRandom decrypts with the vault open");
    expect(!zf_store_bind_record(&record), "binding twice is refused");

    zf_vault_lock();
    expect(!zf_store_record_cred_random(&record, true, random_out),
           "bound CredRandom is unavailable with the vault locked");
    expect(!zf_store_unbind_record(&record), "unbind refused with the vault locked");

    expect(zf_vault_unlock(test_pin_hash_1234()), "reopen vault");
    expect(zf_store_unbind_record(&record), "unbind with the vault open");
    expect(!record.bound, "record unbound");
    expect(memcmp(record.private_wrapped, original.private_wrapped,
                  sizeof(record.private_wrapped)) == 0,
           "unbind restores the device-only private key wrap");
    expect(memcmp(record.hmac_secret_with_uv, original.hmac_secret_with_uv,
                  sizeof(record.hmac_secret_with_uv)) == 0 &&
               memcmp(record.hmac_secret_without_uv, original.hmac_secret_without_uv,
                      sizeof(record.hmac_secret_without_uv)) == 0,
           "unbind restores the hmac-secret seeds");
}

static void test_binding_refuses_non_resident(void) {
    ZfCredentialRecord record;

    test_storage_reset();
    fill_large_resident_hmac_secret_record(&record);
    record.resident_key = false;
    test_binding_open_vault();
    expect(!zf_store_bind_record(&record), "non-resident credentials are not bound");
}

static void test_binding_flag_survives_storage_format(void) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    ZfCredentialRecord record;
    ZfCredentialRecord decoded;
    size_t encoded_size = 0;

    test_storage_reset();
    fill_large_resident_hmac_secret_record(&record);
    expect(zf_store_record_format_encode(&record, buffer, &encoded_size),
           "encode unbound record");
    expect(test_zf_record_decode(buffer, encoded_size, k_repeated_credential_file_name, &decoded),
           "decode unbound record");
    expect(!decoded.bound, "unbound record decodes unbound");

    record.bound = true;
    expect(zf_store_record_format_encode(&record, buffer, &encoded_size), "encode bound record");
    expect(encoded_size <= sizeof(buffer), "bound record fits the record buffer");
    expect(test_zf_record_decode(buffer, encoded_size, k_repeated_credential_file_name, &decoded),
           "decode bound record");
    expect(decoded.bound, "bound flag survives encode/decode");
}

static void test_binding_policy_hides_bound_without_uv(void) {
    Storage storage = {0};
    ZfCredentialStore store = {0};
    ZfCredentialIndexEntry entries[ZF_MAX_CREDENTIALS] = {0};
    ZfGetAssertionRequest request = {0};
    uint16_t matches[ZF_MAX_CREDENTIALS];
    ZfCredentialRecord record;

    test_storage_reset();
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    store.records = entries;
    store.capacity = ZF_MAX_CREDENTIALS;
    fill_large_resident_hmac_secret_record(&record);
    strcpy(record.rp_id, "example.com");
    record.bound = true;
    expect(test_zf_store_add_record(&storage, &store, &record), "add bound record");
    expect(store.count == 1 && store.records[0].bound, "index entry carries the bound flag");
    strcpy(request.assertion.rp_id, "example.com");
    expect(zf_ctap_resolve_assertion_matches(&storage, &store, &request, false, matches) == 0,
           "bound credential is hidden without a PIN check");
    expect(zf_ctap_resolve_assertion_matches(&storage, &store, &request, true, matches) == 1,
           "bound credential is visible after a PIN check");
}

static void test_binding_unbind_all_rewrites_records(void) {
    Storage storage = {0};
    ZfCredentialStore store = {0};
    ZfCredentialIndexEntry entries[ZF_MAX_CREDENTIALS] = {0};
    ZfCredentialRecord record;
    ZfCredentialRecord loaded;
    uint8_t buffer[ZF_STORE_RECORD_IO_SIZE];

    test_storage_reset();
    store.records = entries;
    store.capacity = ZF_MAX_CREDENTIALS;
    fill_large_resident_hmac_secret_record(&record);
    strcpy(record.rp_id, "example.com");
    test_binding_open_vault();
    expect(zf_store_bind_record(&record), "bind before storing");
    expect(test_zf_store_add_record(&storage, &store, &record), "store bound record");

    zf_vault_lock();
    expect(!zf_store_unbind_all(&storage, &store), "unbind-all refuses with the vault locked");
    expect(zf_vault_unlock(test_pin_hash_1234()), "reopen vault for unbind-all");
    expect(zf_store_unbind_all(&storage, &store), "unbind-all with the vault open");
    expect(!store.records[0].bound, "index entry unbound");
    memset(&loaded, 0, sizeof(loaded));
    expect(zf_store_load_record_with_buffer(&storage, &store.records[0], &loaded, buffer,
                                            sizeof(buffer)),
           "reload unbound record");
    expect(!loaded.bound, "stored record unbound");
}

static void run_binding_tests(void) {
    test_binding_bind_unbind_roundtrip();
    test_binding_refuses_non_resident();
    test_binding_flag_survives_storage_format();
    test_binding_policy_hides_bound_without_uv();
    test_binding_unbind_all_rewrites_records();
}
