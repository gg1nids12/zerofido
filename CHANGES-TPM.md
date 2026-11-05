# Changes in the `tpm` branch

This branch is a modified version of [ZeroFIDO](https://github.com/MinorGlitch/zerofido)
(GPL-3.0-or-later, © Alex Stoyanov). Base: upstream commit `358ef94` (v0.8.0).
Changes are listed newest last, with dates, as GPL-3.0 section 5(a) requires.
New source files carry a note at the top; changes inside upstream files are marked with `tpm branch` comments.

## 2026-11-05

- `README.md`: work-in-progress banner (English and Russian).
- `CHANGES-TPM.md`: this file.
- `docs/TPM_HARDENING.md`: design notes for the TPM-like hardening.
- No application code changed in this entry.

## 2026-11-05 (later) — stage 1: PIN vault and PIN-bound passkeys

The PIN stays optional. Without a PIN everything works as upstream.

- New: `src/pin/vault.h`, `src/pin/core/vault.c` — PIN vault. A slow,
  device-bound stretch through the device-unique AES key, a KEK, a random
  passkey master key, and a PIN verifier. No PIN hash is stored.
- New: `src/store/binding.h`, `src/store/binding.c` — PIN binding of
  discoverable credentials (inner key layer, unbind-all).
- Modified:
  - `src/pin/core/retry.c`, `src/pin/client_pin/operations.c`: check the PIN
    through the vault.
  - `src/pin/core/plaintext.c`: setPin/changePin create or rewrap the vault.
  - `src/pin/core/lifecycle.c`: load and reconcile the vault; removing the
    PIN removes the vault.
  - `src/pin/core/token.c`: the PMK is wiped with the PIN token.
  - `src/pin/command.c`: keepalive during the stretch.
  - `src/zerofido_types.h`: `bound` flag; 10-character minimum PIN on the
    device.
  - `src/store/record_format.c`: record key 18 `bound`.
  - `src/zerofido_store.c`: index flag.
  - `src/zerofido_crypto.[ch]`: inner layer, rewrap, signing with the inner
    key.
  - `src/ctap/commands/make_credential.c`: bind passkeys created with a PIN
    check.
  - `src/ctap/response.c`, `src/ctap/extensions/hmac_secret.[ch]`: use the
    inner layer.
  - `src/ctap/policy.c`: bound credentials need a PIN check.
  - `src/transport/usb_hid_worker.[ch]`, `src/transport/adapter.[ch]`:
    processing keepalive.
  - `src/ui/views.c`: PIN removal unbinds passkeys; 10+ PIN hint; PMK wipe
    tick.
  - `src/app/lifecycle.c`: PMK wipe on exit.
- Tests:
  - New: `tests/native/protocol/subsystems/pin/vault_tests.inc`,
    `tests/native/protocol/subsystems/store/binding_tests.inc`.
  - Upstream PIN tests now send the real PIN hash, because the stored state
    is a verifier.

### Verification (2026-11-05)

- Host: all upstream suites pass (Python 75, 3 skipped for missing upstream
  docs; native crypto, protocol, transport/U2F with clang), plus the new
  vault and binding suites.
- Device (Flipper Zero, Momentum mntm-012, API 87.1; a test build with
  auto-accept, driven over USB HID by python-fido2):
  - 17/17 end-to-end checks: no-PIN register and sign-in; a short PIN is
    rejected (0x37); a 10+ PIN is set; a wrong PIN gives 0x31 and retries go
    8→7; a right PIN takes ~1.8–2.2 s.
  - A PIN-bound passkey signs with a PIN and is hidden without one (0x2E).
  - After changePin the old PIN fails and the bound passkey still signs.
  - 5/5 after an app restart: the vault, PIN and bound passkey persist.
  - U2F inside ZeroFIDO registers and authenticates.

