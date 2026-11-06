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

## 2026-11-05 — device feedback: OK button, PIN length, U2F-like screens

- `4fc2c40` `src/ui/approval_state.c`: OK approves (was Right); Left/Back deny.
  `src/zerofido_types.h`: minimum PIN length back to the CTAP minimum of 4 — a longer device
  minimum made Windows loop between "enter PIN" and "reinsert the key".
  New `src/zerofido_trace.[ch]`: service trace with command codes, status codes and timings
  only (`/ext/apps_data/zerofido/trace.txt`, capped).
- `b87f087` `src/ui/status.[ch]`, `src/ui/views.c`, `src/ui/approval_state.c`,
  `src/zerofido_app_i.h`, `src/zerofido_ui_i.h`: home and approval screens in the style of
  the Flipper U2F app (the passkey list is one press of Down away).
- `3b2c244` `src/pin/core/retry.c`: no SD write on a PIN success when nothing changed;
  timings in the trace (`src/pin/command.c`, CTAP commands).

## 2026-11-05 — one app, automatic transport

- `0cefb5f` `application.fam`: separate USB and NFC app names (interim).
- `c50346b` `src/ui/views.c`, `src/app/lifecycle.[ch]`: one app; USB with the cable (VBUS),
  NFC without, switched at runtime without saving, never during an approval.

## 2026-11-05 — size and isolation

- `6cfc1f6`
  - `application.fam`: `ZEROFIDO_U2F` and `ZEROFIDO_PACKED_ATTESTATION` build flags, both
    off by default (the Flipper's built-in U2F app is separate and untouched).
  - New `src/zerofido_u2f_stub.c`: adapter stubs; U2F APDUs answer "not supported".
  - `src/zerofido_attestation.c`: all-zero AAGUID without attestation.
  - `src/zerofido_types.h`: 64 credentials (was 32).
  - `src/pin/core/vault.c`, `src/pin/vault.h`: second copy `vault.mirror`; a damaged primary
    falls back to it and is repaired.
  - Tests: mirror fallback; manifest test follows the branch defaults.

## 2026-11-05 — Bluetooth LE transport for Windows

- `f9cd5e0` New `src/transport/ble_link.[ch]`, `src/transport/ble_worker.[ch]`: CTAP over
  BLE (FIDO service `0xFFFD`, Device Information, numeric-comparison pairing, own bond file,
  reassembly on the BLE thread, keepalive, CANCEL). Modified `src/transport/adapter.[ch]`,
  `src/app/lifecycle.c` (profile up while the app runs, default profile restored on exit),
  `src/ui/views.c` (a BLE request switches to the BLE worker; back after 10 s idle),
  `src/ui/status.c`, `src/zerofido_runtime_config.[ch]` (runtime-only BLE mode),
  `src/zerofido_types.h`, `src/zerofido_app_i.h`, `application.fam` (`ZEROFIDO_BLE`).
  Details: [docs/BLUETOOTH.md](docs/BLUETOOTH.md).
- `93dcc7b` `src/transport/ble_worker.c`: the link is marked idle before the reply (Windows
  sends the next request at once; it was dropped). `src/zerofido_notify.c`: when OK is needed,
  4 vibration pulses over ~3 s and a blue blinking LED until the request is answered.

## 2026-11-05 — NFC debugging aids

- `b9a96d4` `application.fam`, `src/ui/views.c`: `ZEROFIDO_NFC_LAB` lab build stays in NFC
  with the cable in.
- `814576e` New `src/transport/nfc_xlog.[ch]`; hooks in `src/transport/nfc_dispatch.c`,
  `nfc_iso_dep.c`, `nfc_engine.c`, `nfc_session.c`, `nfc_worker.c`, `nfc_trace.h`,
  `src/ui/views.c`: light NFC exchange log (APDU headers, status words, events, timings; no
  data) written to the trace after the phone leaves. `src/zerofido_trace.c`: cap 16 KB.

## 2026-11-05 — code review fixes

- `d39824b`
  - `src/pin/core/retry.c`: CTAP order — one retry is stored as used before the ~1 s vault
    check and restored on success; a power cut during the check no longer hides a wrong guess.
  - `src/pin/core/vault.c`, `src/pin/vault.h`, `src/pin/core/lifecycle.c`: the verifier in
    the sealed PIN state names the current vault, so a mirror left from before a PIN change is
    never used; a mirror that fails to update is removed; stretch count capped at 8x default;
    PMK lock/tick/use in short critical sections; `zf_vault_touch()`.
  - `src/pin/core/token.c`: a request that proves the PIN token restarts the PMK lifetime, so
    it lasts through that request's OK wait.
  - `src/ui/approval_state.c`: long site names cut at the start (the registrable domain stays
    visible); OK ignored for 0.4 s after a request appears.
  - `src/transport/ble_link.c`, `src/ui/views.c`: BLE does not take over while a PC uses the
    USB key; stale BLE requests expire after 5 s.
  - Tests: stale mirror, huge stretch count, retry stored before the check
    (`tests/native/protocol/subsystems/pin/vault_tests.inc`, `tests/native/include/furi.h`).
- `47f9f30` `src/ui/views.c`: comment for the USB-awake rule.

## 2026-11-06 — NFC off by default, docs, tools

- `8326ee5` `application.fam`, `src/zerofido_types.h`, `src/transport/adapter.[ch]`,
  `src/app/lifecycle.c`, `src/zerofido_runtime_config.c`, `src/ui/views.c`,
  `src/ui/status.c`: NFC compiled out of the universal build by default (`ZEROFIDO_NFC=1`
  restores it); no cable means Bluetooth. Code 81.4 → 68.9 KB.
- `application.fam`: `ZEROFIDO_TRACE` flag for the service trace.
- `README.md`: fork overview, installation (English and Russian), Bluetooth pairing, security
  notes, build flags. New `docs/BLUETOOTH.md`. `docs/TPM_HARDENING.md`: status section.
- New `host_tools/ble_scan.py`, `host_tools/ble_ctap_test.py`: Bluetooth checks from a PC.

### Verification (2026-11-05/06, Momentum mntm-012, Windows 11)

- Host: native crypto, protocol (with the new vault/PIN tests) and transport/U2F suites pass
  with clang; the retry-before-check test fails without the fix.
- Device: Windows registration and sign-in over USB with the PIN on the PC (passkeys.io,
  webauthn.io); pairing and registration over Bluetooth without the cable;
  `host_tools/ble_ctap_test.py` passes; USB getInfo after every install.
- NFC with Android: the phone never selected the FIDO applet in two attempts (only Android's
  own NDEF probing); NFC is off by default since then.
