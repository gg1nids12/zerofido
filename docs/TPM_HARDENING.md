# TPM-like hardening for ZeroFIDO (work in progress)

Status: see *Status (2026-11-06)* below and `CHANGES-TPM.md`. Still a development
version — keep backup sign-in methods. Base: upstream ZeroFIDO v0.8.0 (commit `358ef94`).

The PIN is optional. Without a PIN ZeroFIDO behaves as upstream (press OK on the Flipper).
The protection below applies when a PIN is set.

## Status (2026-11-06)

Implemented and tested on a device: the PIN vault (F1), PIN-bound discoverable credentials
and hmac-secret (F2, F3), PIN removal that unbinds first (F8), USB keepalive during long work
(F10), 64 credentials (F6). Added after the review: the retry is stored before the check, a
stale vault mirror can no longer revive an old PIN, the stretch count is capped, the PMK
lifetime covers the OK wait, safer approval screen.

Different from the plan below:

- The PIN stays optional and discoverable credentials can be created without one (F5 is not
  enforced) — the owner wants "plug in, press OK" to work without a PIN.
- Minimum PIN length is the CTAP minimum (4); a longer device minimum made Windows loop.
- Names stay in clear on the SD card (F7 not done).
- NFC is off by default (F9 moot for now); Bluetooth LE for Windows was added instead
  ([BLUETOOTH.md](BLUETOOTH.md)).

Limits that software on this hardware cannot remove:

- No secure element, no secure boot: with the Flipper in hand, custom firmware can use the
  device key and try PINs at about one per second outside the retry counter. The PIN length is
  the real protection. A stolen SD card alone is useless.
- The retry counter lives on the SD card and can be rolled back together with the PIN state
  (F4).

## Goal

Use Flipper Zero as the only passkey authenticator, with key protection as close to a
TPM 2.0 as the hardware allows. Main scenario: the Flipper is lost or stolen. The finder
must not be able to extract credentials or learn the PIN, even with custom firmware.

## What the hardware gives

The STM32WB55 offers:

- a device-unique AES key in the radio core's key storage (the "unique" enclave slot). It
  cannot be read out, but any CPU1 code can load it into the AES peripheral;
- hardware AES and a hardware RNG.

It does not offer:

- a secure element or secure boot. The device accepts any firmware, including through DFU;
- storage that cannot be rolled back;
- a way to delete a key from the key storage (ST AN5185), so wipe-after-N-failures cannot be
  enforced in hardware;
- isolation between external apps (FAPs) and the enclave API.

## Weaknesses in v0.8.0 (physical-access attacker)

All of these need someone holding the device and able to run their own firmware or FAP.
The upstream README already says physical access changes the risk model.

- **F1. The PIN verifier is recoverable.** `client_pin_v2.bin` stores LEFT(SHA-256(PIN),16)
  encrypted only with the device key. Code that can use the device key recovers it. The PIN
  can then be guessed offline at SHA-256 speed, with no salt and no stretching. The verifier
  also stays in RAM for the whole app session.
- **F2. Credential keys are not bound to the PIN.** `private_wrapped` is AES under the device
  key only.
- **F3. The same applies to hmac-secret** (`credRandom`).
- **F4. The PIN retry state can be rolled back** by restoring an older copy of the whole file.
  The seal only detects field splicing.
- **F5. Discoverable credentials can be created when no PIN is set.**
- **F6. Store capacity is 32 records**, discoverable and non-discoverable together.
- **F7. RP IDs and user names are stored in clear** on the SD card.
- **F8. On-device PIN removal** must take bound credentials into account.
- **F9. The iOS NFC path processes CTAP synchronously** (`send_ctap2_direct`), so long work
  there may time out.
- **F10. USB long work sends no keepalive.** Keepalives are only sent while waiting for a
  button press.

## Design (stage 1)

### Keys

```
DUK      device-unique enclave key (not extractable)
pinHash  LEFT(SHA-256(PIN),16), as sent by the platform over CTAP
S        Stretch(pinHash, salt, N): sequential AES-CBC chain under DUK, N steps.
         It can only be computed on this device.
KEK      HKDF-SHA256(salt, S || pinHash, "zerofido-kek-v1")
PMK      random 32-byte passkey master key
K_rec    HKDF-SHA256(PMK, credential_id, "zerofido-cred-v1")
```

- `vault.bin` holds: magic, version, salt, N, IV, AES-256-CBC(KEK, PMK), and
  HMAC-SHA256(KEK, everything before it). It is written atomically.
- A PIN is correct only if the MAC verifies. No PIN verifier is stored anywhere (fixes F1).
- The DUK chain keeps every guess on the device, at about one second per guess.
- N is calibrated on hardware and stored in the vault, so it can be raised later.

### What gets bound

- Discoverable credentials: the private key is DUK-wrap(AES-256-CBC(K_rec, key)). hmac-secret
  is wrapped the same way (fixes F2 and F3).
- A new record field `Bound` marks these records. Their effective credProtect is
  UV_REQUIRED, so the existing policy hides them without UV.
- Non-discoverable (second-factor) credentials stay DUK-only, because relying parties may
  not ask for UV.
- Stage 1b encrypts the names (F7) and keeps an RP ID hash for lookup.

### PMK lifetime

- The PMK is unlocked by a successful `getPinToken` or `getPinUvAuthToken…`.
- One copy lives in RAM. It is wiped when the token expires (30 s), after the operation,
  on app exit, on transport stop, on reset, and when the PIN is blocked.

### PIN operations

- **setPin** creates the PMK and the vault, and rebinds any legacy discoverable records.
- **changePin** unlocks with the old PIN, then rewraps only the vault, so the change
  cannot leave records half-converted.
- **Removing the PIN** also removes the bound credentials, after confirmation (F8).
- **The retry counter stays.** The comment that overstates its protection is corrected (F4).
- **Minimum PIN length** is 10. This needs testing for how platforms report the policy
  error.

### Creation policy

- A discoverable credential needs a PIN that is set plus pinAuth. Otherwise the request is
  refused and a hint is shown on screen (F5).

### Transport

- **USB (F10):** stretch in slices of about 50 ms, sending
  CTAPHID_KEEPALIVE(PROCESSING) and honouring CANCEL between slices.
- **iOS NFC (F9):** measure the timing first. If about 1 s does not fit, either shorten the
  stretch and require stricter PINs, or unlock on the device before tapping.

### Other

- Raise capacity to 64–128 records after measuring memory (F6).
- Optionally use deterministic ECDSA (RFC 6979) so signing does not depend on the RNG.
- Store format version 2. Old records stay readable. A downgrade cannot read bound records.

## Later stages

- **2.** Dedicated firmware build: ZeroFIDO built in, external apps, Bluetooth and USB file
  access disabled.
- **3.** Sealing on a dedicated device: signed-only updates, debug and DFU disabled. This is
  irreversible and needs a review of what happens to the key storage first.
- **4.** Research only: a Windows 11 third-party passkey provider backed by the Flipper.

## Testing

- **Host:** the upstream suites, plus new tests for the vault (create, right and wrong PIN,
  change, corruption), bound record round-trip, refusing to create discoverable credentials
  without a PIN, and the PMK wipe timer.
- **Device:** calibrate N; test webauthn.io in Chrome, Edge and Firefox on Windows; test
  iPhone and Android over NFC.
