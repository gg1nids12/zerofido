# Bluetooth LE transport (tpm branch)

ZeroFIDO in this fork speaks CTAP2 over Bluetooth Low Energy, as defined in the CTAP 2.x
specification ("Bluetooth Smart / Bluetooth Low Energy Technology"). Windows 10/11 uses paired
Bluetooth security keys for WebAuthn; that is the target. Android and iOS browsers do not use
Bluetooth security keys.

Sources: `src/transport/ble_link.[ch]` (profile, GATT, pairing, reassembly),
`src/transport/ble_worker.[ch]` (requests, keepalive, cancel), the automatic transport choice
in `src/ui/views.c` (`zerofido_auto_transport_tick`).

## Profile

While ZeroFIDO runs it replaces the Flipper's default Bluetooth profile (the mobile-app serial
profile) and restores it on exit (`bt_profile_restore_default`).

- Advertising: name `FIDO <Flipper name>`, 16-bit service UUID `0xFFFD` (FIDO), connectable.
  The Bluetooth address is derived from the Flipper's own (byte 2 XOR `0xF1`), so Windows keeps
  this pairing apart from the mobile-app one.
- Pairing: LE Secure Connections with MITM, numeric comparison (IO capability DisplayYesNo).
  The Flipper firmware shows *Verify code* with Cancel/OK; the PC shows the same code. Bonds
  are stored in the app data folder (`.bt_fido.keys`), separate from the system bonds.
- FIDO service `0xFFFD`:

  | Characteristic | UUID | Properties | Security |
  |---|---|---|---|
  | fidoControlPoint | `F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB` | write | authenticated write |
  | fidoStatus | `F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB` | notify | — (notifications go over the encrypted link) |
  | fidoControlPointLength | `F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB` | read | authenticated read |
  | fidoServiceRevisionBitfield | `F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB` | read, write | authenticated |

  The revision bitfield offers `0x20` (FIDO2 only; legacy U2F is off in this fork).
- Device Information service `0x180A`: manufacturer `ZeroFIDO dev`, model
  `Flipper Zero FIDO2`, firmware `tpm-dev`.

## Framing

Requests and responses use the CTAP BLE frames: an initial frame `CMD | HLEN | LLEN | data`
and continuation frames `SEQ | data` (SEQ 0x00–0x7F). Commands: `PING 0x81`, `KEEPALIVE 0x82`,
`MSG 0x83` (CTAP2 command byte + CBOR), `CANCEL 0xBE`, `ERROR 0xBF`.

- Fragment size = negotiated ATT MTU − 3, capped at 240 bytes (one HCI event or command with
  headers); 20 bytes until the MTU exchange. `fidoControlPointLength` follows it.
- Requests up to 1024 bytes. Bad length → `ERROR 0x03`, unknown command → `0x01`, wrong
  sequence → `0x04`, continuation stalled for 3 s → `0x05`.
- While a command runs, the Flipper sends `KEEPALIVE` every 300 ms: `0x01` (processing, e.g.
  the PIN vault stretch) or `0x02` (waiting for OK). `CANCEL` aborts the command with CTAP status
  `0x2D`; a disconnect cancels it too.
- Reassembly runs on the Bluetooth event thread into a buffer owned by the link, so a request can
  arrive while USB is the active transport. The link is marked idle before a reply is sent:
  Windows sends the next request as soon as it sees a reply.

## Choosing the transport

- No cable → Bluetooth worker (idle until a request).
- Cable in a PC → USB HID worker.
- A complete Bluetooth request switches to Bluetooth at once, except while a PC is using the USB
  key (USB link awake): Windows may ask every authenticator at once, and the switch would stop a
  USB sign-in midway. A Bluetooth request that nobody takes expires after 5 s.
- After 10 s without Bluetooth traffic the cable rule applies again. No switch happens while a
  request waits for OK.

## Diagnostics

The service trace (`/ext/apps_data/zerofido/trace.txt`, flag `ZEROFIDO_TRACE`) records codes
only — no addresses, no data:

- `BLE link conn=… up=… enc=… pair=status/reason mtu=… notify=… rev=… writes=… disc=reason`
- `BLE cmd=<CTAP cmd> len=… status=<CTAP status> out=… ms=…`
- `AUTO mode=usb|ble ok=… free=… maxblk=…`

`host_tools/ble_scan.py` looks for the advertising, `host_tools/ble_ctap_test.py` checks PING,
getInfo, a touch request with CANCEL and an unknown command over Bluetooth from a paired
Windows PC (no OK press needed, nothing is created).

## Verified (2026-11-05/06, Momentum mntm-012, Windows 11)

- Pairing from Windows Settings with the code confirmed on the Flipper; Windows enumerates the
  FIDO service (protection level: encryption and authentication).
- `host_tools/ble_ctap_test.py`: PING 300 bytes in 2 fragments, getInfo, 18 keepalives in 5 s
  while waiting for OK, CANCEL → `0x2D`, unknown command → `ERROR 0x01`.
- Registration on webauthn.io over Bluetooth without the cable, with a PIN entered on the PC
  and OK on the Flipper: PIN check 1.9 s, credential created (rk, uv).
