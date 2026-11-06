# ZeroFIDO tpm branch (FlipperPasskey), 2026-11-06: new file.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the ZeroFIDO Bluetooth transport from a Windows PC (after pairing).

    python host_tools/ble_ctap_test.py [bluetooth-address]

Needs `pip install bleak fido2`. Sends PING (echo), CTAP2 getInfo, a touch request that is
cancelled after 5 s, and an unknown command, over CTAP-over-BLE framing. Nothing is created
or changed and no OK press is needed. The Flipper must not be busy with a USB host.
"""
import asyncio
import os
import sys
import time

from bleak import BleakClient, BleakScanner
from fido2 import cbor

CP = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
STATUS = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
CPLEN = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"
REV = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"
PING, KEEPALIVE, MSG, CANCEL, ERROR = 0x81, 0x82, 0x83, 0xBE, 0xBF


def say(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def frames_for(cmd, data, size):
    frames = [bytes([cmd, len(data) >> 8, len(data) & 0xFF]) + data[: size - 3]]
    rest, seq = data[size - 3:], 0
    while rest:
        frames.append(bytes([seq]) + rest[: size - 1])
        rest, seq = rest[size - 1:], (seq + 1) & 0x7F
    return frames


async def main():
    dev = await BleakScanner.find_device_by_filter(
        lambda d, a: (a.local_name or d.name or "").startswith("FIDO "), timeout=8)
    if not dev and len(sys.argv) > 1:
        dev = sys.argv[1]  # a paired device that Windows keeps connected does not advertise
        say("not advertising; connecting to the given address")
    elif not dev:
        say("no ZeroFIDO Bluetooth device found (ZeroFIDO open, cable unplugged?)")
        return 2
    else:
        say("found %s, connecting" % (dev.name,))
    ok = True
    async with BleakClient(dev, timeout=20) as c:
        size = int.from_bytes(await c.read_gatt_char(CPLEN), "big")
        rev = (await c.read_gatt_char(REV))[0]
        say("fidoControlPointLength=%d, revisions=0x%02X" % (size, rev))
        await c.write_gatt_char(REV, bytes([0x20]), response=True)
        q = asyncio.Queue()
        await c.start_notify(STATUS, lambda _h, d: q.put_nowait(bytes(d)))

        async def send(cmd, data):
            for f in frames_for(cmd, data, size):
                await c.write_gatt_char(CP, f, response=True)

        async def receive(timeout=15):
            keepalives = 0
            while True:
                f = await asyncio.wait_for(q.get(), timeout)
                if f[0] == KEEPALIVE:
                    keepalives += 1
                    continue
                cmd, n, buf, seq = f[0], (f[1] << 8) | f[2], f[3:], 0
                while len(buf) < n:
                    g = await asyncio.wait_for(q.get(), timeout)
                    if g[0] != seq:
                        raise RuntimeError("bad sequence %d (expected %d)" % (g[0], seq))
                    buf, seq = buf + g[1:], seq + 1
                return cmd, buf[:n], keepalives

        payload = os.urandom(300)
        t0 = time.time()
        await send(PING, payload)
        cmd, data, _ = await receive()
        good = cmd == PING and data == payload
        ok &= good
        say("PING 300 bytes: %s, %.2f s" % ("echo matches" if good else "FAIL 0x%02X" % cmd,
                                             time.time() - t0))

        t0 = time.time()
        await send(MSG, bytes([0x04]))
        cmd, data, _ = await receive()
        good = cmd == MSG and data[:1] == b"\x00"
        ok &= good
        if good:
            info = cbor.decode(data[1:])
            say("getInfo: ok in %.2f s; versions %s, clientPin=%s, rk=%s" % (
                time.time() - t0, info.get(1), info.get(4, {}).get("clientPin"),
                info.get(4, {}).get("rk")))
        else:
            say("getInfo: FAIL cmd=0x%02X status=%s" % (cmd, data[:1].hex()))

        # Touch request like Windows' authenticator selection; cancelled, nothing created.
        req = bytes([0x01]) + cbor.encode({1: bytes(32), 2: {"id": ".dummy"},
                                            3: {"id": b"\x01", "name": "dummy"},
                                            4: [{"alg": -7, "type": "public-key"}],
                                            8: b"", 9: 1})
        await send(MSG, req)
        t0, keepalives, early = time.time(), 0, None
        while time.time() - t0 < 5:
            try:
                f = await asyncio.wait_for(q.get(), 0.5)
            except asyncio.TimeoutError:
                continue
            if f[0] == KEEPALIVE:
                keepalives += 1
            else:
                early = f
                break
        if early:
            ok = False
            say("touch request answered on its own after %.1f s: %s" % (time.time() - t0,
                                                                      early.hex()))
        else:
            await c.write_gatt_char(CP, bytes([CANCEL, 0, 0]), response=True)
            cmd, data, _ = await receive(5)
            good = cmd == MSG and data[:1] == b"\x2d"
            ok &= good and keepalives >= 10
            say("touch request: %d keepalives in 5 s, after CANCEL %s" % (
                keepalives, "KEEPALIVE_CANCEL (expected)" if good else data.hex()))

        await send(0x84, b"")
        cmd, data, _ = await receive()
        good = cmd == ERROR and data == b"\x01"
        ok &= good
        say("unknown command -> %s" % ("ERROR INVALID_CMD (expected)" if good else
                                        "UNEXPECTED 0x%02X %s" % (cmd, data.hex())))
    say("RESULT: %s" % ("all passed" if ok else "failures"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
