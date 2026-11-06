# ZeroFIDO tpm branch (FlipperPasskey), 2026-11-06: new file.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Look for a ZeroFIDO Bluetooth security key in the air (service 0xFFFD). Read-only.

    python host_tools/ble_scan.py [seconds]

Needs `pip install bleak`. Prints the name, signal strength and advertised services.
"""
import asyncio
import sys

from bleak import BleakScanner

FIDO = "0000fffd-0000-1000-8000-00805f9b34fb"


async def main(seconds):
    found = {}

    def seen(dev, adv):
        uuids = [u.lower() for u in (adv.service_uuids or [])]
        if FIDO in uuids or (adv.local_name or "").startswith("FIDO "):
            found[dev.address] = (adv.local_name, adv.rssi, adv.service_uuids)

    async with BleakScanner(seen):
        await asyncio.sleep(seconds)
    if not found:
        print("no FIDO Bluetooth device found (is ZeroFIDO open, cable unplugged?)")
        return 1
    for addr, (name, rssi, uuids) in found.items():
        print("found %s name=%r rssi=%s dBm services=%s" % (addr, name, rssi, uuids))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(float(sys.argv[1]) if len(sys.argv) > 1 else 8)))
