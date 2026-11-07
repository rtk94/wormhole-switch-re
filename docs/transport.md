# Transport: USB / SCSI / HID

Observed 2026-11-06 on host rich. Two enumerations were captured:

1. Bus 005 Device 003 (port 3) — single-end connection.
2. Bus 003 Device 015 (port 1, `3-1`) — after moving the peer end into a second machine and replugging this end into a different port.

Descriptors were identical between the two ports. What follows applies to both.

## Device identity

```
Bus 005 Device 003: ID 0711:2211 Magic Control Technology Corp. WormholeSwitch
  bcdUSB 2.00, bDeviceClass 0 Unknown
  idVendor 0x0711 Magic Control Technology Corp.
  idProduct 0x2211 WormholeSwitch
  bcdDevice 1.00
  iManufacturer 1 j5create
  iProduct 2 WormholeSwitch
  iSerial 3 C6629C6563582530
  bNumConfigurations 1
```

- Negotiation: High Speed 480M.
- Configuration: `wTotalLength 0x0052` (82 B), `bNumInterfaces 3`, `bConfigurationValue 1`, `bmAttributes 0x60` (Self Powered + Remote Wakeup, missing must-be-set bit 7 — `lsusb` warns), `MaxPower 10mA`.

Sysfs (example at `5-3`, later `3-1`):

```
/sys/bus/usb/devices/5-3/{bcdDevice=0100, idVendor=0711, idProduct=2211,
  product=WormholeSwitch, manufacturer=j5create, serial=C6629C6563582530,
  busnum, devnum, devpath=3, speed=480, version=2.00}
```

Report-descriptor fetch via `lsusb -v` returns `** UNAVAILABLE **` in this environment (control fetch stalls) — descriptors were read from sysfs instead (see HID below).

## Interfaces

| If | Class/Sub/Proto | Endpoints | Driver | Host mapping |
|----|-----------------|-----------|--------|--------------|
| 0 | 08 Mass Storage / 06 SCSI / 80 Bulk-Only | EP1 IN Bulk 512 B, EP2 OUT Bulk 512 B | `usb-storage`, `sg` | `/dev/sr2` (first plug), later `/dev/sr1`, `/dev/sg6` → `/dev/sg2`; SCSI target `host5/target5:0:0/5:0:0:0` then `host4/target4:0:0/4:0:0:0` |
| 1 | 03 HID / 01 Boot / 02 Mouse | EP3 IN Interrupt 8 B, `bInterval 1` ms | `usbhid` → `hid-generic` | `hidraw6` (`0003:0711:2211.0009`), `input25`, then `hidraw0`, `mouse0`/`event2` |
| 2 | 03 HID / 01 Boot / 01 Keyboard | EP4 IN Interrupt 8 B, `bInterval 4` ms | `usbhid` → `hid-generic` | `hidraw7` (`0003:0711:2211.000A`), `input26`, then `hidraw1`, `event3` |

Full configuration bytes (hex, from usbmon control-complete):

```
09 02 52 00 03 01 00 60 05
09 04 00 00 02 08 06 50 00
07 05 81 02 00 02 00
07 05 02 02 00 02 00
09 04 01 00 01 03 01 02 00
09 21 00 01 00 01 22 34 00
07 05 83 03 08 00 01
09 04 02 00 01 03 01 01 00
09 21 00 01 00 01 22 43 00
07 05 84 03 08 00 04
```

## SCSI: fake CD-ROM

`sg_inq` (stable across replugs):

```
PQual=0  PDT=5 (cd/dvd)  RMB=1  version=0x00 [no conformance claimed]
  NormACA=1  HiSUP=1  Resp_data_format=2  length=36
Vendor: j5create
Product: WormholeSwitch
Revision: 2.00
```

The `version=0x00` with no conformance claim is unusually minimal — custom firmware faking SCSI rather than a full SBC implementation.

`sg_vpd` fails: *Malformed SCSI command response*. No VPD pages returned.

`READ CAPACITY(10)` (`opcode 0x25`):

```
Last LBA=1592 (0x0638), Number of logical blocks=1593
Logical block length=2048
Size: 3262464 bytes (3.1 MiB)
Raw: 00 00 06 38 00 00 08 00
```

`READ CAPACITY(16)` (`opcode 0x9E sa 0x10`):

```
SCSI Status: Check Condition
Sense: Illegal Request / Invalid command operation code
```

`LOG SENSE (0x4A)` — kernel polls it about every 2 s when the device is idle (see `docs/capture-log.md`):

```
CBW: 4A 01 00 00 10 00 00 00 08 00  (10-byte CDB)
→ CHECK CONDITION → REQUEST SENSE (0x03) data:
  70 00 05 00 00 00 0A 00 00 00 20 ...
  = sense key 0x05 Illegal Request, ASC 0x20 Invalid command operation code
```

**Capacity anomaly:** `sg_readcap` consistently reports 3.1 MiB, but Linux exposes `/sys/block/srX/size = 31744` (512 B sectors) = 16252928 B (15.5 MiB) and automounts a 15.5 MiB ISO9660 volume labelled `WORMHOLE` (`file -s /dev/sr2: ISO 9660 CD-ROM 'WORMHOLE'`, `lsblk` `sr1 15.5M /media/rich/WORMHOLE`). Kernel block size and device-reported capacity do not agree. `READ CAPACITY(16)` is unsupported, so the kernel fallback is not observable from `sg` alone — flagged as unknown.

Iso content at `/media/rich/WORMHOLE` is byte-identical to the first `/tmp/wormhole_mnt` dump (see `docs/iso-payload.md`).

## HID report descriptors (sysfs)

Read via `/sys/class/hidraw/hidrawX/device/report_descriptor`:

- **Mouse (`hidraw6`/`hidraw0`, 52 B):**
  ```
  0501 0902 a101 0901 a100 0509 1901 2903 1500 2501 9503 7501 8102
  9501 7505 8101 0501 0930 0931 0938 1581 257f 7508 9503 8106 c0 c0
  ```
  Generic Desktop Mouse → Application + Physical collections, 3 buttons, 8-bit signed X/Y/Wheel.

- **Keyboard (`hidraw7`/`hidraw1`, 67 B):**
  ```
  0501 0906 a101 0507 19e0 29e7 1500 2501 7501 9508 8102 7508 9501
  8101 1900 2aff00 1500 26ff00 7508 9506 8100 0508 1901 2905 1500
  2501 7501 9505 9102 7503 9501 9101 c0
  ```
  Generic Desktop Keyboard → Application collection, 8 modifiers, 1 constant byte, 6 key codes (0x00-0xFF), then a Usage Page 0x08 (LEDs) Output section.

Both HID devices report `Uniq=C6629C6563582530` (same as USB serial) and `Name=j5create WormholeSwitch`.

## Peer link: vendor SCSI CDB packets (host → cable)

Host software does **not** use the boot-HID endpoints to talk to the
cable. It sends vendor SCSI commands whose **16-byte CDB is the packet**
(governed by `OTiTransporter::sendHIDPacket` /
`SendSCSICommandSendData` in `OTiTransfer.framework` — see
`docs/mac-gobridge.md` for the full decompiler trail):

```
byte 0    0xD9  (magic)
byte 1    '3' = mouse (type 1) | '4' = keyboard (type 2) | '6' = multimedia/key (type 3)
bytes 2–13  12-byte HID payload
bytes 14–15 'O' 'T'
```

Sent via `SCSITask` (`ExecuteTaskSync`, 2000 ms timeout); sense
`(key<<16 | ASC<<8 | ASCQ)` is mapped to OTi result codes.
The cable microcontroller forwards the packet to the peer end, whose
host software replays it as a CGEvent (macOS) / HID report (Windows).
File/clipboard traffic uses the same SCSI plumbing with a data phase;
its packet magic has not been captured yet.

This only appears on the wire when Wormhole/GoBridge software is
actively transferring — the idle capture in `docs/capture-log.md`
shows only kernel CDBs, which is consistent.

### Multimedia (`'6'`) packets — payload layout undetermined

Type `'6'` (multimedia/key, type 3) exists in the framing above and is
implemented end-to-end in the macOS software: `CKMEvent` maps the
system-defined multimedia events (CGEvent type 14, subtype 8) to
`SendMultimediaKeyEvent(this, 2, usage, 0)` → `KMMainLoop
sendMultimediaKeyData:` → `postMultimediaHIDEventToRemote:` (0x1bccb) →
`OTi_SendHIDPacket(3, …)` (see `docs/mac-gobridge.md`). The keys routed
this way are Eject `0xb8`, Play `0xcd`, Next `0xb5`, Prev `0xb6`, Fast
`0xb3` and Rewind `0xb4`; the other consumer-ish usages (Sound
`0x80`/`0x81`, Brightness `0x48`/`0x47`, Power `0x66`, Mute `0x7f`) go
through the *keyboard* path (`'4'`, usage at payload byte 2) instead, so
they replay on peer EP4.

What is **not** known is the 12-byte wire payload for `'6'`: none of the
committed captures contains a `'6'` frame (no `d9 36` in any pcap), and
the decompilation records only the call signature above — the byte
positions of the press/release flag and the usage are unknown until a
packet is captured, so the parser reports the payload raw (`payload_hex`)
and no layout is assumed anywhere. For type-3 packets
`OTiTransporter::sendHIDPacket` logs `key HID: <first 8 payload bytes>`,
so a live macOS GoBridge session with a real media-key press pins the
layout directly. Forwarding is verified byte-for-byte for `'3'`/`'4'`
only (`docs/live-capture-2026-11-06.md`); whether the cable forwards
`'6'` at all, and which peer endpoint or usage it synthesises (neither
HID report descriptor declares a Consumer page `05 0C`), is open. To
probe cable acceptance without presupposing a layout, send an all-zero
`'6'` frame per `docs/reproduction.md` §6.5.

### Parser support (`tools/wormhole_parse.py`)

The parser decodes both directions (verify with the live-capture
runbook in `docs/reproduction.md` §6):

- **Host → cable (bulk):** any bulk CBW whose CDB starts with `0xD9`
  is reported as `WORMHOLE VENDOR HID (0xD9)` with `hid_type`
  (`mouse`/`keyboard`/`multimedia`), the 12-byte `payload_hex`
  (bytes 2–13), `footer_hex`/`footer_ok` (`OT`), and
  `valid_hid_framing`.  Summary counts are in `vendor_hid_packets` /
  `vendor_hid_types` per device and `total_vendor_hid_packets`
  overall.  Non-`0xD9` CDBs in the SPC vendor range (`0xC0`–`0xFF`)
  are flagged `candidate_upipe` with raw hex so a UPipe / file /
  clipboard packet can be characterised from a live capture.
- **Cable → host (interrupt):** interrupt IN COMPLETEs on EP3 are
  decoded as boot-mouse reports (byte 0 buttons, bytes 1–3 signed
  X/Y/wheel) and EP4 as boot-keyboard reports (byte 0 modifiers,
  byte 1 constant, bytes 2–7 USB HID key codes).  `parse_hid_reports()`
  returns decoded dicts; the CLI prints a `HID interrupt reports`
  section (use `--hid` for a longer list).

Verify the idle sample still shows zeros:

```sh
python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap
# Vendor HID (0xD9) packets: 0  candidate UPipe: 0  HID reports: 841
# 3:15 row: ... 42  0  0  <-- WormholeSwitch
python3 -m unittest tools.test_wormhole_parse   # 42 tests incl. vendor/HID
```

## Bus neighbours on this host (for topology context)

VyVPN router / VIA hub neighbours changed between plugs; at the second enumeration Bus 3 held:

- 3:15 Wormhole (`0711:2211`)
- 3:14 IronKey S200 (`1953:0202`, 196M `sr3`)
- 3:5 / 3:7 Logitech Bolt receivers (`046d:c548`) behind VIA VL813 hub (`2109:2813`)

The IronKey Personal (`1953:1001`) seen on the first enumeration was not present on the second. The second machine's USB bus is not visible from this host's agent scope.
