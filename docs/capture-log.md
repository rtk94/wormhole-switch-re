# Capture log: usbmon

## Method

```sh
sudo modprobe usbmon
sudo tcpdump -i usbmon3 -w /tmp/wormhole_bus3.pcap   # Bus 3 at second plug
```

Then interact: `sg_inq /dev/sg2`, `sg_readcap /dev/sg2`, `dd if=/dev/sr1 bs=512 count=16`.

- `capinfos`: 2298 packets, 199 kB, 29.03 s, 2026-11-06 10:58:43.901301 → 10:59:12.933645, encapsulation USB with Linux header and padding (115, usb-linux-mmap), SHA-256 `fff7d587ab317d5fb2cb40c194347ba40ffb6aa4b7847fd4cba02e0eb3d1c97f`, SHA1 `e0aa43c85d2bf97c01e0d3ea51d3e54241829d99`.
- File preserved: `captures/wormhole_bus3_2026-11-06.pcap` + `wormhole_bus3_capinfos.txt`.
  > NOTE (#17, 2026-11-08): the on-disk capture is now the Wormhole-only
  > (3:15, 250 packets / 22 kB) filtered subset; the committed original (2,298
  > packets) also contained IronKey `3:14` + Logitech `3:7` bus traffic. Wormhole
  > transaction counts below are unchanged; frame numbers and packet totals
  > refer to the original mixed capture. See `docs/issue-17-sanitise-history.md`.

`tcpdump`Completion: `2298 packets captured, 0 dropped by kernel` — analysis stands without relying on later capture.

## Enumeration (first 3 control URBs, Bus 3 Dev 15)

```
USB CONTROL SUBMIT/COMPLETE to 3:15:0
  Device Descriptor: 12 01 00 02 00 00 00 40 11 07 11 22 00 01 01 02 03 01
    = bLength 18, USB 2.00, class 0, VID 0711, PID 2211, bcdDevice 0100,
      iManufacturer 1, iProduct 2, iSerial 3, 1 configuration
USB CONTROL SUBMIT/COMPLETE to 3:15:0
  Config (short):    09 02 52 00 03 01 00 60 05
USB CONTROL SUBMIT/COMPLETE to 3:15:0
  Config (full 82 B): 09 02 52 00 03 01 00 60 05 09 04 00 00 02 08 06 50 00
    07 05 81 02 00 02 00 07 05 02 02 00 02 00
    09 04 01 00 01 03 01 02 00 09 21 00 01 00 01 22 34 00 07 05 83 03 08 00 01
    09 04 02 00 01 03 01 01 00 09 21 00 01 00 01 22 43 00 07 05 84 03 08 00 04
  = wTotalLength 0x0052, 3 interfaces, bmAttributes 0x60, MaxPower 5 (10mA)
```

Matches `lsusb -v` at both ports.

## Bulk-Only: CBW / CSW

Bulk endpoints: **EP2 OUT** (`to 3:15:2`, CBW OUT) and **EP1 IN** (`from 3:15:1`, DATA IN + CSW). 244 bulk sub/complete lines for Wormhole (3:15) in the capture; 0 INTERRUPT lines for Wormhole.

Example transaction pair (≈ every 2 s when idle):

```
10:58:44.466581 USB BULK SUBMIT to 3:15:2
  55 53 42 43 F1 01 00 00 08 00 00 00 80 00 0A 4A 01 00 00 10 00 00 00 08 00
  = USBC CBW Tag 0x01F1, len 8, IN, LUN 0, CDB 10 B: 4A GET EVENT STATUS NOTIFICATION
10:58:44.467259 USB BULK COMPLETE from 3:15:1
  55 53 42 53 F1 01 00 00 00 00 00 00 01
  = USBS CSW Tag 0x01F1, residue 0, status 0x01 (CHECK CONDITION)

10:58:44.467264 USB BULK SUBMIT to 3:15:2
  55 53 42 43 F2 01 00 00 12 00 00 00 80 00 06 03 00 00 00 12 00
  = USBC Tag 0x01F2, CDB 6 B: 03 REQUEST SENSE, alloc 0x0012
10:58:44.467643 USB BULK COMPLETE from 3:15:1
  70 00 05 00 00 00 0A 00 00 00 20 00 00 00 00 00
  = Fixed sense: key 0x05 Illegal Request, ASC 0x20 Invalid command operation code
10:58:44.467803 USB BULK COMPLETE from 3:15:1
  55 53 42 53 F2 01 00 00 00 00 00 00 00
  = USBS status 0x00 (good)
```

Same pair repeats with incrementing tags (`F3/F4`, `F5/F6`, …) every ≤2 s — kernel GET EVENT STATUS NOTIFICATION polling against unsupported opcode.

## SCSI opcode histogram (parsed CBWs, 98 total on Bus 3)

Mixed Bus 3 traffic (Wormhole 3:15 + IronKey 3:14 + others). Wormhole-only tags are 497-506+ in this window (`F1 xx` little-endian). Overall:

```
0x00 TEST UNIT READY: 18
0x03 REQUEST SENSE: 44
0x12 INQUIRY: 2
0x25 READ CAPACITY(10): 1
0x43 READ TOC/PMA/ATIP: 2
0x46 GET CONFIGURATION: 1
0x4A GET EVENT STATUS NOTIFICATION: 30
```

Wormhole-specific in this window (`tools/wormhole_parse.py`): GET EVENT STATUS NOTIFICATION (16) + REQUEST SENSE (16) loop, plus the single INQUIRY (2, standard + EVPD) + READ CAPACITY(10) (1) pair driven by `sg_inq`/`sg_readcap` + `dd` at 10:58:44-46, TEST UNIT READY (4), and the kernel's CD-ROM probes READ TOC/PMA/ATIP (2, `43 00…` / `43 02…`) and GET CONFIGURATION (1, `46 00…`) at frames 1385-1402. IronKey 3:14 accounts for the remaining TEST UNIT READY (14), REQUEST SENSE (28) and GET EVENT STATUS NOTIFICATION (14); it issues no `0x43`/`0x46` in this window.

READ CAPACITY(16) (`0x9E`) failed live (`sg_readcap --16` → Invalid opcode) — not emitted by the kernel in this window because the Linux `sr` driver sizes the disc with READ CAPACITY(10) plus `cdrom_get_last_written()` and does not issue READ CAPACITY(16) (see `docs/capacity-anomaly.md`). The live `sg_raw` READ CAPACITY(10) response (`00 00 06 38 00 00 08 00`) matches `sg_readcap`.

## HID idle

0 interrupt completions to `3:15` in the 29 s capture. Interrupt traffic present on Bus 3 belongs to Logitech receivers (`3:7`), not the Wormhole. This is consistent with: peer machine connected but no Wormhole/GoBridge input-sharing session driving EP3/EP4, so no 8 B interrupt reports arrive at this host.

## REA note

`inspect_pcap_capture` / `inspect_packet_capture` were not used — `inspect_pcap_client` returned:

```
capability_unavailable: tshark was not found in an absolute PATH entry
```

`capinfos` is present (Wireshark 4.4.19), `tshark` is not. Capture was analyzed with `tcpdump -v -X`, `capinfos`, and a Python pcap parser above. Installing `wireshark-common` (provides `tshark`) would unblock the REA pcap path.

## Parser verification

`tools/wormhole_parse.py` (stdlib only) reproduces every count above
from `captures/wormhole_bus3_2026-11-06.pcap`:

```sh
python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap
python3 -m unittest tools.test_wormhole_parse
```

It discovers the Wormhole by VID:PID (`0711:2211`) from control
enumeration rather than a hard-coded Bus:Device, pairs CBW → data →
CSW per device (42 Wormhole transactions: GET EVENT STATUS NOTIFICATION 16, REQUEST SENSE
16, TEST UNIT READY 4, INQUIRY 2, READ CAPACITY(10) 1, READ
TOC/PMA/ATIP 2, GET CONFIGURATION 1), and confirms 0 interrupt
packets for 3:15 (all 1682 interrupt packets are Logitech 3:7).
It also decodes the Wormhole vendor HID protocol (`0xD9` CDBs) and
boot HID reports — in this idle capture both counts are zero for
`3:15` (`vendor_hid_packets=0`, `hid_reports=0`; the 841 total HID
reports are Logitech).
Note the on-disk pcap linktype is 220; Wireshark displays the same
encapsulation as 115 (usb-linux-mmap).  See `docs/reproduction.md`
§6 for the peer-active capture procedure this parser is built for.

File retained in this repo under `captures/` (195 kB, under GitHub's 100 MB limit).

## Synthetic vendor-CDB injection (verified 2026-11-06)

To prove the new `0xD9` decoder works on real wire traffic without a
peer session, a 16-byte CDB was injected with `sg_raw` while capturing
`usbmon3` (see `docs/reproduction.md` §6.5):

```sh
python3 - <<'PY'
import sys; sys.path.insert(0, "tools")
import wormhole_parse as wp
cdb = wp.build_vendor_hid_cdb("3", bytes([0x01, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
open("/tmp/wormhole_d9.cdb", "wb").write(cdb)
print(cdb.hex())   # d933010a000000000000000000004f54
PY
sg_raw -v /dev/sg2 d9 33 01 0a 00 00 00 00 00 00 00 00 00 00 4f 54
# SCSI Status: Good
```

Result (`captures/wormhole_bus3_synth_2026-11-06.pcap`, 22 packets
after filtering to the Wormhole device, 1.50 s, SHA-256 `d20171795fa69a36a376f2c70b6295d4b255fbbf693047eb4e253b7a69cc5e39`,
plus `wormhole_bus3_synth_capinfos.txt`):

```
Vendor HID (0xD9) packets: 1  UPipe: poll 0 / fetch 0 / send 0  other vendor CDBs: 0  HID reports: 0
3:15 row: ... 3  1  0  <-- WormholeSwitch
  f7   WORMHOLE VENDOR HID (0xD9)  CDB=d933010a000000000000000000004f54
      dir=OUT len=0  CSW=good
      vendorHID type=mouse payload=010a00000000000000000000
      footer_ok=True framing=True
  (next two transactions are the usual GET EVENT STATUS NOTIFICATION / REQUEST SENSE pair)
HID interrupt reports (0 in focus): interfaces idle
```

Key observations: the firmware returns **Good** (not CHECK CONDITION)
for the `0xD9` CDB, confirming it is a recognised vendor opcode, and
the parser's `build_vendor_hid_cdb` helper produces byte-identical
framing.  No inbound HID reports appear for `3:15` — a single-host
injection does not synthesise the peer's input replay, which still
requires a two-machine GoBridge session.
