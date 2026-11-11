# wormhole-switch-re

Reverse-engineering research, notes, and captures for the **J5Create Wormhole** USB A↔A bridge cable (Magic Control Technology **WormholeSwitch**, VID `0711` / PID `2211`).

This is a community documentation project. It is **not affiliated with, sponsored by, or endorsed by** J5Create, KaiJet Technology, or Magic Control Technology Corp. Original firmware and host-software binaries are copyrighted and are **not** vendored here — only hashes, descriptors, and analysis are published.

## What this device is

The Wormhole is a USB A-to-A cable whose middle contains a microcontroller that presents as a compound USB device to each host it is plugged into:

- a **fake CD-ROM** (SCSI Bulk-Only) carrying Windows/macOS host software, and
- **two boot-class HID interfaces** (mouse + keyboard) that allow input injection from the peer machine.

When both ends are plugged into two PCs, each PC runs the bundled *Wormhole* / *GoBridge* software (see `docs/iso-payload.md`). The local USB enumeration is identical regardless of whether the peer is connected — the peer link is internal to the cable.

```
        ┌──────────── J5Create Wormhole cable ────────────┐
  PC A ─┴─ USB A ─[ microcontroller ]─ USB A ─┴─ PC B
                     │
                     ├─ If 0: Mass Storage 08/06/50 (Bulk-Only) → /dev/srX, /dev/sgY
                     ├─ If 1: HID Boot Mouse 03/01/02 (EP3)
                     └─ If 2: HID Boot Keyboard 03/01/01 (EP4)
```

## Protocol summary (observed)

| Layer | Detail |
|---|---|
| USB | USB 2.00, High-Speed 480M, self-powered, MaxPower 10mA, malformed `bmAttributes 0x60` (missing must-be-set bit 7). |
| SCSI (If 0) | Standard Bulk-Only, Bulk-Only CBW (`USBC`) / CSW (`USBS`). INQUIRY returns PDT=5 (cd/dvd), version `0x00` (no conformance claimed), vendor `j5create`, product `WormholeSwitch`, rev `2.00`. Minimal command set: `TEST UNIT READY`, `INQUIRY`, `REQUEST SENSE`, `READ CAPACITY(10)`, `READ(10)`. `LOG SENSE (0x4A)` and `READ CAPACITY(16) (0x9E)` return CHECK CONDITION / INVALID OPCODE. |
| Capacity anomaly | `READ CAPACITY(10)` returns last LBA 1592 / 2048 B blocks (3.1 MiB), which is the usable size of the ISO9660 volume labelled `WORMHOLE`. Linux exposes `/dev/srX` as 31744×512 B (15.5 MiB) because `sr` takes `max(READ CAPACITY, last_written)` and the firmware's track information reports 7936 blocks. See `docs/capacity-anomaly.md`. |
| HID (If 1/2) | Boot Mouse (52 B report descriptor) and Boot Keyboard (67 B). Appear as `hidraw*` + input events. Idle until peer software injects reports — see `docs/transport.md`. |
| ISO payload | `autorun.inf` → `SKLoader.exe` (embedded UPX DLL resource) + `Deployment/GSDD.lst`/`GSDD.zz`, macOS `Wormhole.app` → `WormholeShell` → `Wormhole.tgz` → `GoBridgeDemon` + `KMKeyMouse`/`KMClipboard`/`OTiTransfer`. See `docs/iso-payload.md` and `docs/pe-analysis.md`. |

See [`docs/capture-log.md`](docs/capture-log.md) for a sample usbmon capture and CBW/CSW breakdown.

## Repository layout

```
.
├── README.md                     # this file
├── LICENSE                       # MIT (for documentation code/scripts)
├── ROADMAP.md                    # milestones and open work
├── CONTRIBUTING.md               # contribution and capture rules
├── architecture.html             # architecture diagram
├── .gitignore                    # excludes firmware blobs, pcaps > policy, etc.
├── .github/workflows/tests.yml   # CI: unit tests
├── docs/
│   ├── transport.md              # USB descriptors, SCSI, HID identities
│   ├── iso-payload.md            # ISO contents, manifests, macOS bundle map
│   ├── pe-analysis.md            # REA PE imports/resources/certs for SKLoader.exe + embedded DLL
│   ├── mac-gobridge.md           # GoBridgeDemon + OTiTransfer function-level analysis (HID CDB packets)
│   ├── capture-log.md            # usbmon methodology + CBW/CSW pattern
│   ├── capacity-anomaly.md       # why Linux reports 15.5 MiB for a 3.1 MiB volume (#13)
│   ├── live-capture-2026-11-06.md # live peer-active capture: injection results, sanitisation
│   ├── 15-byte-cdb-truncation.md # short vendor CDBs in the original run (#16)
│   ├── issue-15-mouse60-orphan.md # bus3 x=+60 report findings (#15)
│   ├── issue-17-sanitise-history.md # capture sanitisation record (#17)
│   ├── protocol-mouse-upipe.md   # vendor HID notes (UPipe section superseded by upipe-protocol.md)
│   ├── upipe-protocol.md         # UPipe peer channel: SCSI poll/fetch/send, framing, commands (#7)
│   ├── gsdd.md                   # GSDD container format (#10)
│   ├── wormhole-app-ui.md        # macOS Wormhole.app UI analysis (#12)
│   ├── methodology.md            # REA device-protocol workflow used
│   └── reproduction.md           # commands to re-dump this device yourself
├── captures/
│   ├── wormhole_bus3_2026-11-06.pcap          # idle baseline (no session)
│   ├── wormhole_bus3_capinfos.txt
│   ├── wormhole_bus3_synth_2026-11-06.pcap    # sg_raw 0xD9 injection (vendor HID verified)
│   ├── wormhole_bus3_synth_capinfos.txt
│   ├── wormhole_bus3_live3_2026-11-06.pcap    # live peer-active, local host (Wormhole only)
│   ├── wormhole_bus3_live3_capinfos.txt
│   ├── wormhole_bus1_live_2026-11-06.pcap     # live peer-active, peer host
│   ├── wormhole_bus1_live_capinfos.txt
│   ├── wormhole_bus3_rerun_2026-11-06.pcap    # peer->local re-run, local host (Wormhole only)
│   ├── wormhole_bus3_rerun_capinfos.txt
│   ├── wormhole_bus3_live_2026-11-08.pcap     # local-host live session
│   ├── wormhole_bus3_live_2026-11-08_1751.pcap
│   └── wormhole_bus3_live_2026-11-08_1755.pcap
└── tools/
    ├── wormhole_parse.py         # stdlib-only usbmon pcap parser (CBW/CSW/SCSI + vendor 0xD9 HID + boot HID reports)
    ├── test_wormhole_parse.py    # unittest suite for the parser (44 tests)
    ├── filter_usbmon.py          # keep one device's records from a raw usbmon pcap (sanitising)
    ├── test_filter_usbmon.py     # unittest suite for the filter (9 tests)
    ├── peer_rerun_send.py        # logged send driver for the peer->local re-run (sg_raw and SG_IO)
    ├── test_peer_rerun_send.py   # unittest suite for the driver (4 tests)
    ├── upipe_peer.py             # Linux UPipe peer: login, clipboard push, file download (SG_IO)
    ├── test_upipe_peer.py        # unittest suite for the peer (38 tests)
    └── gobridge_scsi.d           # dtrace tracer for GoBridgeDemon's SCSI tasks (macOS)
```

## Reproduce the basics

```sh
lsusb -v -d 0711:2211
sg_inq /dev/sgX
sg_readcap /dev/sgX          # note: --16 fails on this firmware
sg_readcap --10 /dev/sgX
lsblk -o NAME,PATH,TRAN,SIZE /dev/srX
sudo modprobe usbmon
sudo tcpdump -i usbmon3 -w wormhole.pcap   # Bus 3 = wormhole bus on this host; adjust
```

See `docs/reproduction.md` for endpoints, `/sys` paths, and REA commands.

## Parse a capture

`tools/wormhole_parse.py` is stdlib-only (no tshark/pyshark/scapy) and
reproduces the counts in `docs/capture-log.md` from the committed pcap.
It discovers the Wormhole by VID:PID during control enumeration, so it
does not depend on a Bus:Device number from a previous plug.  It also
decodes the Wormhole vendor HID protocol (16-byte `0xD9` CDB,
`D9 '3'/'4'/'6' <12 payload> O T` — see `docs/transport.md`) and boot
HID interrupt reports (EP3 mouse, EP4 keyboard), and flags any other
vendor-range CDB as a candidate UPipe packet.  It does not decode UPipe
yet (#8); the UPipe format and a Linux peer are in
`docs/upipe-protocol.md`:

```sh
python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap
python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap --json
python3 tools/wormhole_parse.py live.pcap --hid   # peer-active capture
python3 -m unittest tools.test_wormhole_parse
python3 -m unittest tools.test_filter_usbmon
python3 -m unittest tools.test_peer_rerun_send
python3 -m unittest tools.test_upipe_peer
```

For the live peer-active capture runbook (idle baseline, GoBridge
session, and a single-host `sg_raw` vendor-CDB injection test), see
`docs/reproduction.md` §6.

Raw captures record every device on the bus, so publish only filtered copies:
`python3 tools/filter_usbmon.py RAW.pcap --device 3:15 -o captures/OUT.pcap`.
Results and sanitisation for the 2026-11-06 run: `docs/live-capture-2026-11-06.md`.

## Tooling notes (this host)

- `reverse-engineer-anything` skill v49, `references/device-protocol-analysis.md` followed (identify transport → capture traffic → reconstruct CBW/CDB → map host binaries).
- `inspect_pe_imports` / `inspect_pe_resources` / `inspect_pe_certificates` worked (target-free).
- Deep analysis unblocked: Ghidra **12.1.4** installed side-by-side at `/opt/ghidra_12.1.4_PUBLIC` (12.2 untouched), `/usr/local/bin/ghidra` symlink repointed to 12.1.4 so REA 6.8.0 accepts it. `rea doctor --provider ghidra` healthy; SKLoader (988 functions), unpacked OTiArchive DLL (1,849), and GoBridgeDemon (1,204) all decompile. See `docs/pe-analysis.md` *Tooling*.
- `inspect_pcap_client` now passes: `tshark`/`capinfos` 4.4.19 at `/usr/bin/`. (The repo parser in `tools/` remains stdlib-only and does not need them.)
- `upx` 4.2.4 (`/usr/bin/upx`) installed — embedded DLL unpacked 104,488 → 310,312 B; real imports (380) and exports (12 `OTI_*`/`ArchiveTree*`) recovered. See `docs/pe-analysis.md`.

## License

Documentation and scripts in this repository are MIT. Original J5Create/KaiJet firmware and software binaries are not included and remain copyrighted by their respective owners.

## Acknowledgements

Thanks to Magic Control Technology Corp. for the hardware that prompted this study, and to the REA (`reverse-engineer-anything`) toolchain for the PE and capture-analysis workflow.
