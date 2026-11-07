# Methodology

Followed `reverse-engineer-anything` v49 → `references/device-protocol-analysis.md` ("SCSI/USB device protocol reverse engineering (IronKey pattern)").

## Workflow

1. **Identify transport** — `lsusb` + `lsusb -t` + `/sys/bus/usb/devices` + `lsusb -v -d 0711:2211`. Established Bulk-Only mass storage + two boot HID interfaces. No video class (no USB camera on this host — 0x0E absent, no `/dev/video*`).
2. **Map kernel bindings** — `usb-storage`, `usbhid`, `/sys/block/srX`, `/dev/sgY`, `hidraw*`, `/proc/bus/input/devices`. Established `/dev/srX` (removable CD-ROM), `sgX`, `event*` input handlers.
3. **Capture traffic** — Linux `usbmon` + `tcpdump -i usbmon3` (bus 3). CBW (`USBC`) / CSW (`USBS`) reconstructed by hex dump; DATA IN decoded as SCSI sense / inquiry / capacity.
4. **Reconstruct command protocol** — SCSI opcode histogram + CDB decoding; LOG SENSE rejection and capacity anomaly documented as observed behaviour, not inferred firmware design.
5. **Map host binaries (REA)** —
   - Windows PE suite: `inspect_pe_imports` → `inspect_pe_resources` → `inspect_pe_certificates` on `SKLoader.exe` (dependency graph, embedded DLL, Authenticode chain). Then carved resource payload and re-ran `inspect_pe_imports` on the UPX stub.
   - Mac bundle: `open_binary` on `GoBridgeDemon`, fallback ELF strings for Mach-O symlinks (`@executable_path/../Frameworks/...`).
6. **Close / retain** — `close_binary` after `open_binary`. Evidence IDs are cited in `docs/pe-analysis.md`.

## IronKey-pattern notes applied

- The PE's `KERNEL32` imports (`CreateProcessA`, `ShellExecuteA`, `FindResource`/`LoadResource`) were the tell that the **loader is the protocol entry point**, mirroring the IronKey `ikpkcs11.dll` lesson: reverse the loader/embedded DLL first, not the wire.
- SCSI vendor-opcode hunting (IronKey 0x20) does **not** apply here — this device uses *standard* opcodes minimally (INQUIRY, TEST UNIT, REQUEST SENSE, READ CAPACITY, READ). No vendor CDBs were observed in the capture.
- Linux ELF fallback was not needed (no ELF target in the ISO).

## Tool / provider gaps

| Desired | Status | Remediation |
|---------|--------|-------------|
| Deep disassembly (`binary_overview`, `list_procedures`, `analyze_function`) | **Done (2026-11-06)** — Ghidra 12.1.4 side-by-side at `/opt/ghidra_12.1.4_PUBLIC`, `/usr/local/bin/ghidra` repointed; SKLoader 988, unpacked DLL 1,849, GoBridgeDemon 1,204 functions. See `docs/pe-analysis.md` *Tooling*. | — |
| `tshark` REA pcap (`inspect_pcap_capture`, `inspect_packet_capture`) | **Done** — `tshark`/`capinfos` 4.4.19 at `/usr/bin/`; `inspect_pcap_client` passes | — |
| UPX decompression | **Done** — `upx` 4.2.4, `upx -d` 104,488 → 310,312 B; real imports (380) + exports (12) recovered | — |
| `inspect_macho` | Unavailable on Linux (macOS-only) | Use `open_binary` (Ghidra) or macOS host |
| Live peer traffic | Not captured — second machine connected but no Wormhole session driven; parser now decodes `0xD9` + HID and flags UPipe candidates (see `docs/reproduction.md` §6) | Run GoBridge on both ends, move mouse/files, re-capture `usbmon3` |

## Preservation

- Original firmware/host blobs are **not** in this repo (copyrighted). Hashes are recorded in `docs/iso-payload.md` and `docs/pe-analysis.md`.
- Pcap retained in `captures/` (195 kB, sanitized — USB only, no network identifiers).
- Scratch working directory: `~/.hermes/cache/scratch/wormhole/` (not tracked). REA paths in evidence IDs point there.

## What remains unknown

- `GSDD.zz` / `GSDD.lst` container format (encryption/compression) and their role in SKLoader deployment.
- Bridge peer-to-peer data channel between the two cable ends (internal to the microcontroller, not enumerated from one host).
- Why kernel block size (15.5 MiB) disagrees with `READ CAPACITY(10)` (3.1 MiB) — resolved as firmware state-dependent capacity (kernel fallback and unit mismatch ruled out by replaying `drivers/scsi/sr.c` `get_sectorsize()` against the recorded responses; see `docs/transport.md` § Capacity anomaly and `tools/capacity_anomaly.py`). Byte-level confirmation of the predicted enumeration response is hardware-gated (cold-plug usbmon capture).
- File/clipboard **UPipe** packet magic and framing beyond the HID `D9` format — needs a live peer-active usbmon capture (see `docs/reproduction.md` §6). `tools/wormhole_parse.py` now has a vendor-CDB decoder (`0xD9` HID + `candidate_upipe` for other `0xC0`–`0xFF` CDBs) so the next capture is immediately parseable; only the UPipe magic itself remains unknown until that capture runs.
- Cable-side forwarding (how the microcontroller routes CDB packets to the peer end) is not in host binaries; needs firmware or two-end capture.
