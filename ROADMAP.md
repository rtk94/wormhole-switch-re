# Roadmap

Milestones track the reverse-engineering progression from initial enumeration to a complete, documented protocol spec with working reference tools. Versioning is semantic-ish: **v0.x = research milestones**, **v1.0 = stable reference release**.

---

## ✅ v0.1 — Device enumeration & USB topology (Done)

- [x] `lsusb -v -d 0711:2211` — VID/PID, device class, configurations
- [x] Interface map: 3 interfaces (Mass Storage Bulk-Only, HID Boot Mouse, HID Boot Keyboard)
- [x] Endpoint map: EP1 IN / EP2 OUT (bulk 512 B), EP3 IN (int 8 B, 1 ms), EP4 IN (int 8 B, 4 ms)
- [x] Sysfs paths for block device (`/dev/srX`), SCSI generic (`/dev/sgX`), hidraw (`/dev/hidraw*`), input (`/dev/input/event*`)
- [x] Malformed `bmAttributes 0x60` (missing bit 7) documented
- [x] Physical hardware inspected: two housings (j5create/JUC400 + wormhole), blue LEDs, warmth asymmetry documented

**Deliverables:** `docs/transport.md` §Device identity, §Interfaces, `architecture.html`

---

## ✅ v0.2 — SCSI / Mass Storage layer (Done)

- [x] INQUIRY → PDT=5 (cd/dvd), vendor `j5create`, product `WormholeSwitch`, rev `2.00`, version `0x00`
- [x] Supported opcodes: TEST UNIT READY, INQUIRY, REQUEST SENSE, READ CAPACITY(10), READ(10)
- [x] Rejected: GET EVENT STATUS NOTIFICATION (0x4A), READ CAPACITY(16) (0x9E) → CHECK CONDITION / INVALID OPCODE
- [x] Capacity anomaly resolved: READ CAPACITY = 1593×2048 = 3.1 MiB (authoritative); kernel `max()` inflates to 15.5 MiB; tail unreadable (`docs/capacity-anomaly.md`)
- [x] `sg_vpd` fails — no VPD pages

**Deliverables:** `docs/transport.md` §SCSI, `docs/capture-log.md`, `docs/reproduction.md` §2, `docs/capacity-anomaly.md`

---

## ✅ v0.3 — ISO payload & host software inventory (Done)

- [x] ISO9660 volume `WORMHOLE` (15.5 MiB) — full file listing with hashes
- [x] Windows: `autorun.inf` → `SKLoader.exe` (MFC, signed by Magic Control Technology), embedded UPX DLL resource
- [x] macOS: `Wormhole.app` → `WormholeShell` (Mach-O universal) → extracts `Wormhole.tgz` → `GoBridgeDemon` + `KMKeyMouse` / `KMClipboard` / `OTiTransfer` / `FileChgEvent`
- [x] Manifest: KaiJet `Wormhole1107`, loader `1.0.1325.32`, ISO `1.0.1107.56`
- [x] `GSDD.zz` / `GSDD.lst` container format reversed: OTiArchive DB, 29 records, repeating-XOR encrypted XML (`docs/gsdd.md`)

**Deliverables:** `docs/iso-payload.md`, `docs/pe-analysis.md`, `docs/mac-gobridge.md`, `docs/gsdd.md`

---

## 🔄 v0.4 — UPipe protocol (file / clipboard channel) — **CURRENT**

The HID injection path (`0xD9` CDB, types `'3'`/`'4'`/`'6'`) is decoded and verified end-to-end. Multimedia `'6'` mapped (all-zero probe; inferred `payload[0]` = usage). The **file/clipboard channel** uses the same SCSI Bulk-Only pipe: a `0xD8` status poll plus `0xD9 0x28` / `0xD9 0x2A` 64 KiB transfers (`docs/upipe-protocol.md`).

- [x] Capture live peer-active session with clipboard copy and file transfer — Linux ↔ macOS, 2026-11-11, with `tools/upipe_peer.py` on Linux and `tools/gobridge_scsi.d` (dtrace) on the Mac. No usbmon capture of it is published: the Login packet carries the Mac's host name (#7)
- [x] Identify UPipe CDB magic byte(s) — `0xD8` poll, `0xD9 0x28` fetch, `0xD9 0x2A` send
- [ ] Decode UPipe framing and commands — packet tail, chunk header, terminator, Login (`0x01`), ResponseResult (`0xa1`), clipboard XmlPacket (`0x39`: text and file metadata) and file download (`0x10` → `0xa1`/`0xa3`/`0xa7`, `0xa9` on error) decoded; upload, rename, delete and mkdir (`0x11`…), image clipboard formats and `MultipleFilePackage` open (#9)
- [ ] Verify bidirectional symmetry (PC A → PC B vs PC B → PC A) — clipboard text verified both ways; file download verified Mac → Linux only
- [x] `tools/wormhole_parse.py` decodes UPipe: poll state, chunk headers and the reassembled commands, reusing the `tools/upipe_peer.py` decoders (#8)
- [x] Document in `docs/transport.md` (new section) + new `docs/upipe-protocol.md`

**Status:** `tools/upipe_peer.py` acts as a GoBridge peer on Linux: login, clipboard text push (`--clipboard`) and file download from the Mac (`--download`). `tools/wormhole_parse.py` decodes UPipe in usbmon captures. Remaining: the Mac fetching files from Linux, and uploads.

---

## 🔄 v0.5 — Windows host software parity (In progress)

macOS GoBridgeDemon is analysed to function level (`docs/mac-gobridge.md`). Windows path (`SKLoader.exe` → embedded DLL → `OTiTransfer`) is mapped at import/resource level (`docs/pe-analysis.md`). GSDD container format is reversed (`docs/gsdd.md`).

- [x] `GSDD.zz` / `GSDD.lst` container format — encryption/compression, role in SKLoader deployment
- [ ] Deep decompile embedded DLL (UPX unpacked, 1,849 functions) — trace `OTi_*` exports to SCSI/HID calls
- [ ] Map Windows HID injection: `SendInput` / `HID` API usage vs macOS `CGEvent` path
- [ ] Map Windows file/clipboard: `OTiTransfer` → `DeviceIoControl` / `IOCTL_SCSI_PASS_THROUGH` vs macOS `SCSITask`
- [x] Analyse `Wormhole.app` UI (macOS frontend) — `docs/wormhole-app-ui.md` (#12)
- [ ] Cross-reference macOS/Windows packet formats for parity (same `0xD9` HID? same UPipe?)

**Deliverable:** `docs/windows-gobridge.md` (parallel to `mac-gobridge.md`)

---

## 🔄 v0.6 — Firmware mysteries (Partially resolved)

Host-side observations resolved several firmware-adjacent questions without needing a firmware dump:

- [x] Capacity anomaly root cause: firmware `READ CAPACITY` (3.1 MiB) vs kernel `last_written` (15.5 MiB) — kernel `max()` in `sr.c get_sectorsize()`
- [x] Multimedia HID type `'6'` wire payload: all-zero probe proves framing; `payload[0]` = Consumer usage (inferred from dylib); 6 usages via `'6'`, 6 via `'4'`
- [x] 15-byte CDB truncation: host-side short send (missing pad byte), not usbmon, not firmware — wire proof in `docs/15-byte-cdb-truncation.md`
- [x] Peer forwarding confirmed; `bus3_live2` orphan x=+60 attributed to peer-side injection through cable by inference (`docs/issue-15-mouse60-orphan.md`)
- [ ] Peer-to-peer data channel internals: exact firmware routing between housings (not visible from one host)
- [ ] Firmware extraction / analysis (if feasible — JTAG/SWD, DFU, or vendor update mechanism)

**Approach remaining:** Two-end simultaneous capture (usbmon on both hosts) + host-software logging correlation. Firmware dump is stretch goal.

---

## 🎯 v1.0 — Stable reference release

- [ ] Complete protocol specification: USB/SCSI/HID/UPipe in one document (`docs/protocol-spec.md`)
- [ ] Parser (`tools/wormhole_parse.py`) covers all observed packet types with 100% test coverage
- [ ] Reproduction guide (`docs/reproduction.md`) validated on clean Linux/macOS/Windows hosts
- [ ] All captures in `captures/` are filtered, documented, and parseable by the reference parser
- [ ] Cross-platform host-software analysis parity (macOS + Windows)
- [ ] `README.md`, `CONTRIBUTING.md`, `ROADMAP.md`, `LICENSE` complete
- [x] Architecture diagram (`architecture.html`) in repo root
- [ ] Tag `v1.0` — reference frozen for downstream implementers (emulators, KVM switches, protocol translators)

---

## Milestone status summary

| Version | Theme | Status | Target |
|---------|-------|--------|--------|
| v0.1 | Enumeration & topology | ✅ Done | — |
| v0.2 | SCSI / Mass Storage | ✅ Done | — |
| v0.3 | ISO payload & host inventory | ✅ Done | — |
| v0.4 | **UPipe protocol** | 🔄 **In progress** | Uploads, Mac → Linux fetch |
| v0.5 | Windows host parity | 🔄 In progress | After v0.4 |
| v0.6 | Firmware internals | 🔄 Partially resolved | Long-term |
| v1.0 | Stable reference release | 📋 Planned | When v0.4–0.6 converge |

---

## How to move v0.4 forward

The capture method is in `docs/upipe-protocol.md` (Linux peer tool + Mac dtrace tracer). Remaining steps:

1. Serve `0x10` DownloadMultipleFile from Linux: push a `CB_Format_File` clipboard entry to the Mac, paste in Finder, and answer the Mac's request.
2. Decode the upload and file-operation commands (`0x11`…) the same way: decompile, add to `tools/upipe_peer.py`, verify live.
3. Repeat against a Windows peer for parity (v0.5).

Once uploads are done, v0.4 closes.
