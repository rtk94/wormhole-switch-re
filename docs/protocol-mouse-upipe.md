# Wormhole Switch: Mouse Relative-Move Encoding & UPipe Framing

Synthesized from `docs/mac-gobridge.md` (GoBridgeDemon + OTiTransfer function-level analysis) and `tools/wormhole_parse.py` (vendor HID CDB decoder). All offsets and byte layouts are **host→cable direction** unless noted.

---

## 1. Mouse Relative-Move: `SendMouseEvent` → 0xD9 CDB (type `'3'`)

### 1.1 Call chain (macOS side)

```
CKMEvent::SendMouseEvent (0x3cd8, KMKeyMouse.dylib)
    → boundary detection: BoundaryDetectionInVirtualFrame / BoundaryDetectionInMainFrame
    → speed scaling via MouseInterface
    → [KMMainLoop sendMouseData:packet]
    → delegate: THMFileManager.postMouseHIDEventToRemote:
    → OTi_SendHIDPacket(type=1, packet)   // type 1 = mouse
    → OTiTransporter::sendHIDPacket(type, data)   // builds 16-byte CDB
    → SendSCSICommandSendData(CDB=packet, CDB_len=0x10, data=NULL)
```

### 1.2 16-byte CDB wire format (host → cable)

| Offset | Size | Value | Meaning |
|--------|------|-------|---------|
| 0      | 1    | `0xD9` | Vendor HID magic (SCSI opcode) |
| 1      | 1    | `'3'` (0x33) | Type: **mouse** (type 1 in ObjC → char `'3'`) |
| 2–13   | 12   | **HID payload** | 12 bytes: mouse report + padding |
| 14–15  | 2    | `'O' 'T'` (0x4F 0x54) | OTiTransfer footer |

The 14-byte `CFData` passed to `OTi_SendHIDPacket` is exactly bytes 0–13 above; `sendHIDPacket` appends the `'OT'` footer to make the 16-byte CDB.

### 1.3 12-byte HID payload layout (bytes 2–13)

From `OTiTransporter::sendHIDPacket` pseudocode and the parser's `decode_vendor_hid_cdb`:

```
Byte 2  : Button state (bit 0 = left, bit 1 = right, bit 2 = middle)
Byte 3  : Relative X  (signed int8, −128..+127)
Byte 4  : Relative Y  (signed int8, −128..+127)
Byte 5  : Wheel delta (signed int8, −128..+127)
Bytes 6–13 : Zero padding (always 0x00 in observed captures)
```

**This matches the boot-mouse interrupt report format** (EP3 IN, 4 bytes) decoded by `decode_hid_mouse_report` in `wormhole_parse.py` — the host→cable CDB payload *is* the same 4-byte report, zero-padded to 12 bytes.

### 1.4 Relative-move encoding rules (from `SendMouseEvent`)

- **Coordinates are relative deltas**, not absolute. `SendMouseEvent` accumulates deltas from the CGEvent tap (`kCGHIDEventTap`).
- **Boundary detection** (`BoundaryDetectionInVirtualFrame` / `BoundaryDetectionInMainFrame`) clamps or wraps when the virtual cursor hits the remote screen edge — this is how "seamless" cross-screen motion works.
- **Speed scaling** via `MouseInterface` applies a multiplier (configurable per-session) before the int8 clamp.
- **Clamping**: each axis is clamped to `int8_t` range (−128..+127). Large physical moves are split into multiple CDBs (observed burst of 0xD9 packets per drag).
- **Button state** is the *current* button mask at the time of the move event (down/drag/up all generate a CDB with the corresponding bit set).

### 1.5 Example CDB (mouse move right 10, down 5, left button held)

```
D9 33 01 0A FB 00 00 00 00 00 00 00 00 00 4F 54
│  │  │  │  │  └─ wheel = 0
│  │  │  │  └───── Y = −5 (0xFB = −5 signed)
│  │  │  └──────── X = +10 (0x0A)
│  │  └─────────── buttons = 0x01 (left down)
│  └────────────── type = '3' (mouse)
└───────────────── magic = 0xD9
```

---

## 2. Keyboard & Multimedia Types (for completeness)

| Type char | ObjC type | HID payload (bytes 2–13) | Parser constant |
|-----------|-----------|--------------------------|-----------------|
| `'3'` (0x33) | 1 (mouse) | 4-byte boot report + 8×0x00 | `VENDOR_HID_TYPES[0x33] = "mouse"` |
| `'4'` (0x34) | 2 (keyboard) | 8-byte boot report (mods + 6 keycodes) + 4×0x00 | `VENDOR_HID_TYPES[0x34] = "keyboard"` |
| `'6'` (0x36) | 3 (multimedia) | Usage ID at byte 2, rest 0 | `VENDOR_HID_TYPES[0x36] = "multimedia"` |

Keyboard payload matches the boot-keyboard interrupt report (EP4 IN, 8 bytes) decoded by `decode_hid_keyboard_report`.

### 2.1 Multimedia type `'6'` (ObjC type 3) — synthetic probe decode (issue #20)

The framing for `'6'` is identical to `'3'`/`'4'`: 16-byte CDB
`D9 '6' <12 payload> OT`, no bulk data phase. What is unique to `'6'`
is the payload: instead of a boot report it carries **one HID
Consumer usage** (a discrete transport key) with the rest zero. That
layout is now pinned at two levels — the cable-acceptance probe is
**observed**, the usage position is **inferred** from the dylib and
still needs a live GoBridge press to prove. Both are stated
separately below; nothing is presented as captured unless it is.

#### 2.1.1 Decoded packets (captures/wormhole_bus3_live_2026-11-08.pcap)

Parser: `python3 tools/wormhole_parse.py captures/wormhole_bus3_live_2026-11-08.pcap --json`
(SHA-256 `fb04485766cc5e6b76a70ad282f65645106d27d26aacde1facadaeb6098e7383`,
3,756 packets, 629 SCSI transactions, one Wormhole device 3:15
`0711:2211`). The capture contains exactly **2**
`0xD9` CBWs — one mouse reference and one multimedia probe:

| # | CBW frame | t_offset | Tag | CDB hex (16 B) | `hid_type` | `payload_hex` (bytes 2–13) | CSW |
|---|-----------|----------|-----|----------------|------------|----------------------------|-----|
| 1 | 3711 | 569.117813 s | `0x2c062` | `d933010a000000000000000000004f54` | `mouse` (`'3'`, 0x33) | `010a00000000000000000000` | good |
| 2 | 3727 | 572.172738 s | `0x2c065` | `d9360000000000000000000000004f54` | `multimedia` (`'6'`, 0x36) | `000000000000000000000000` | good |

Both are OUT (`flags=0x00`), LUN 0, `CBW data_len=0` (no data phase),
`footer_hex=4f54` (`OT`), `footer_ok=True`, `valid_hid_framing=True`.

Raw CBW submit (frame 3727, 31 bytes on EP2 OUT):
`55534243 65c00200 00000000 00000000 10 d9360000000000000000000000004f54`
= `USBC`, tag `0x0002c065`, data_len 0, flags `00`, LUN `00`,
CDB_len `0x10`, then the CDB above. The CSW at frame 3732 carries
status `0x00` (good).

Byte-by-byte breakdown of the `'6'` packet (`d9360000000000000000000000004f54`):

| CDB offset | Value | Role |
|------------|-------|------|
| 0 | `0xD9` | Vendor HID magic (`VENDOR_HID_MAGIC`) |
| 1 | `0x36` (`'6'`) | Type: multimedia (ObjC type 3) |
| 2 | `0x00` | payload[0] — usage (inferred; see §2.1.2) |
| 3 | `0x00` | payload[1] — press/release-or-subtype candidate (unconfirmed) |
| 4 | `0x00` | payload[2] — zero in probe |
| 5 | `0x00` | payload[3] — zero in probe |
| 6 | `0x00` | payload[4] — zero in probe |
| 7 | `0x00` | payload[5] — zero in probe |
| 8 | `0x00` | payload[6] — zero in probe |
| 9 | `0x00` | payload[7] — zero in probe |
| 10 | `0x00` | payload[8] — zero in probe |
| 11 | `0x00` | payload[9] — zero in probe |
| 12 | `0x00` | payload[10] — zero in probe |
| 13 | `0x00` | payload[11] — zero in probe |
| 14 | `0x4F` (`'O'`) | OTiTransfer footer byte 1 |
| 15 | `0x54` (`'T'`) | OTiTransfer footer byte 2 |

Reference mouse packet (frame 3711, `d933010a000000000000000000004f54`):
byte 2 `0x01` (buttons = left), byte 3 `0x0a` (X = +10),
byte 4 `0x00` (Y = 0), byte 5 `0x00` (wheel = 0), bytes 6–13 zero —
the familiar 4-byte boot-mouse report + 8×`0x00` (see §1.3).

The `'6'` frame is byte-identical to the framing-only probe from
`docs/reproduction.md` §6.5:
`build_vendor_hid_cdb("6", bytes(12))` →
`d9360000000000000000000000004f54` (round-trip verified when the
parser runs: `hid_type=multimedia`, `type_char=6`,
`payload_hex=000000000000000000000000`, `valid_hid_framing=True`).
Its purpose in §6.5 is deliberately to **not presuppose where the
usage byte sits**: an all-zero payload tests framing acceptance only.
**CSW `good`** therefore proves the cable firmware recognises and
accepts `'6'` framing — it does not prove any usage mapping.
There is no second `'6'` packet in the capture (both
`wormhole_bus3_live_2026-11-08_1751/_1755.pcap` files contain zero
`0xD9` transactions), so this is the entire wire evidence for `'6'`.

The capture's only HID interrupt report (frame 3730, EP3 IN,
`00000000` — idle mouse) lands between the `'6'` CBW (3727) and its
CSW (3732). Because bulk-only and interrupt transfers are concurrent,
that interleaving is ordinary polling coincidence, not evidence of a
consumer replay: an idle `00000000` carries no usage, and neither
HID report descriptor declares a Consumer page (`05 0C`) — so no
peer-end replay can be assessed from this single-host capture. A
two-host run (or a macOS GoBridge session) is still required for that.

#### 2.1.2 Which bytes encode the multimedia key (dylib cross-reference)

Source: KMKeyMouse.dylib via `docs/mac-gobridge.md`:

- `CKMEvent::KMEventHandler` dispatches CGEvent type `14`
  (system-defined), subtype `8` = multimedia, mapping
  `data1 >> 16` to HID usages.
- Six usages route to the **multimedia** path — `SendMultimediaKeyEvent(this, 2, usage, 0)`:

| Usage | Key | Routed via |
|-------|-----|------------|
| `0xb8` | Eject | `'6'` |
| `0xcd` | Play | `'6'` |
| `0xb5` | Next | `'6'` |
| `0xb6` | Previous | `'6'` |
| `0xb3` | Fast (forward) | `'6'` |
| `0xb4` | Rewind | `'6'` |

- Six other consumer-ish usages route to the **keyboard** path
  instead — `SendKeyboardEvent(14-byte buffer, usage at byte 2)` —
  and so travel as `'4'`, not `'6'`: SoundUp `0x80`, SoundDown
  `0x81`, BrightnessUp `0x48`, BrightnessDown `0x47`, Power `0x66`,
  Mute `0x7f`.
- Call chain for `'6'`: `SendMultimediaKeyEvent` →
  `KMMainLoop sendMultimediaKeyData:` →
  `-[THMFileManager postMultimediaHIDEventToRemote:]` (0x1bccb) →
  `OTi_SendHIDPacket(3, packet)` → `OTiTransporter::sendHIDPacket`
  (builds the 16-byte CDB, logs `key HID: <first 8 payload bytes>`
  for type 3, then `SendSCSICommandSendData` with NULL data).

Working payload layout (12 bytes, CDB bytes 2–13):

| Payload byte | CDB byte | Meaning | Confidence |
|--------------|----------|---------|------------|
| `payload[0]` | 2 | HID Consumer usage (one of `b3/b4/b5/b6/b8/cd` above) | **Inferred** — consistent with §2's "usage at byte 2" and the keyboard-path `usage at byte 2` wording; not proven by the all-zero probe, which is usefully compatible with any offset |
| `payload[1]` | 3 | Possibly the press/release or subtype field (the `2` / trailing `0` in `SendMultimediaKeyEvent(this, 2, usage, 0)`) | **Unknown** — the decompile records the call signature only; no byte position is established |
| `payload[2..7]` | 4–9 | Within the `key HID:` logged window; zero in the probe | Observed zero; meaning unknown |
| `payload[8..11]` | 10–13 | Zero in the probe; beyond the logged window | Observed zero; presumed padding |

To convert the inferred row into a proven one, capture a real media
key press in a macOS GoBridge session and read the `key HID:`
payload dump from `OTiTransporter::sendHIDPacket` — that log prints
the exact bytes the dylib built. Until then the parser correctly
reports the payload raw (`payload_hex`) and no layout is assumed
anywhere.

#### 2.1.3 How `'6'` differs from type `'3'`

| Aspect | `'3'` mouse | `'6'` multimedia |
|--------|-------------|------------------|
| Payload semantics | 4-byte boot-mouse report in `payload[0..3]`: buttons, signed X, signed Y, signed wheel (bytes 2–5) | 1-byte Consumer usage in `payload[0]` (bytes 2) + (at most) one press/release byte; rest zero |
| Event model | Continuous relative deltas, streamed (bursts per move/drag); clamped to signed int8; boundary detection + speed scaling in `SendMouseEvent` | Discrete key event: one CDB per key press (press/release pairing still unknown) |
| Peer replay | EP3 boot-mouse report (4 bytes) — verified 1:1 in the two-host runs | No Consumer collection in either descriptor; target endpoint/usage synthesis unverified |
| Wire framing | `D9 33 <12> OT`, no data phase | Identical: `D9 36 <12> OT`, no data phase (same `sendHIDPacket`, same NULL data) |
| Evidence in this capture | `d933010a…` at 569.118 s, CSW good | `d9360000…` (all-zero probe) at 572.173 s, CSW good — framing accepted, usage unexercised |

---

## 3. UPipe / File-Transfer Framing: `GetData` / `PutData` Queues

> **Superseded (2026-11-11).** The UPipe channel has been captured and
> decoded; see [upipe-protocol.md](upipe-protocol.md). This section keeps
> the pre-capture static analysis. §3.3 below lists what was observed.

### 3.1 What we know from static analysis

`OTiTransporter` (C++, ~70 methods) exposes:

- `GetData` / `PutData` — queue operations for bulk endpoints
- `RunLoopFunction` / `ReceiveData` / `SendData` — async I/O loop
- `processReceiveState` / `processTransferState` — state machines
- `rxQueues`, `txQueue` counters in `THMFileManager` (GoBridgeDemon)

The **same SCSI plumbing** (`SendSCSICommandSendData` / `SendSCSICommandReceiveData`) is used for file/clipboard transfer — the difference is:
- HID packets: **no data phase** (`CFData* data = NULL` in `SendSCSICommandSendData`)
- File/clipboard: **has a data phase** (CBW `data_len > 0`, bulk data follows)

### 3.2 Vendor CDB range flagged as UPipe candidates

`wormhole_parse.py` defines:

```python
VENDOR_RANGE = (0xC0, 0xFF)        # SPC vendor-specific opcodes
VENDOR_HID_MAGIC = 0xD9            # Only 0xD9 is fully decoded
```

Any CDB with opcode `0xC0–0xFF` **except 0xD9** is reported as the
following. This predates the capture: real UPipe traffic uses `0xD8`
and `0xD9`, so the parser flags the `0xD8` poll as a candidate and
reads `0xD9 0x28`/`0x2A` as malformed HID (#8).


```json
{
  "is_vendor": true,
  "is_vendor_hid": false,
  "name": "VENDOR CDB 0xNN (possible UPipe)",
  "candidate_upipe": true,
  "cdb_hex": "...",
  "cbw_data_len": <expected data phase length>
}
```

### 3.3 Observed UPipe structure (2026-11-11)

| Field | Observed |
|-------|----------|
| CDB opcodes | `0xD8 00 03` status poll (16 B in); `0xD9 0x28 0x64` fetch (64 KiB in); `0xD9 0x2A 0xFF` send (64 KiB out) |
| CDB length | 16 bytes, `O` `T` footer as for HID |
| Packet | `0xffec`-byte body + its first 20 bytes as a tail; chunk header of five little-endian `u32`s |
| Direction | Both ends poll the cable; each fetches what the other sent |
| Commands | Byte 0 = GoBridge command ID (Login `0x01`, XmlPacket `0x39`, DownloadMultipleFile `0x10`, ResponseResult `0xa1`, …) |

Details and evidence: [upipe-protocol.md](upipe-protocol.md).

### 3.4 Clipboard rides UPipe, not HID

From `docs/mac-gobridge.md` (KMClipboard.dylib):

> Clipboard payloads ride **UPipe messages** (`marshallFromUPipeMsg`), i.e. the same peer channel as file commands — not HID packets.

So the UPipe channel multiplexes:
- File transfer (upload/download, directory ops); download decoded
- Clipboard sync; confirmed as `XmlPacket` (`0x39`) carrying `Cmd_Transfer_Clipboard`
- Possibly hotkey/switch commands (`_NotifyUPipeMesssageUpToAppThread:`)

---

## 4. Cross-Reference: `tools/wormhole_parse.py` Decoder

### 4.1 Key constants (lines 145–158)

```python
VENDOR_HID_MAGIC = 0xD9
VENDOR_HID_TYPES = {
    0x33: "mouse",      # '3'
    0x34: "keyboard",   # '4'
    0x36: "multimedia", # '6'
}
VENDOR_HID_FOOTER = b"OT"
VENDOR_HID_LEN = 16
VENDOR_RANGE = (0xC0, 0xFF)
```

### 4.2 `decode_vendor_cdb(cdb)` (lines 487–546)

Returns a dict with:

| Key | Meaning |
|-----|---------|
| `is_vendor` | True for any opcode in `0xC0–0xFF` |
| `is_vendor_hid` | True only for `0xD9` |
| `hid_type` | `"mouse" \| "keyboard" \| "multimedia" \| "unknown"` |
| `payload_hex` | Bytes 2–13 (12 bytes) as hex |
| `payload` | List of 12 ints |
| `footer_ok` | True if bytes 14–15 == `b"OT"` |
| `valid_hid_framing` | All three checks pass (len==16, type known, footer OK) |
| `candidate_upipe` | True for vendor opcodes ≠ 0xD9 |

### 4.3 `build_vendor_hid_cdb(hid_type, payload)` (lines 549–558)

Test helper — builds a valid 16-byte CDB for `sg_raw` injection:

```python
build_vendor_hid_cdb("3", b"\x01\x0a\xfb\x00")  # mouse move example
# → b'\xd9\x33\x01\x0a\xfb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4f\x54'
```

### 4.4 `decode_hid_mouse_report(payload)` (lines 604–623)

Decodes the **interrupt IN report** (EP3, 4 bytes) — same 4-byte layout as CDB payload bytes 2–5:

```python
{
  "buttons": 0x01,
  "left": True, "right": False, "middle": False,
  "x": +10, "y": -5, "wheel": 0
}
```

---

## 5. What Still Needs a Live Peer-Active Capture

| Unknown | Where to look |
|---------|---------------|
| UPipe CDB magic bytes (opcode + payload header) | Resolved: [upipe-protocol.md](upipe-protocol.md#layer-1-scsi-commands) |
| UPipe command/response encoding | Partly resolved: login, clipboard and download decoded; uploads open (#9) |
| Clipboard UPipe message format | Resolved: [XmlPacket `0x39`](upipe-protocol.md#xmlpacket-0x39-clipboard) |
| Cable-side routing (microcontroller firmware) | Not in host binaries; needs two-end capture or firmware dump (#14) |

---

## 6. Quick Reference: CDB Byte Map

```
Byte:  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
      ┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
HID   │D9 │'3'│Btn│ X │ Y │Whl│ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ O │ T │  ← mouse
      │D9 │'4'│Mod│Res│Kc1│Kc2│Kc3│Kc4│Kc5│Kc6│ 0 │ 0 │ 0 │ 0 │ O │ T │  ← keyboard
      │D9 │'6'│Use│ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ 0 │ O │ T │  ← multimedia
      ├───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┼───┤
UPipe │NN │?? │                    command-specific payload                    │  ← candidate_upipe
      └───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
```

- **HID path**: 0xD9 CDB, no bulk data phase, 16 bytes on the wire.
- **UPipe path**: Other vendor opcode, **has bulk data phase** (CBW `data_len` > 0), CDB length likely 16 but payload structure unknown.

---

## 7. Related Files

- `docs/mac-gobridge.md` — Full function-level RE trail (GoBridgeDemon, OTiTransfer, KMKeyMouse)
- `docs/pe-analysis.md` — Windows SKLoader + OTiArchive DLL analysis
- `tools/wormhole_parse.py` — Reference parser (`decode_vendor_cdb`, `build_vendor_hid_cdb`, `decode_hid_mouse_report`)
- `captures/wormhole_bus3_2026-11-06.pcap` — Idle capture (zero vendor HID traffic)
- `captures/wormhole_bus3_live_2026-11-08.pcap` — Synthetic `d933…` mouse + `d936…` all-zero multimedia probe (§2.1)
- `docs/reproduction.md` §6 — How to capture a peer-active session