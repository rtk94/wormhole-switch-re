# UPipe protocol: the peer data channel

**What this document answers**

- Which SCSI commands carry peer data (poll, fetch, send) and what the poll reply states mean
- How a 64 KiB OTi packet is framed (integrity tail, chunk header, end-of-command terminator)
- How GoBridge commands are encoded, with Login (`0x01`) and ResponseResult (`0xA1`) in full
- How to stand in for a GoBridge peer from Linux with `tools/upipe_peer.py`
- What the clipboard push (`0x39` XmlPacket) looks like for text and files, and how to send text to the Mac
- What is still unknown (file contents transfer, drag-and-drop, the `0xF0` CDB, `DUMMY_DATA`)

The HID injection path (`0xD9 '3'/'4'/'6'` CDBs with no data phase) is a
separate mechanism, covered in [transport.md](transport.md#peer-link-vendor-scsi-cdb-packets-host--cable)
and [protocol-mouse-upipe.md](protocol-mouse-upipe.md).

## Sources

| Layer | Where it was decoded |
|---|---|
| SCSI commands, poll states, send rules | Ghidra decompile of macOS `OTiTransfer` (i386 slice, sha256 `b7d7157e…`, see [mac-gobridge.md](mac-gobridge.md)): `OTiTransporter::ProcessIdleState`, `GetRemoteHostStatus`, `GetData`, `PutData`, `SendData`, `RejectRemoteTX`, `requestResendPacket` |
| Chunk framing, command encoding | Ghidra decompile of `GoBridgeDemon` (sha256 `152311cb…`): `CommandSender wrappedCommandDataWith:`, `CommandData initFromData:`, `CommandDataBuffer`, `LoginCommand`, `ResponseResult`, `THMGBServer`/`THMGBClient handleCommand:` |
| OS byte constants | `KMClipboard.dylib` exports `GB_OS_TYPE_*`, `OS_*` (GoBridgeDemon frameworks) |
| Wire confirmation | Two-end capture 2026-11-11, see [Evidence](#evidence-2026-11-11) |

## Layer 1: SCSI commands

Every command is a 16-byte vendor CDB ending in `4f 54` (`"OT"`), sent to
the cable's mass-storage LUN. Each side runs the same loop: poll, then
fetch or send depending on the reply.

| Purpose | CDB | Data phase |
|---|---|---|
| Poll (`GetRemoteHostStatus`) | `d8 00 03 <txHi> <txLo> … 4f 54` | 16 B in |
| Fetch (`GetData`) | `d9 28 64 00 … 4f 54` | 65 536 B in |
| Send (`PutData`) | `d9 2a ff … 4f 54` | 65 536 B out |
| Reject peer's data (`RejectRemoteTX`) | `d9 39 00 … 4f 54` | none |
| Request resend (`requestResendPacket`) | `d8 <x> 0b … 4f 54` | not traced |
| Unknown, issued once when the peer comes online | `f0 00 02 00 … 4f 54` | 64 B in |

- `<txHi> <txLo>` is the number of packets the poller has queued (big-endian).
- The Mac leaves CDB bytes 3–13 of the poll and send commands uninitialised
  (stack contents); the cable ignores them as far as observed. The Linux tool sends zeros.
- `0xF0` is probably `GetPhysicalBusType` (called from `ProcessIdleState`
  when the peer comes online). Unconfirmed.

### Poll reply (byte 0 = state)

| State | Meaning | What `ProcessIdleState` does |
|---|---|---|
| `0x00`, `0x08`, `0x10` | Peer device offline | Clear queues; post `OTi_NotifyRemoteDevUnplug` |
| `0x01` | Peer device present, peer app offline | Clear queues; post `OTi_NotifyRemoteAppOffline` |
| `0x04` | Packet size | Log only |
| `0x05` | Data waiting; bytes 1–2 = packet count (BE16) | Fetch that many packets, or `RejectRemoteTX` if its rx queue holds ≥ 200 |
| `0x06` | Ready for a single packet | Send 1 queued packet |
| `0x07` | Peer app online | Send all `<tx>` packets announced in the poll |
| `0x09` | Peer asks to resend the last packet | Re-queue the last sent packet |
| `0x0A` | Peer asks to drop the last packet | Forget the last sent packet |

The first non-offline reply makes the Mac log `notify remote app online`
and start its GoBridge login.

### Send errors

`PutData` maps sense data to OTi result codes. With no peer polling, every
send fails with sense key 9, ASC `0x85` (`SendError: others`). Other codes:
`0x87` no image, `0x88` Tx/Rx image conflict, `0x89` Tx/Tx image conflict,
`0x90` resend last packet, `0x91` remove last packet.

## Layer 2: OTi packet

Every fetch and send moves exactly 65 536 bytes:

```
offset 0x0000  body (0xffec bytes, zero-padded)
offset 0xffec  body[0:20]   (integrity tail)
```

`GetData` rejects a packet whose tail differs from its first 20 bytes, and
discards one whose first 20 bytes equal `DUMMY_DATA` (contents
unconfirmed; the all-zero terminator below is **not** discarded at this
layer, because the Mac's dtrace shows it fetching them).

## Layer 3: chunk header (`CommandSender`)

The body starts with five little-endian `u32`s:

| Offset | Field | Notes |
|---|---|---|
| 0x00 | `seq` | Packet counter, +1 per chunk, never 0; persists for the daemon's lifetime |
| 0x04 | `session` | Command counter, +1 per command, starts at 1 |
| 0x08 | `index` | Chunk index within the command, from 0 |
| 0x0c | `total` | Chunk count for the command |
| 0x10 | `length` | Command bytes in this chunk (≤ `0xffd8`) |
| 0x14 | data | `length` bytes of the encoded command |

A command longer than `0xffd8` bytes is split across chunks of the same
`session`. After the last chunk the sender always emits one **all-zero
chunk** (`seq` 0) as a terminator. `CommandData initFromData:` returns nil
for `seq` 0, so the receiver drops it. `CommandDataBuffer` reassembles
chunks by `session`, sorts by `index`, and dispatches when `total` chunks
are present.

## Layer 4: commands

Byte 0 of the reassembled command is the command ID. The rest is
per-command. GoBridgeDemon encodes multi-byte fields big-endian and UTF-16
strings as UTF-16BE. It decodes a remote's fields with a byte swap, and picks
the UTF-16 order, by `remoteIsBigEndian` (implemented in `KMClipboard.dylib`,
not decompiled). For a Linux peer (OS `0x20`) that is false: the Mac reads our
fields little-endian and our strings as UTF-16LE, while still sending its own
big-endian. A big-endian `0x10` request from Linux crashed GoBridgeDemon (see
[Evidence](#evidence-2026-11-11)). The same holds for replies: the Mac
accepted little-endian ResponseResult, `0xa3`, `0xa7` and `0xa9` from Linux
when it requested files (`serve` runs). Login's code page is zero in
practice, so its order was not tested.

IDs known to `CommandDataBuffer commandClassForCommandID:`: `0x00` (dummy),
`0x01`, `0x02`, `0x04`, `0x06`–`0x09`, `0x0c`, `0x0e`, `0x10`–`0x15`, `0x37`,
`0x39`, `0x3a`, `0xa1`–`0xa9`, `0xad`. Server side (`THMGBServer`):
`0x01` Login, `0x02` Logout, `0x04` GetDirectoryInfo, and the file
operations listed in [mac-gobridge.md](mac-gobridge.md#file-transfer-command-surface-objc-selectors).
Client side (`THMGBClient`) handles `0xa1`–`0xa9` and `0xad`, starting with
`0xa1` ResponseResult. `0x39` is `XmlPacketCommand`; `OTiCommand doCommand:`
drops it while the server is not connected. Login, ResponseResult and the
clipboard form of XmlPacket and the file download are decoded below; other
payloads are not.

### OS byte

High nibble = type, low nibble = version (`GB_OS_TYPE_MASK 0xf0`,
`GB_OS_VERSION_MASK 0x0f`):

| Type | Value | Versions |
|---|---|---|
| Windows | `0x00` | `OS_WIN31` 1 … `OS_WINXP` 7 |
| Mac | `0x10` | `OS_MACOS_10_0` 0 … `OS_MACOS_10_8` 8 |
| Linux | `0x20` | — |

OS X 10.6.8 sends `0x16`. The constant for `0x20` is named Linux, and the
daemon logs `remote is linux`, but the Mac's Wormhole Switch window labels a
`0x20` peer "Android" (`Remote Computer: Android linux-peer`, 2026-11-11).

### Login (`0x01`)

```
01 <os> <code page, BE16> <name length> <name, UTF-8>
```

The Mac sends `01 16 00 00 1c <28-byte host name>`. The name is the
Bonjour host name (`<mac-hostname>.local`), so raw packets identify the machine.

### ResponseResult (`0xA1`)

```
a1 <requestCommand> <requestResult>
   <sessionID BE32> <errorCode BE32> <lowFileSize BE32> <highFileSize BE32>
   <extraInfoFlag> <extraInfoLength BE32> <extraInfo>
   <tag, 6 bytes> <errorString length BE32> <errorString>
```

- The login reply (`THMGBServer handleLogin:`) is `requestCommand` 1,
  `requestResult` 0, `extraInfoFlag` 3, and `extraInfo` =
  `"OSVERSION" + <local OS byte>` (10 bytes). With flag 3, `extraInfoLength`
  stays 0 and the decoder reads exactly 10 bytes at offset 23 of the payload.
  The whole reply is 44 bytes.
- The decoder reads `tag` and `errorString` only when the remote is a Mac.
- `THMGBClient handleRequestResponse:` acts on `requestCommand` 1 by logging
  `did login to remote` and setting `didLoginToRemote`; it does not check
  `requestResult`.

### Login handshake

Both sides are client and server at once:

1. The peer comes online (poll reply leaves `0x00`/`0x01`). Each side sends a Login.
2. Each side's server answers the other's Login with a ResponseResult, records
   the peer's OS byte (`setRemoteOSVersion`), and calls `remoteDidLoginWithName:`.
3. On a Linux peer the Mac logs `remote is linux` and skips
   `forwardDomainFoldersInfoToRemote`, which Windows and Mac peers receive.

Either side may log in first. If the Linux side restarts soon after
stopping (40 s in the one observed case; the timeout is unknown), the Mac still treats it as logged in and sends no new Login, so
`upipe_peer.py` sends its own Login at startup; the Mac answers it with a
ResponseResult either way.

### XmlPacket (`0x39`): clipboard

```
39 <xml length BE32> <xml, UTF-8, no terminator>
```

The Mac pushes the clipboard to a logged-in peer as soon as it changes
(`ClipboardHandler` → `sendCBUPipeMessage`); nothing is requested first.
The XML is one line; indented here:

```xml
<ExtraXmlCommand>HookAppService</ExtraXmlCommand>
<ExtraXmlParam><OTIMSG>
  <Param_Clipboard_Info_2><OTIMSG>
    <CP_Content>…</CP_Content>            <!-- text: hex of UTF-16LE, NUL-terminated -->
    <NodeInfoList><Line><NodeInfo>…</NodeInfo></Line>…</NodeInfoList>  <!-- files -->
    <CB_Format_Type>CB_Format_Text | CB_Format_File</CB_Format_Type>
  </OTIMSG></Param_Clipboard_Info_2>
  <NP_Cmd>Cmd_Transfer_Clipboard</NP_Cmd>
  <NP_Up_Notice_NamePipe_Name>\\.\pipe\OTI_ClipboardAgent</NP_Up_Notice_NamePipe_Name>
</OTIMSG></ExtraXmlParam>
```

- Text: `CP_Content` is uppercase hex of the UTF-16LE string including its
  NUL. The Mac reads `public.utf8-plain-text` and converts.
- Files (Finder copy): one `NodeInfo` per file, uppercase hex of an
  824-byte record:

  | Offset | Size | Field |
  |---|---|---|
  | 0 | 260 | path, 8-bit, NUL-padded (`MAX_PATH`); Mac paths are written `/\Users\…` |
  | 260 | 520 | same path, UTF-16LE, NUL-padded |
  | 780 | 3 × 8 | FILETIMEs; observed creation, last access, last write (order inferred from values) |
  | 804 | 4 | size high (observed 0) |
  | 808 | 4 | size low (observed 91 713 for a 91.7 KB `.jpg`) |
  | 812 | 12 | zero in the one sample; meaning unconfirmed |

  All fields are little-endian (the Windows layout), from either side.
  This carries metadata only. The receiver fetches the contents with
  [DownloadMultipleFile](#downloadmultiplefile-0x10-file-contents).
- Files from Linux (`--offer`): the encoder reproduces the Mac's 2 049-byte
  file packet byte for byte. A Linux peer must send the plain POSIX path:
  the Mac names the pasted file after the text behind the last `/`, so the
  Mac's own `/\…` form made the whole path the file name. On paste in
  Finder the Mac logs `Detect dummy paste file, start the download...`,
  writes a `.SKMClipboardFileOfPaste` placeholder and requests the files
  with `0x10`, using the same paths.
- The named-pipe name and `HookAppService` are Windows clipboard-agent
  routing, sent unchanged by the Mac.
- No reply is sent or expected in either direction.
- The same message works from Linux to the Mac (`--clipboard`): the Mac's
  `Clipboard Handler` logs `addFromUPipeMsg(): Found incoming clipboard data and
  success update to pastboard..` and `pbpaste` returns the text, including
  non-ASCII and non-BMP characters (`é ✓ 日本語 😀`) and `\n` line breaks. It
  does not echo the text back (`Found pboard owned by SKM...`).

### DownloadMultipleFile (`0x10`): file contents

From the decompiled `THMGBServer handleDownloadMultipleFile:` and the command
classes' `initFromData`/`encodeData`; verified live in both directions. Every
field is in the sender's byte order and read by the receiver according to the
sender's OS (see [Layer 4](#layer-4-commands)): the Mac sends big-endian
whether it requests or serves, and reads a Linux peer's request and replies
little-endian.

Request, requester → server:

```
10 <multiSessionID u32> <count u16> { <fileID u32> <pathLen u16> <path UTF-16, pathLen bytes> }*
```

A non-Linux sender appends `<destLen u16> <dest>` per file; the Mac decodes
it only when the remote is a Mac. Requesting from a Linux peer, the Mac sends
no destination, ends each path with a UTF-16 NUL (counted in `pathLen`), and
numbers the files from `multiSessionID` up (session 104: file IDs 104 and
105). Its session IDs counted 101, 102, … across requests in one daemon run.

Replies, server → requester, in order:

| ID | Command | Layout (big-endian) |
|---|---|---|
| `0xa1` | ResponseResult | `requestCommand 0x10`, `sessionID = multiSessionID`, result 0 (34 bytes) |
| `0xa3` | DownloadFileData | `a3 <fileID u32> <totalCount u32> <currentIndex u32> <dataLength u32> <data>`; 17-byte header, at most `0x800000` (8 MiB) data bytes per command, so a 20 MiB file arrives as 3 pieces (`totalCount` 3, `currentIndex` 1–3) |
| `0xa7` | DownloadMultiFileFinished | `a7 <multiSessionID u32>` |
| `0xa9` | UploadMultiFileError (instead of `0xa3`/`0xa7` when a file is missing) | `a9 <sessionID u32> <errorCode u32> <errorFileID u32> <tag 6 B> <errorStringLength u32> <errorString UTF-16BE, NUL-terminated>`; seen: code 6, `Read file data error`, tag all zero |

`fileID` in `0xa3` is the requester's `fileID`. After the last piece of each
file the Mac logs `setAttribute: 0` (`ChangeFileAttribute`); it sent no
separate packet for it in the test. A missing file ends the whole request:
the Mac logs `<path> does not exist!!!`, sends `0xa9`, and sends neither the
remaining files nor `0xa7`. Other IDs from the decompile, not seen live:
`0xa5` DownloadFileDataFailed, `0xa6` ResponseDownloadMultiFileZeroLength
(`sessionID u32, count u16, fileIDs`), `0xab` DownloadMultiFileException.
`0x0b` DownloadFile has a class but is not in `commandClassForCommandID:`, so
the Mac cannot receive it.

Serving from Linux (`--offer`), little-endian replies in the order above
were accepted: the Mac logs `Client commandID: A1`, `ResponseResult(0xa1)
{_RequestCommand:16, _RequestResult:0, …}`, `A3`, `A7`, `multi download
finish: <session>` and `[Download]Did download N files`. After an `0xa9` it
keeps the files that arrived, logs `Did download 1 files`, drops the
session, and Wormhole.app shows a `Warning` dialog: `Fail to copy file
"<path>"!` with the path from the `0xa9`'s file. A request left unanswered
gets no timeout, error or dialog in the 4 minutes watched; the next paste
starts a new session.

## Linux peer: `tools/upipe_peer.py`

Stdlib only (SG_IO via ctypes). `/dev/sgN` must be the cable's generic node
(`cat /sys/class/scsi_generic/sgN/device/model` → `WormholeSwitch`) and
readable by your user (`cdrom` group on Debian). Keep `--out` outside the repo.

```sh
# Receive only: poll and fetch, never send
python3 tools/upipe_peer.py /dev/sg1 --out ~/wormhole-private/upipe/RUN --seconds 60
# Also answer the peer's Login and log in to it as "linux-peer"
python3 tools/upipe_peer.py /dev/sg1 --out ~/wormhole-private/upipe/RUN --seconds 60 --login linux-peer
# Also push text to the Mac's clipboard once the Mac accepts the login
python3 tools/upipe_peer.py /dev/sg1 --out ~/wormhole-private/upipe/RUN --seconds 20 --login linux-peer --clipboard "hello"
# Fetch a file from the Mac (absolute path on the Mac); saved as RUN/download_1.bin
python3 tools/upipe_peer.py /dev/sg1 --out ~/wormhole-private/upipe/RUN --seconds 30 --login linux-peer --download "/Users/<user>/file.bin"
# Put local files on the Mac's clipboard and serve them when pasted in Finder
python3 tools/upipe_peer.py /dev/sg1 --out ~/wormhole-private/upipe/RUN --seconds 90 --login linux-peer --offer ./a.bin --offer ./b.bin
python3 -m unittest tools.test_upipe_peer
```

Output: one `pkt_NNNN.bin` per fetched packet and `upipe_peer.jsonl`
(`state`, `packet`, `command`, `queue`, `sent` records), plus
`download_<fileID>.bin` per `--download`. With `--download` the tool stops as
soon as `0xa7` or `0xa9` arrives. `--endian big` sends the request
big-endian; it exists only to reproduce the crash below. `--offer` serves
only the offered files (anything else gets `0xa9`, code 6), re-reading each
file when the request arrives, and exits once a request is answered.

Mac-side tracing uses `tools/gobridge_scsi.d` (dtrace on GoBridgeDemon's
`SCSITaskClass` calls; usage in the script header). It needs root, so it
logs CDBs, data and sense from the Mac's point of view without a second usbmon host.

## Evidence (2026-11-11)

Linux desktop ↔ MacBook (OS X 10.6.8, GoBridgeDemon 152311cb…), cable on bus 5 device 111.

| Run | What happened |
|---|---|
| Mac alone (nothing fetching on Linux) | Mac's 13 send attempts all fail with sense key 9 / ASC `0x85`; its polls still read `0x07` (why, with no Linux poller, is unexplained) |
| `macpeer` (receive only) | Linux polls → state `0x07`, then `0x05` with 2 waiting; fetches Login (seq 2, session 2) and a terminator. Both 64 KiB packets match the Mac's dtrace data-out buffers byte for byte. The Mac logs `login to remote with name: …`, `Send command: 1` and waits |
| `login` (`--login linux-peer`) | Mac's Login (seq 3, session 3) arrives; Linux queues ResponseResult + its own Login (4 packets); all 4 sends succeed; the Mac fetches all 4, logs `ResponseResult(0xa1) {_RequestCommand:1, _RequestResult:0, …}`, `did login to remote`, `[Login Command] Os Type:20 ,name: linux-peer`, `remote has login`, `remote is linux`, and replies with its own 44-byte ResponseResult (OS `0x16`). Wormhole.app logs `remoteDidLoginWithName linux-peer, os: 32` |
| `xfer` (`--login`, then user actions on the Mac) | Same handshake. Copying text sends a 587-byte XmlPacket (`CB_Format_Text`, seq 7); copying a `.jpg` in Finder sends a 2 049-byte one (`CB_Format_File`, one `NodeInfo`, seq 8). Dragging a file toward the Linux side sent nothing: the Mac logs `DragDrop getScreenFrame` and later `Clear the dragdropboard contents`. The Mac logged only these two pasteboard changes (`changeCount` 1 and 2). 39 061 polls, no send errors |
| `clip` (`--login linux-peer --clipboard …`, two runs) | Linux's text arrives in the Mac's pasteboard (checked with `pbpaste` over ssh). The encoder reproduces the Mac's own 587-byte text packet from `xfer` byte for byte. In a second run 40 s later the Mac sent no Login; after the tool was changed to log in first, the Mac answered with a ResponseResult and accepted the second push |
| `dl` (`--download`, big-endian request) | The Mac's GoBridgeDemon threw an uncaught `NSRangeException` (`subdataWithRange: range {12, 23040} exceeds data length 102`): 23040 is `0x5A00`, our big-endian path length `0x005A` read little-endian. Wormhole.app relaunched the daemon (new PID), which sent Login again |
| `dl…le` (`--download`, little-endian request) | Mac logs `remote is linux`, `sever will handle command: DownloadMultipleFile(0x10)`, `Send command: A3`, `setAttribute: 0`, `Send command: A7`. Linux receives ResponseResult (34 bytes, session 1), one 300 017-byte `0xa3` (file 1, index 1 of 1) and `0xa7`. The saved 300 000-byte file's SHA-256 matches the Mac's random test file |
| `dl…big` (`--download`, 20 MiB random file) | Three `0xa3` pieces (8 MiB, 8 MiB, 4 MiB; `totalCount` 3, `currentIndex` 1–3), then `0xa7`. About 1.3 s from the request's ResponseResult to `0xa7` (~16 MB/s). SHA-256 matches |
| `offer` (`--offer`, no serving yet) | Finder paste on the Mac (AppleScript `keystroke "v"` over ssh) leads to a 171-byte big-endian `0x10` (session 101, file ID 101, the offered path plus a NUL, no destination). The Mac then logs `The dummy file has not yet been copied, wait a moment...` 7 times at 0.5 s intervals (`nTimeout` 0–6, the same on every later paste, served or not) and nothing more for session 101 |
| `serve` (`--offer`, Mac-style `/\…` path) | ResponseResult, one 300 017-byte `0xa3`, `0xa7`, all little-endian; the Mac logs `multi download finish: 102`. The pasted file's SHA-256 matches, but its name is the whole `\home\…\wh_serve_test.bin` path |
| `serve…big` (`--offer`, POSIX path, 20 MiB random file) | Named `wh_big.bin`. Three `0xa3` (8, 8, 4 MiB), `0xa7`; 338 sends, none failed, about 1.1 s from the request to the last send (~18 MB/s). SHA-256 matches |
| `serve…err` (`--offer` two files, the second deleted before the paste) | One 315-byte `0x10` for both (session 104, file IDs 104/105). ResponseResult, `0xa3` for the first, `0xa9` (code 6) for the second. The Mac keeps the first file (SHA-256 matches), logs `Did download 1 files`, removes the session; Wormhole.app shows `Fail to copy file "…/wh_gone.bin"!` |
| `dl…missing` (`--download` missing file, then an existing one) | ResponseResult, then a 65-byte `0xa9` (session 1, code 6, file 1, `Read file data error`). Mac logs `… does not exist!!!`, `Send command: A9`. The second file was not sent and no `0xa7` followed. No crash (same daemon PID) |

The `macpeer` usbmon capture, filtered to `5:111` with
`tools/filter_usbmon.py` (19 830 records, sha256 `11b0da0e…`), shows
2 928 poll CDBs and 2 fetches. Its fetched data matches the tool's packet
files. The other 374 SCSI transactions are the kernel's
`GET EVENT STATUS NOTIFICATION` / `REQUEST SENSE` media polling.
`tools/wormhole_parse.py` decodes it as `UPipe: poll 2928 / fetch 2 /
send 0`: 2 927 polls answer `0x07` (remote app online) and one `0x05`
(data waiting, 2 packets); the two fetches are the Mac's Login (session 2,
one chunk, tail OK) and its terminator (#8). Raw captures, packets and Mac logs stay private
because they contain the Mac's host name.

## Open questions

- Drag-and-drop: what it needs from the peer (likely the mouse/KM side; the
  Mac abandoned the drag).
- The `MultipleFilePackage` ID (`TX_MULTIPLE_FILE_PACKAGE`) and when the
  Mac uses it; other `0xa9` error codes.
- Uploads and file operations (`0x11`…, `handleUploadFileData`, rename,
  delete, mkdir): what triggers them from the Mac.
- `0xa6` (zero-length file) and `0xa5`/`0xab`: `--offer` sends an empty file
  as one empty `0xa3`, which is not verified live.
- Image clipboard formats (only text and file seen).
- `--os windows` to get `forwardDomainFoldersInfoToRemote` traffic.
- `DUMMY_DATA` contents, and what the `0xF0` CDB returns.
- Windows peer parity: the same commands are expected but not yet captured.
