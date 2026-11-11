# UPipe protocol: the peer data channel

**What this document answers**

- Which SCSI commands carry peer data (poll, fetch, send) and what the poll reply states mean
- How a 64 KiB OTi packet is framed (integrity tail, chunk header, end-of-command terminator)
- How it differs from the HID `0xD9` injection path
- How GoBridge commands are encoded, and which `THMGBServer`/`THMGBClient`
  handler each command ID reaches ([selector map](#selector-map))
- The clipboard (`0x39` XmlPacket: text, files, TIFF images), file download
  and serving (`0x10`, MultipleFilePackage `0x3a`), the remote browser
  (`0x04`), uploads (`0x13`/`0x12`/`0x15`/`0x0c`) and file operations
  (New Folder, rename, Move to Trash), each verified live against the Mac
- How to stand in for a GoBridge peer from Linux with `tools/upipe_peer.py`
- What is still unknown (drag-and-drop, the aborts, `0x37`, Windows-only
  clipboard formats, the `0xF0` CDB, `DUMMY_DATA`)

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

### Compared with the HID `0xD9` path

| | HID injection | UPipe |
|---|---|---|
| CDB | `d9 '3'/'4'/'6' <12-byte payload> 4f 54`: the CDB *is* the packet | `d8` poll, `d9 28` fetch, `d9 2a` send; the CDB carries no payload |
| Data phase | none | 16 B poll reply, 65 536 B per fetch or send |
| Flow control | none; each CDB is sent on its own | each side polls; sends are gated by the poll state and the peer's announced count |
| Framing | none | packet tail with checksum (Layer 2), chunk header, multi-packet commands reassembled by session (Layer 3) |
| Content | one mouse, key or media report | GoBridge commands: ID byte plus payload (Layer 4) |
| Errors | sense mapped to OTi result codes | same sense mapping ([Send errors](#send-errors)), plus `0xa9` and ResponseResult at the command layer |

Both use 16-byte CDBs ending in `4f 54` on the same mass-storage LUN, and
the same `SCSITask` plumbing in `OTiTransfer`.

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
drops it while the server is not connected. Login, ResponseResult, the
clipboard and drive-list forms of XmlPacket, the file download, the remote
browser, the file operations and the upload are decoded below; other
payloads are not.

Command IDs recovered so far (not exhaustive), from each class's `init`
(`setCommandID:`) in the decompiled GoBridgeDemon:

| ID | Command | ID | Command |
|---|---|---|---|
| `0x01` | Login | `0x39` | XmlPacket |
| `0x02` | Logout | `0xa1` | ResponseResult |
| `0x04` | GetDirectoryInfo | `0xa2` | DirectoryInfo |
| `0x06` | DeleteDirectory | `0xa3` | DownloadFileData |
| `0x07` | MakeNewDirectory | `0xa4` | DriveInfo |
| `0x08` | DeleteFile | `0xa7` | DownloadMultiFileFinished |
| `0x09` | RenameFile | `0xa8` | UploadMultiFileConfirmation |
| `0x0a` | UploadFile | `0xa9` | UploadMultiFileError |
| `0x0c` | UploadFileData | `0xaa` | UploadMultiFileConfirmationExt |
| `0x0d` | UploadFileAbort | `0xad` | DomainFolders |
| `0x10` | DownloadMultipleFile | `0x34` | SyncDynamic |
| `0x11` | DownloadMultipleFileAbort | `0x37` | ChangeFileAttribute |
| `0x12` | UploadMultipleFile | `0x3a` | MultipleFilePackage |
| `0x13` | UploadMultipleFileConfirm | | |
| `0x14` | UploadMultipleFileAbort | | |
| `0x15` | UploadMultipleFileZeroLength | | |

### Selector map

Every command travels in the same `d9 2a` send and `d9 28` fetch packets.
What tells them apart is byte 0 of the reassembled command, not the CDB.
Handlers are `THMGBServer(ServerCommandHandler)` for IDs below `0xa0` and
`THMGBClient(ClientCommandHandler)` for `0xa0` and up. Payload fields are in
the sender's byte order: the Mac sends big-endian, and a Linux peer sends
little-endian ([Layer 4](#layer-4-commands)). Paths are UTF-16.

| Handler | ID | Payload after the ID | Reply | Status |
|---|---|---|---|---|
| `handleLogin:` | `0x01` | `<os> <codePage u16> <nameLen> <name>` | `0xa1` with `OSVERSION` | live, both ways |
| `handleLogout:` | `0x02` | not decoded (60 bytes from the Mac) | `0xa1` (decompile; `upipe_peer.py` sends none) | seen on a Wormhole.app restart |
| `handleGetDirectoryInfo:` | `0x04` | `<len u16> <path>` | `0xa1`, `0xa2` | live |
| `handleRemoveDirectory:` | `0x06` | `<session u32> <len u16> <path>` | `0xa1` 0/1 | live |
| `handleMakeNewDirectory:` | `0x07` | `<session u32> <len u16> <path>` | `0xa1` | live |
| `handleDeleteFile:` | `0x08` | `<session u32> <len u16> <path>` | `0xa1` 0/1 | live |
| `handleRenameFile:` | `0x09` | `<session u32> <oldLen u16> <newLen u16> <old> <new>` | `0xa1`, error code on failure | live |
| `handleUploadFileData:` | `0x0c` | `<fileID u32> <total u32> <index u32> <len u32> <data>` | `0xa7` when the session completes | live |
| `handleDownloadMultipleFile:` | `0x10` | `<multi u32> <count u16> {<fileID u32> <len u16> <path>}` | `0xa1`, `0xa3`…, `0xa7` or `0xa9` | live, both ways |
| `handleDownloadMultipleFileAbort:` | `0x11` | not decoded | — | not observed |
| `handleUploadMultipleFile:` | `0x12` | `<multi u32> <count u16> {<fileID u32> <len u16> <path>}` | only on error | live |
| `handleUploadMutipleFilesConfirm:` | `0x13` | `<multi u32> <size u64> <large u16> <count u16> {…}` | `0xa8` | live |
| `handleUploadMultipleFileAbort:` | `0x14` | `<multi u32>` | none | from the decompile, not observed |
| `handleUploadMultipleFilesWithZeroLength:` | `0x15` | as `0x12` | `0xa9` code 3 on failure only | live |
| `handleChangeFileAttribute:` | `0x37` | not decoded | — | not observed |
| `handleExtraXMLPacket:` | `0x39` | `<xmlLen u32> <xml>` | none | live, both ways (clipboard, drive list) |
| (`THMFileManager handleMultipleFilePackage:`) | `0x3a` | `<count u32 LE> <11 bytes> <commands>` | per command | live, peer → Mac only |
| `handleRequestResponse:` | `0xa1` | see [ResponseResult](#responseresult-0xa1) | — | live |
| `handleDirectoryInfo:` | `0xa2` | `<count u16> <552-byte records> <free u64> <pad>` | — | live |
| `handleDownloadFileData:` | `0xa3` | as `0x0c` | — | live, both ways |
| `handleDriveInfo:` | `0xa4` | not decoded | — | not observed (a Linux peer uses the XML drive list) |
| `handleDownloadFileZero:` | `0xa6` | `<session u32> <count u16> <fileIDs>` | — | not observed: the Mac sends an empty file as one empty `0xa3` |
| `handleUploadDownloadFinish:` | `0xa7` | `<session u32>` | — | live, both ways |
| `handleUploadMultipleFileConfirmation` | `0xa8` | `<4 flags> <session u32> <existCount u32> <IDs>` | — | live |
| `handleUploadMultiFileError` | `0xa9` | `<session u32> <code u32> <fileID u32> <tag 6> <len u32> <string>` | — | live, both ways |
| `handleDomainFolders:` | `0xad` | not decoded | — | not observed (sent to Windows/Mac peers only) |
| `handleTransferFailed:` | ? | not decoded | — | not observed |

Sections: [Login](#login-0x01), [clipboard](#xmlpacket-0x39-clipboard),
[images](#xmlpacket-0x39-images), [download](#downloadmultiplefile-0x10-file-contents),
[package](#multiplefilepackage-0x3a-several-commands-in-one),
[browser](#getdirectoryinfo-0x04-and-directoryinfo-0xa2),
[file operations](#file-operations-new-folder-rename-move-to-trash),
[upload](#upload-mac--shared-folder).

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

### XmlPacket (`0x39`): images

A copied picture travels as paths, not pixels. The Mac writes the
pasteboard's TIFF and a 24-bit Windows BMP of it to temp files and sends
(1 024 bytes for a 900 × 505 image):

```xml
<CP_Content_Text></CP_Content_Text>
<CP_Content_Bitmap_ImageFile>…</CP_Content_Bitmap_ImageFile>  <!-- …/-Tmp-/CBBitmapContent.tmp, BMP -->
<CP_Content_ImageFile>…</CP_Content_ImageFile>                <!-- …/-Tmp-/CBContent.tmp, the TIFF -->
<CB_Format_Type>Apple TIFF Format</CB_Format_Type>
```

inside the same `Param_Clipboard_Info_2` wrapper as text. Each path is
uppercase hex of UTF-16LE plus NUL, in the Mac's `/\var\folders\…` form.
The receiver fetches the files itself with `0x10`, using the POSIX path
(`/var/folders/…`). Fetched from Linux, both matched the Mac's temp files
byte for byte, and `CBContent.tmp` matched the copied TIFF.

Receiving (KMClipboard's `COSXClipboardAppleBaseConverter`), the Mac:

1. reads `CP_Content_ImageFile` and downloads it at once (`Enter
   handleDownloadClipboardFile`, a normal `0x10` session) into its temp folder;
2. puts the bytes on the pasteboard as the format's type (`Apple TIFF Format`
   → `NSTIFFPboardType`);
3. if `CP_Content_Bitmap_ImageFile` is present, downloads it too, opens it
   with `NSImage` (any format it reads) and adds its `TIFFRepresentation`.

An empty `CP_Content_Bitmap_ImageFile` element crashed GoBridgeDemon
(`ConvertHexStringToPath` on an empty string, `EXC_BAD_ACCESS` in
`+[StringUtil stringWithLittleEndianUnicodeData:]`). Without the element the
Mac skips step 3. Other receive converters in KMClipboard, not tried:
`CB_Format_DIB` (also lands as TIFF), `CB_Format_MutipleImages`,
`CB_Format_RTF`, `CB_Format_PPT_ActiveClipboard`, and the Apple PDF, PICT,
RTF, RTFD and HTML formats.

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

### MultipleFilePackage (`0x3a`): several commands in one

```
3a <count u32, little-endian> <11 bytes, skipped> <command>*
```

`MultipleFilePackage initFromData:` reads the count without a byte swap,
starts at offset 15 of the payload, and for each command reads its ID,
decodes it with that command's class and steps by its header plus data
length. `THMFileManager handleMultipleFilePackage:` hands each command to the
server (ID < `0xa0`) or the client (ID ≥ `0xa0`). The Mac's own `encodeData`
writes only the header, so the Mac never sends a usable one, but it accepts
one from a peer. Serving four small files as one `0x3a` holding four `0xa3`,
the Mac logged `counts=4`, `Exit from MultipleFilePackage:initFromData:`, then
`Did download 4 files` after the `0xa7`. `upipe_peer.py` bundles runs of
whole-file `0xa3` pieces (single-piece files next to each other in the
request) up to 8 MiB per package. A run of one, and pieces of split files,
stay bare.

### Serving to the Mac

Serving from Linux (`--offer`), little-endian replies in the order above
were accepted: the Mac logs `Client commandID: A1`, `ResponseResult(0xa1)
{_RequestCommand:16, _RequestResult:0, …}`, `A3`, `A7`, `multi download
finish: <session>` and `[Download]Did download N files`. After an `0xa9` it
keeps the files that arrived, logs `Did download 1 files`, drops the
session, and Wormhole.app shows a `Warning` dialog: `Fail to copy file
"<path>"!` with the path from the `0xa9`'s file. A request left unanswered
gets no timeout, error or dialog in the 4 minutes watched; the next paste
starts a new session.

### Drive list (`0x39`): remote browser roots

A Linux peer announces its folders with an XmlPacket (from the decompiled
`NP_Cmd_Post_Drive_Update_Info` handling; one line on the wire):

```xml
<ExtraXmlCommand>HookAppService</ExtraXmlCommand><ExtraXmlParam><OTIMSG>
  <NP_Cmd>NP_Cmd_Post_Drive_Update_Info</NP_Cmd>
  <NP_Remote_Request_Info><NP_Misc_Drive_ListMRS>
    <Line><NP_Misc_Drive_Letter>/home/user/share</NP_Misc_Drive_Letter>
          <NP_Misc_Drive_Total_Space_Number>N</NP_Misc_Drive_Total_Space_Number>
          <NP_Misc_Drive_Free_Space_Number>N</NP_Misc_Drive_Free_Space_Number></Line>
  </NP_Misc_Drive_ListMRS></NP_Remote_Request_Info>
</OTIMSG></ExtraXmlParam>
```

`upipe_peer.py --share` sends it once the Mac accepts our Login. Wormhole.app's
window then reads `Remote Computer: Android Android`, shows the drive path in
its path bar and requests its listing with `0x04`. The sidebar's DEVICES list
stays empty.

### GetDirectoryInfo (`0x04`) and DirectoryInfo (`0xa2`)

```
04 <pathLen u16> <path UTF-16, no NUL>
```

The server answers with ResponseResult (`requestCommand` 4, result 0), then:

```
a2 <count u16> <count × 552-byte record> <freeSpace u64> <pad byte>
```

Record (`0x228` bytes, ten u32 words, then the name):

| Offset | Field |
|---|---|
| 0 | attributes: `0x10` directory, `0x02` hidden, `0x01` read-only, `0x04` root-owned, `0x10000` symlink |
| 4, 8 | creation time, low word then high word, Unix seconds |
| 12, 16 | last access time, same form |
| 20, 24 | last write time, same form (the Date Modified column) |
| 28, 32 | size, low word then high word (a 5 GiB file showed as `5 GB`) |
| 36 | name length in bytes (at most 512) |
| 40 | name, UTF-16, no NUL |

The time and size words were settled live: a probe listing one entry per
candidate encoding showed the right date only for (low, high) Unix seconds.
The decoder reads `freeSpace` only when at least one more byte follows it
(`offset < length − 9`), so the pad byte is needed. Without it the window
shows `0 bytes available`; with it, the share's real free space. Expanding a
folder's disclosure triangle, and the Mac's refresh after every paste, send a
new `0x04` for that path. On error the server sends ResponseResult result 1,
error code 3, and no `0xa2`.

### File operations: New Folder, rename, Move to Trash

All three are requests to the server, which answers each with a
ResponseResult for that command (session 0; result 0 on success, 1 on
failure), then the Mac re-lists the folder with `0x04`. Paths are UTF-16
with a NUL counted in the length.

```
07 <sessionID u32> <pathLen u16> <path>                       MakeNewDirectory
09 <sessionID u32> <oldLen u16> <newLen u16> <old> <new>      RenameFile
08 <sessionID u32> <pathLen u16> <path>                       DeleteFile
06 <sessionID u32> <pathLen u16> <path>                       DeleteDirectory
```

- **New Folder** (File menu) sends `0x07` for `untitled folder` in the folder
  being viewed (a selected subfolder is not used). The Mac picks the name: with
  `untitled folder` present it sent `untitled folder 2`. Before every paste
  it also sends `0x07` for the destination folder itself, with the upload's
  session ID, so an existing folder must count as success.
- **Rename** (edit the name in place) sends `0x09` with session 0 and both
  full paths. On result 1 Wormhole.app shows `Fail to rename file "<old
  name>"!` and keeps the old name. The Mac's server sets error code and tag
  `ErrStr` on failure; `upipe_peer.py` sends error code 3.
- **Move to Trash** (File menu) first asks `The item will be deleted
  immediately. Are you sure you want to continue?`. For a file it sends
  `0x08` (session 0). For a folder it walks the tree itself: `0x04` for each
  folder, `0x08` for each file in it, then `0x06` for the emptied folder (seen
  with session 103). The Mac's own server (`handleDeleteFile:`,
  `handleRemoveDirectory:`) calls `moveToTrash:` and answers result 0 or 1
  with no error code, so despite the warning nothing is deleted outright.
  `upipe_peer.py` does the same with the freedesktop.org home Trash
  (`$XDG_DATA_HOME/Trash`, default `~/.local/share/Trash`: the item goes to
  `files/`, a `.trashinfo` record to `info/`), so file managers can restore
  it.

### Upload: Mac → shared folder

A Finder copy pasted into Wormhole.app's remote browser (Edit > Paste) runs:

1. `0x07` for the destination folder (above).
2. `0x13` UploadMultipleFileConfirm, Mac → server:
   ```
   13 <multiSessionID u32> <allFileSize u64> <largeFilesCount u16> <count u16>
      { <fileID u32> <pathLen u16> <path UTF-16 + NUL> }*
   ```
   Paths are destination paths on the server.
3. `0xa8` UploadMultiFileConfirmation, server → Mac:
   ```
   a8 <readOnly u8> <freeSpace u8> <fileSystem u8> <destRootReadOnly u8>
      <sessionID u32> <existCount u32> <existFileID u32>*
   ```
   The Mac stops when `freeSpace` is 0 or `destRootReadOnly` is 1. For each
   ID in the exist list it shows its own `An item named "…" already exists
   in this location` dialog (Don't Replace / Stop / Replace, Apply to all).
   Don't Replace sent nothing more for that file (one file: no `0x12` at
   all, only a refresh). Replace went on as below and overwrote the file.
4. `0x15` UploadMultipleFileZeroLength for the paste's empty files, if
   any, in the same layout as `0x12`. The Mac's server creates them
   (`createZeroLengthFiles:withErrorFileID:`) and answers only on failure,
   with `0xa9` code 3. A paste of only empty files ends here; the Mac sends
   no data and expects no `0xa7`.
5. `0x12` UploadMultipleFile, Mac → server, with no size fields, for the
   other files:
   ```
   12 <multiSessionID u32> <count u16> { <fileID u32> <pathLen u16> <path UTF-16 + NUL> }*
   ```
   The server answers only on error (ResponseResult result 1).
6. `0x0c` UploadFileData, Mac → server, one per piece, in the same form as
   `0xa3`: `0c <fileID u32> <totalCount u32> <currentIndex u32> <dataLength u32> <data>`,
   at most 8 MiB per piece. Files go one after another.
7. When every file of the session is written, the server sends `0xa7`
   DownloadMultiFileFinished with the session ID. An error goes out as `0xa9`
   (code 3, `Remote operation error`). `0x14` UploadMultipleFileAbort carries
   the session ID.

`0x0a` UploadFile and `0x0d` exist but were not seen.

### Copy: shared folder → Mac

Selecting a file in the remote browser, Edit > Copy, then Paste in Finder
sends the same `0x10` request as a clipboard paste, for the shared path
(session 106, file ID 107: here the file ID did not equal the session ID).
The replies are those of [DownloadMultipleFile](#downloadmultiplefile-0x10-file-contents).

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
# Share a folder: browse it, copy from it and paste into it from Wormhole.app
python3 tools/upipe_peer.py /dev/sg1 --out ~/wormhole-private/upipe/RUN --seconds 600 --login linux-peer --share ~/share
# Put a TIFF on the Mac's clipboard; save every image the Mac copies as RUN/clipboard_<n>.tiff
python3 tools/upipe_peer.py /dev/sg1 --out ~/wormhole-private/upipe/RUN --seconds 30 --login linux-peer --clipboard-image ./pic.tiff
python3 tools/upipe_peer.py /dev/sg1 --out ~/wormhole-private/upipe/RUN --seconds 300 --login linux-peer --save-clipboard-images
python3 -m unittest tools.test_upipe_peer
```

Output: one `pkt_NNNN.bin` per fetched packet and `upipe_peer.jsonl`
(`state`, `packet`, `command`, `queue`, `sent` records), plus
`download_<fileID>.bin` per `--download` and `clipboard_<n>.tiff` per image
with `--save-clipboard-images`. With `--download` the tool stops as
soon as `0xa7` or `0xa9` arrives. `--endian big` sends the request
big-endian; it exists only to reproduce the crash below. `--offer` serves
only the offered files (anything else gets `0xa9`, code 6), re-reading each
file when the request arrives, and exits once a request is answered.
`--share` (repeatable) runs for `--seconds`. It lists, serves, creates
folders, renames, trashes and accepts uploads only inside the shared folders,
after resolving symlinks. It never renames onto an existing name, and never
renames or trashes a shared folder itself. Trashing a symlink moves the link,
not its target. A request it cannot parse gets ResponseResult result 1
instead of stopping the tool. When the Mac logs out (Wormhole.app
restarted), the tool logs in again once the restarted daemon logs in, and
resends the drive list.

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
| `share` (`--share`, then browsing on the Mac) | The drive list shows the share in Wormhole.app; the Mac requests its listing (`0x04`, 71 bytes). Names, sizes (a 5 GiB sparse file as `5 GB`), dates and folders show; expanding `subdir` requests it. Free space showed `0 bytes available` until the pad byte was added, then `73.47 GB available` (`df`: 78 886 010 880 bytes) |
| `upload` (Finder copy, Paste in the remote browser) | `0x07`, `0x13` (100 000 bytes) → `0xa8`, a 101-byte `0x12`, one `0x0c`, then our `0xa7` and the Mac's refresh. SHA-256 matches. The first try crashed the tool: it parsed `0x12` with `0x13`'s layout. The Mac's window then stayed busy until Wormhole.app was restarted |
| `upload…big`, `upload…two` | 20 MiB: three `0x0c` (8, 8, 4 MiB), about 1.3 s from `0x12` to the last piece (~16.5 MB/s). Two files in one paste: one `0x13`/`0x12` pair listing both, the pieces file by file, one `0xa7`. All hashes match |
| `upload…exists` (same file pasted again) | `0xa8` lists the file's ID; the Mac shows its replace dialog. Don't Replace: no `0x12`, file unchanged. Replace: `0x12`, `0x0c`, file overwritten (hash matches) |
| `fileops` (`--share`, File menu and in-place rename on the Mac) | Move to Trash on a file: `0x08` (105 bytes, session 0) → result 0, the file lands in the test Trash with its `.trashinfo`. On a folder with one file: `0x04` for it, `0x08` for the file, `0x06` for the folder (session 103). Rename: `0x09` (213 bytes) → result 0, renamed. Rename onto an existing folder: result 1, error code 3; the Mac shows `Fail to rename file …!` and nothing changes. New Folder twice: `0x07` for `untitled folder`, then `untitled folder 2` |
| `img` (`--login`; a 900 × 505 TIFF set as the Mac's clipboard) | A 1 024-byte XmlPacket, `Apple TIFF Format`, with the two temp paths; the encoder reproduces it byte for byte. `--download` of both paths: the TIFF (1 818 400 bytes) and the BMP (1 363 554), SHA-256 equal to the Mac's files. `--save-clipboard-images` saved the TIFF as `clipboard_1.tiff` (same hash) |
| `imgpush` (`--clipboard-image`, 200 × 100 TIFF) | First try with an empty Bitmap element: the Mac fetched the file, then GoBridgeDemon crashed (above). Without the element: the Mac fetched it with `0x10` and its clipboard held the 60 140-byte TIFF; read back, 200 × 100 |
| `pkg` (`--offer`, small files) | Two, then four, small files in one `0x3a`: the Mac logs `counts=2`/`counts=4` and `Did download N files`; all hashes match. With a 20 MiB file between two small ones nothing is bundled, and all three match |
| `empty` (empty files) | `--download` of an empty Mac file: `0xa1`, one empty `0xa3`, `0xa7` (no `0xa6`). Pasting an empty file into a share: `0x07`, `0x13` (size 0), `0x15`; before the fix the tool ignored `0x15` and the file was silently missing, with no error on the Mac. After the fix the file is created. A mixed paste (empty plus 100 kB) sends `0x13` listing both, `0x15` for the empty one, `0x12` and `0x0c` for the other; both arrive and the hash matches |
| `sharedl` (Copy in the remote browser, Paste in Finder) | The Mac sends `0x10` for the shared path; ResponseResult, `0xa3`, `0xa7`; the Mac logs `Did download 1 files`. SHA-256 matches |
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

Mac-side items are tracked in #51; the Windows formats and parity in #50.

- Drag-and-drop: what it needs from the peer (likely the mouse/KM side; the
  Mac abandoned the drag).
- Other `0xa9` error codes.
- `0x37` ChangeFileAttribute: the Mac logs `setAttribute: 0` after each
  downloaded file but sent none in the tests.
- `0x0a` UploadFile, `0x0d`, `0xaa`, `0xa4`, `0xa5`, `0xa6`, `0xab`: when
  the Mac uses them.
- The aborts (`0x11`, `0x14`): cancel a transfer mid-way to capture them.
- The other clipboard formats (`CB_Format_DIB`, `CB_Format_MutipleImages`,
  RTF, HTML, PDF): expected from Windows peers; only text, file and TIFF seen.
- `--os windows` to get `forwardDomainFoldersInfoToRemote` traffic.
- `DUMMY_DATA` contents, and what the `0xF0` CDB returns.
- Windows peer parity: the same commands are expected but not yet captured.
