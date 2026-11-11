# UPipe protocol: the peer data channel

**What this document answers**

- Which SCSI commands carry peer data (poll, fetch, send) and what the poll reply states mean
- How a 64 KiB OTi packet is framed (integrity tail, chunk header, end-of-command terminator)
- How GoBridge commands are encoded, with Login (`0x01`) and ResponseResult (`0xA1`) in full
- How to stand in for a GoBridge peer from Linux with `tools/upipe_peer.py`
- What is still unknown (file/clipboard command payloads, the `0xF0` CDB, `DUMMY_DATA`)

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
per-command. GoBridgeDemon encodes multi-byte fields big-endian and decodes
them with a byte swap only when `remoteIsBigEndian` (implemented in
`KMClipboard.dylib`, not decompiled).

IDs known to `CommandDataBuffer commandClassForCommandID:`: `0x00` (dummy),
`0x01`, `0x02`, `0x04`, `0x06`–`0x09`, `0x0c`, `0x0e`, `0x10`–`0x15`, `0x37`,
`0x39`, `0x3a`, `0xa1`–`0xa9`, `0xad`. Server side (`THMGBServer`):
`0x01` Login, `0x02` Logout, `0x04` GetDirectoryInfo, and the file
operations listed in [mac-gobridge.md](mac-gobridge.md#file-transfer-command-surface-objc-selectors).
Client side (`THMGBClient`) handles `0xa1`–`0xa9` and `0xad`, starting with
`0xa1` ResponseResult. `0x39` is `XmlPacketCommand`; `OTiCommand doCommand:`
drops it while the server is not connected. Payloads other than Login and
ResponseResult are not decoded yet.

### OS byte

High nibble = type, low nibble = version (`GB_OS_TYPE_MASK 0xf0`,
`GB_OS_VERSION_MASK 0x0f`):

| Type | Value | Versions |
|---|---|---|
| Windows | `0x00` | `OS_WIN31` 1 … `OS_WINXP` 7 |
| Mac | `0x10` | `OS_MACOS_10_0` 0 … `OS_MACOS_10_8` 8 |
| Linux | `0x20` | — |

OS X 10.6.8 sends `0x16`.

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

## Linux peer: `tools/upipe_peer.py`

Stdlib only (SG_IO via ctypes). `/dev/sgN` must be the cable's generic node
(`cat /sys/class/scsi_generic/sgN/device/model` → `WormholeSwitch`) and
readable by your user (`cdrom` group on Debian). Keep `--out` outside the repo.

```sh
# Receive only: poll and fetch, never send
python3 tools/upipe_peer.py /dev/sg1 --out ~/wormhole-private/upipe/RUN --seconds 60
# Also answer the peer's Login and log in to it as "linux-peer"
python3 tools/upipe_peer.py /dev/sg1 --out ~/wormhole-private/upipe/RUN --seconds 60 --login linux-peer
python3 -m unittest tools.test_upipe_peer
```

Output: one `pkt_NNNN.bin` per fetched packet and `upipe_peer.jsonl`
(`state`, `packet`, `command`, `queue`, `sent` records).

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

The `macpeer` usbmon capture, filtered to `5:111` with
`tools/filter_usbmon.py` (19 830 records, sha256 `11b0da0e…`), shows
2 928 poll CDBs and 2 fetches. Its fetched data matches the tool's packet
files. The other 374 SCSI transactions are the kernel's
`GET EVENT STATUS NOTIFICATION` / `REQUEST SENSE` media polling.
`tools/wormhole_parse.py` counts the `d8`/`d9 28` CDBs as `candidate UPipe`
(it does not decode them). Raw captures, packets and Mac logs stay private
because they contain the Mac's host name.

## Open questions

- File, clipboard and XML (`0x39`) command payloads. Next step: run
  `--login` while copying text or dragging a file on the Mac, and try
  `--os windows` to get `forwardDomainFoldersInfoToRemote` traffic.
- `DUMMY_DATA` contents, and what the `0xF0` CDB returns.
- `remoteIsBigEndian` rule (affects how the Mac decodes our big-endian fields).
- Windows peer parity: the same commands are expected but not yet captured.
