# 15-byte CDB truncation (Issue #16)

Root cause of the short vendor HID CDBs seen in the original peer to
local run: the peer host submitted 15-byte CDBs. This is a host-side
short send, not a usbmon capture limit and not a device firmware
truncation. The device received the 15-byte CDBs and correctly
rejected them (CHECK CONDITION, sense key 9, ASC FF/FF).

Note on sizes: no 32-byte CDB exists in any capture. The Wormhole
vendor HID packet is a 16-byte CDB (`D9 <type> <12 payload> OT`, see
`docs/protocol-mouse-upipe.md`). The short frames are missing one zero
pad byte from the 12-byte payload, leaving 15 bytes, not truncated
from 32.

## Where the short frames are

All seven 15-byte CDBs are in `captures/wormhole_bus1_live_2026-11-06.pcap`
(peer host, Wormhole 1:6, unfiltered file, 524 packets). The two
local-host files named in the issue are negative controls:
`wormhole_bus3_2026-11-06.pcap` is idle (zero `0xD9` CDBs) and
`wormhole_bus3_synth_2026-11-06.pcap` has one 16-byte `0xD9` at frame
7, accepted (CSW good). Frame numbers below are parser frame numbers
(pcap record index, 1-based).

| Frame | Tag | CDB (hex) | Len | CSW | Sense after |
|---|---|---|---|---|---|
| 99 | 0x46ff | `d93300280000000000000000004f54` | 15 | CHECK CONDITION | key 9, ASC FF/FF at f103 |
| 109 | 0x4701 | `d93300320000000000000000004f54` | 15 | CHECK CONDITION | key 9, ASC FF/FF at f113 |
| 131 | 0x4705 | `d933003c000000000000000000004f54` | 16 | good | (the one success; includes the only forwarded report on the local host, EP3 `x=+60` at raw frame 617) |
| 147 | 0x4708 | `d93301000000000000000000004f54` | 15 | CHECK CONDITION | key 9, ASC FF/FF at f151 |
| 157 | 0x470a | `d93300000000000000000000004f54` | 15 | CHECK CONDITION | key 9, ASC FF/FF at f161 |
| 179 | 0x470e | `d93400000500000000000000004f54` | 15 | CHECK CONDITION | key 9, ASC FF/FF at f183 |
| 201 | 0x4712 | `d93400000000000000000000004f54` | 15 | CHECK CONDITION | key 9, ASC FF/FF at f205 |
| 239 | 0x4718 | `d93300000001000000000000004f54` | 15 | CHECK CONDITION | key 9, ASC FF/FF at f243 |

Sense data (18 bytes, all seven identical):
`70 00 09 00 00 00 00 0a 00 00 00 00 ff ff 00 00 00 00`.

Full 31-byte CBWs (SUBMIT payloads, `tools/wormhole_parse.py`
output, confirmed with `tcpdump -r` / `tshark -x`):

```
f99 (short):  55534243 ff460000 00000000 00 00 0f  d93300280000000000000000004f54 00
f131 (good):  55534243 05470000 00000000 00 00 10  d933003c000000000000000000004f54
```

Byte map of the mouse X=+40 case. Valid 16-byte form:
`D9 33 00 28 00 00 | 00 00 00 00 00 00 00 00 | 4F 54`
(payload `00 28 00 00` + eight pad zeros + `OT`).
Observed 15-byte form:
`D9 33 00 28 00 00 | 00 00 00 00 00 00 00 | 4F 54`
(one pad zero missing, `OT` shifted left one byte, CBW length byte
`0x0f`, trailing CBW pad byte `00`). Inserting a single `00` before
`OT` in every short CDB yields a valid 16-byte HID frame
(`valid_hid_framing=True` for all seven reconstructions), so the
payload content is otherwise intact.

Positive controls (all accepted, all 16 bytes): 9 of 9 local to peer
sends in `wormhole_bus3_live3_2026-11-06.pcap` (frames 43, 47, 63, 67,
83, 87, 103, 169, 185), 1 of 1 in the synth capture (f7), 2 of 2 in
`wormhole_bus3_live_2026-11-08.pcap` (f3711, f3727), and 12 of 12 in
the same-day re-run (see `docs/live-capture-2026-11-06.md`).

## Hypothesis discrimination

### 1. usbmon kernel buffer limit: ruled out

- pcap snaplen is 245824 bytes; largest packet in any capture is
  160 bytes. Zero records have `incl_len < orig_len` in any file
  (checked record by record, all six published pcaps). Nothing was
  dropped by the capture layer.
- Every CBW SUBMIT payload is exactly 31 bytes (`urb_len=31`,
  `data_len=31`, `payload_len=31`), including all seven short
  frames. A capture truncation would cut the tail of the record; it
  cannot rewrite the CBW CDB-length byte from `0x10` to `0x0f`,
  shift the `OT` footer one byte left, and append a `00` pad byte.
- The same host, bus and file captured a complete 16-byte CBW
  (f131) between short ones, plus 6-byte and 10-byte kernel CDBs
  throughout. Data phases up to 252 bytes (INQUIRY etc.) also
  arrive intact.
- The 8-byte CBW COMPLETE echoes in usbmon are a known usbmon
  behaviour (the parser ignores them); they occur for good and
  short frames alike and are unrelated to this issue.

### 2. Device firmware truncation: ruled out

- usbmon SUBMIT records describe the URB the host submitted to the
  device. The device cannot retroactively shorten a CBW that the
  host already emitted. The 15-byte length is already present in
  the host-submitted CBW (length byte `0x0f`, shifted footer).
- The same device accepted 16-byte `0xD9` CDBs in this session
  (f131) and in every other session, so a firmware length cap of 15
  is false.
- The firmware's response (CHECK CONDITION + sense `9 / FF FF`,
  distinct from the kernel-polling sense `5 / 0x20` for `LOG
  SENSE`) shows it parsed the 15-byte CDB as sent and rejected
  invalid framing. Rejection is the downstream effect, not the
  cause. Deliberate 15-byte controls in the re-run (phase P4)
  reproduce the identical sense.

### 3. Host driver / tool input: confirmed

The 15-byte CDB existed before the CBW was built: the usb-storage
driver copies `cmd_len` bytes from the CDB buffer supplied via the
SG interface, and the CBW length byte (`0x0f`) plus shifted `OT`
show the source buffer itself was 15 bytes. The most plausible
mechanism is a short input on the peer host (one `00` omitted when
the `sg_raw` bytes were typed or assembled), with the single 16-byte
success (mouse `X=+60`, f131) being the one command typed
correctly. The same-day re-run shows `sg_raw -C 1` delivers complete
16-byte frames when given complete frames (phase P1, 4 of 4 Good),
so `sg_raw` does not truncate. The original run's typed commands
were not recorded, so the exact typo cannot be pinned from the
capture; the wire evidence only proves the CDB was short before
the CBW was built.

## Correlation checks

- Opcode: only `0xD9` ever varies. Across all captures,
  `REQUEST SENSE` is always 6 bytes (451 cases), `GET EVENT STATUS NOTIFICATION` (`0x4A`) always
  10 (429), kernel `TEST UNIT READY` / `INQUIRY` etc. always 6 or
  10. No non-`0xD9` CDB is ever short. Shortness is specific to the
  hand-built vendor CDBs.
- Data phase direction and transfer length: all `0xD9` commands
  (short and good) are OUT with `cbw_data_len=0` (no data phase).
  Shortness does not correlate with direction or length; both
  populations share them exactly.
- HID type: mouse (`'3'`) 5 short / 1 good, keyboard (`'4'`) 2
  short, wheel also short. No type correlation.
- Timing: inter-send gaps are regular (~1.37 to ~1.39 s; the good
  frame sits mid-sequence at +1.386 s). No timing correlation; the
  re-run at 0.25 s spacing also showed no timing guard.

## Reproduce

```sh
python3 tools/wormhole_parse.py captures/wormhole_bus1_live_2026-11-06.pcap --all
python3 tools/wormhole_parse.py captures/wormhole_bus3_synth_2026-11-06.pcap --all
tcpdump -r captures/wormhole_bus1_live_2026-11-06.pcap -xx | less
```

Open only: the original typed command (not recorded) and a
peer-side wire log, which would show the same 15-byte CBW leaving
the peer host and close the loop. Neither changes the verdict: the
shortening predates the CBW, the capture, and the device.
