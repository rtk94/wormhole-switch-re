# Reproduction

All commands assume an x86_64 Linux host with the Wormhole plugged into one USB port. Bus numbers differ per host — confirm with `lsusb` first.

## 1. Enumerate

```sh
lsusb
lsusb -t
lsusb -v -d 0711:2211          # expect: 3 interfaces (1× Mass Storage, 2× HID)
for f in /sys/bus/usb/devices/*:1.*/bInterfaceClass; do
  echo "$f: $(cat $f)"
done
# expect: 08 (Mass Storage), 03 (HID), 03 (HID) — no 0E (Video)
```

If `lsusb -v` says `** UNAVAILABLE **` for HID report descriptors, read them from sysfs:

```sh
for n in /sys/class/hidraw/hidraw*/; do
  echo "== $n =="
  python3 -c "d=open('$n/device/report_descriptor','rb').read(); print(len(d), d.hex())"
done
```

## 2. SCSI identities

```sh
lsblk -o NAME,PATH,TRAN,SIZE,MOUNTPOINT /dev/srX
ls -l /sys/block/srX/device/{vendor,model,rev}
# expect: vendor j5create, model WormholeSwitch, rev 2.00

sg_inq /dev/sgX
sg_readcap /dev/sgX          # expect: Last LBA 1592, 2048 B
sg_readcap --16 /dev/sgX     # expect: Illegal Request / Invalid opcode on this firmware
sg_readcap /dev/sgX -H       # raw: 00 00 06 38 00 00 08 00
cat /sys/block/srX/size      # observe: 31744 (15.5 MiB) — vs 3.1 MiB above
```

Mount (automount handles it as `/media/$USER/WORMHOLE`):

```sh
sudo mkdir -p /tmp/wormhole_mnt
sudo mount -o ro /dev/srX /tmp/wormhole_mnt
ls -lR /tmp/wormhole_mnt
# verify hashes: see docs/iso-payload.md
```

## 3. HID identities

```sh
cat /proc/bus/input/devices | grep -A6 Wormhole
# expect: j5create WormholeSwitch, two entries (mouse + sysrq/kbd)
ls -l /dev/hidraw*
cat /sys/class/hidraw/<n>/device/input/*/name
```

## 4. USB capture (usbmon)

```sh
sudo modprobe usbmon
sudo tcpdump -D | grep usbmon     # list usbmonN interfaces
# Bus 3 in the log in docs/capture-log.md; adjust to your bus:
sudo tcpdump -i usbmon3 -w wormhole.pcap &
# in another terminal, interact:
sg_inq /dev/sgX
sg_readcap /dev/sgX
dd if=/dev/srX of=/tmp/out.bin bs=512 count=16
# stop:
sudo pkill tcpdump
capinfos wormhole.pcap
tcpdump -r wormhole.pcap -c 20 -v -X
```

CBW signature is `55 53 42 43` (`USBC`), CDB starts at byte 15. E.g. LOG SENSE is `4A 01 00 00 10 ...`, REQUEST SENSE is `03 00 00 00 12 00`, INQUIRY is `12 00 00 00 24 00`, READ CAPACITY(10) is `25 00 00 00 00 00`.

## 5. REA analysis (target-free)

Copy the ISO to a writable scratch dir (ISO mount is read-only and non-writable — `chmod -R u+w` after copy or copy to a new dir):

```sh
mkdir -p /tmp/wormhole && sudo cp -a /media/$USER/WORMHOLE/. /tmp/wormhole/
```

Then, via the `reverse-engineer-anything` skill:

- `inspect_pe_imports` / `inspect_pe_resources` / `inspect_pe_certificates` on `SKLoader.exe`
- Carve the DLL resource (offset 70520, size 104488 in that sample) and run `inspect_pe_imports` again
- `open_binary` on `GoBridgeDemon` (Mach-O) for deep analysis (requires aligned Ghidra)

Prerequisites to enable the blocked paths:

```sh
# tshark for REA pcap tools (Wireshark 4.x)
sudo apt install wireshark-common

# UPX for embedded DLL
sudo apt install upx-u

# Ghidra 12.1.x for REA deep analysis (REA 6.8.0 verifies 12.1.4)
# Install side-by-side, e.g. /opt/ghidra_12.1.4_PUBLIC, then point REA at it:
#   sudo ln -sfn /opt/ghidra_12.1.4_PUBLIC/ghidraRun /usr/local/bin/ghidra
# (REA discovers Ghidra via the `ghidra` launcher on PATH), or per-invocation:
#   GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.4_PUBLIC rea doctor --provider ghidra
# Verify: rea doctor --provider ghidra  # healthy, version 12.1.4
```

## 6. Second-machine bridge test (live peer-active capture)

Plug the other end into a second PC, leave both ends connected.  The local
enumeration is identical whether or not the peer is connected — the
peer link is internal to the cable — so a capture only shows *effects*
(host → cable vendor CDBs, cable → host HID reports).  The peer
microcontroller's forwarding itself is not visible from one host.

### 6.0 Where captures go

`tcpdump -i usbmon<N>` records every device on that bus, not just the Wormhole
(keyboards, mice, other storage).  Keep raw captures out of the repo and
publish only a copy filtered to the Wormhole:

```sh
mkdir -p ~/wormhole-private/raw-captures
lsusb -d 0711:2211                 # Bus:Dev changes on re-enumeration; use the current one
python3 tools/wormhole_parse.py RAW.pcap --all --no-transactions   # check the device table
python3 tools/filter_usbmon.py RAW.pcap --device 3:15 -o captures/OUT.pcap   # 3:15 = Bus:Dev from lsusb
```

Filter whenever the device table lists anything besides the Wormhole and its
root hub.  `docs/live-capture-2026-11-06.md` has the 2026-11-06 check.

### 6.1 Find the bus

```sh
lsusb -t                        # note the Wormhole Bus number (e.g. Bus 003)
sudo tcpdump -D | grep usbmon   # usbmonN matches that Bus
# this repo's sample is Bus 3 (usbmon3); use your own N below
```

### 6.2 Idle baseline (no Wormhole software on either side)

```sh
RAW=~/wormhole-private/raw-captures/wormhole_bus3_idle_$(date +%F).pcap
sudo tcpdump -i usbmon3 -w "$RAW" &
sleep 30
sudo pkill tcpdump
python3 tools/filter_usbmon.py "$RAW" --device 3:15 -o captures/wormhole_bus3_idle_$(date +%F).pcap
python3 tools/wormhole_parse.py captures/wormhole_bus3_idle_*.pcap
# expect: only kernel LOG SENSE / REQUEST SENSE pairs, 0 vendor HID (0xD9),
# 0 Wormhole HID reports — as in docs/capture-log.md
```

### 6.3 Peer-active session (GoBridge/Wormhole on both ends)

1. On each machine, install and run the software from the ISO
   (`Wormhole.app` → `WormholeShell` extracts `Wormhole.tgz` to
   `~/Library`; see `docs/iso-payload.md`).  On macOS `GoBridgeDemon`
   needs Accessibility permission for the CGEvent taps.
2. On the capturing host, start the capture **before** switching:

```sh
RAW=~/wormhole-private/raw-captures/wormhole_bus3_live_$(date +%F).pcap
sudo tcpdump -i usbmon3 -w "$RAW" &
```

3. Switch to the peer (hotkey or cross the screen edge), then in
   sequence while the capture is running:
   - move the mouse in a pattern (relative moves)
   - click / scroll
   - type a short string on the keyboard
   - drag a small file between machines (or copy a clipboard item)
   - switch back to local
4. Stop the capture and parse:

```sh
sudo pkill tcpdump
python3 tools/filter_usbmon.py "$RAW" --device 3:15 -o captures/wormhole_bus3_live_$(date +%F).pcap
capinfos captures/wormhole_bus3_live_*.pcap
python3 tools/wormhole_parse.py captures/wormhole_bus3_live_*.pcap --hid
python3 tools/wormhole_parse.py captures/wormhole_bus3_live_*.pcap --json | less
```

### 6.4 What to look for

| Signal | Where | Meaning |
|---|---|---|
| Bulk CBW with CDB opcode `0xD9`, byte 1 `3/4/6`, footer `OT` | Bulk-Only transactions, `vendorHID` column | Host → cable HID packet (`OTi_SendHIDPacket`). Parser decodes type/payload in the `vendorHID` tail. |
| Bulk CBW with any other vendor opcode (`0xC0`–`0xFF`) + data phase | `candidateUPipe` flag | Possible UPipe / file / clipboard packet — magic unknown; capture the raw hex. |
| Interrupt IN on EP3 (mouse) / EP4 (keyboard) for the Wormhole `Bus:Dev` | `HID interrupt reports` section | Cable → host replay of the peer's input. EP3: 4-byte mouse (buttons/X/Y/wheel); EP4: 8-byte keyboard (modifiers + 6 keys). |
| Only `LOG SENSE`/`REQUEST SENSE` pairs, zero of the above | Same sections empty | No session was driven — check that GoBridge is running on both ends and the switch hotkey matched. |

### 6.5 Injecting a test packet (single-host, no GoBridge)

You can verify the wire path and the parser without a session by
sending a synthetic `0xD9` CDB with `sg_raw` while capturing.  This
exercises the cable's marker handling; it does not prove peer
forwarding (that needs both ends).  Build the CDB with the parser's
helper so the framing is guaranteed correct:

```sh
RAW=~/wormhole-private/raw-captures/wormhole_bus3_synth_$(date +%F).pcap
CDB=$(python3 -c 'import sys; sys.path.insert(0, "tools"); import wormhole_parse as wp; print(" ".join("%02x" % b for b in wp.build_vendor_hid_cdb("3", bytes([0x01, 10] + [0] * 10))))')
echo "$CDB"
sudo tcpdump -i usbmon3 -w "$RAW" &
# /dev/sgX is the Wormhole's SCSI generic device (see §2).  Pass the bytes
# space-separated with -C 1; --cmd-file is not supported in this sg3-utils build.
sudo sg_raw -C 1 /dev/sgX $CDB
sudo pkill tcpdump
python3 tools/filter_usbmon.py "$RAW" --device 3:15 -o captures/wormhole_bus3_synth_$(date +%F).pcap
python3 tools/wormhole_parse.py captures/wormhole_bus3_synth_*.pcap --hid
# expect: one extra CBW in the transaction list with
#   name=WORMHOLE VENDOR HID (0xD9), hid_type=mouse, footer_ok=True
```

The multimedia type (`'6'`) can be probed the same way.  Its 12-byte
payload layout is undetermined (see `docs/transport.md`), so send an
all-zero frame first: it tests whether the cable accepts the `'6'`
framing at all without presupposing where the usage byte sits.

```sh
CDB6=$(python3 -c 'import sys; sys.path.insert(0, "tools"); import wormhole_parse as wp; print(" ".join("%02x" % b for b in wp.build_vendor_hid_cdb("6", bytes(12))))')
echo "$CDB6"
sudo sg_raw -C 1 /dev/sgX $CDB6
# expect (if accepted): one CBW with hid_type=multimedia, footer_ok=True;
#   CHECK CONDITION means the cable rejects the type -- record either way.
# With a second host: watch peer EP4 (or evtest/hidraw) for a replayed
#   consumer usage; during a macOS GoBridge session the daemon's
#   `key HID:` log shows the real payload layout, which is the cleanest
#   way to map the bytes.
```

For a logged, four-phase version of the peer-to-local test (sg_raw and a direct SG_IO call, plus a 15-byte control), see `tools/peer_rerun_send.py`. It needs write access to the `/dev/sgN` node. Results: `docs/live-capture-2026-11-06.md`, re-run section.

Record what you see when you do this — the peer-to-peer data channel is internal, so local capture can only show its HID/SCSI *effects*.
