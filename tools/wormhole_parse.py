#!/usr/bin/env python3
"""Parse a Linux usbmon pcap (linktype 220, usb-linux-mmap) for the
J5Create WormholeSwitch (VID 0711:PID 2211) and other USB devices on the bus.

Stdlib only -- no tshark, pyshark or scapy required.  The committed sample
``captures/wormhole_bus3_2026-11-06.pcap`` is the reference input.

What it does
------------
* Reads a classic pcap (not pcapng), decodes the 64-byte usb-linux-mmap
  header of every packet.
* Discovers devices from USB control enumeration (GET_DESCRIPTOR) by
  VID:PID, so it never relies on a hard-coded Bus:Device number, which
  changes on every replug and differs between the two cable ends.
* Pairs SCSI Bulk-Only CBW -> data -> CSW transactions per device and
  decodes the CDB, the data phase (INQUIRY / READ CAPACITY(10) /
  REQUEST SENSE / READ TOC / GET CONFIGURATION) and the CSW status.
* Decodes the Wormhole vendor HID protocol: a 16-byte CDB whose
  opcode is 0xD9, byte 1 is '3' (mouse) / '4' (keyboard) / '6'
  (multimedia), bytes 2-13 are a 12-byte HID payload, and bytes 14-15
  are 'O' 'T' (OTiTransfer::sendHIDPacket -- see docs/transport.md and
  docs/mac-gobridge.md).  Any other CDB in the SPC vendor range is also
  flagged as a potential UPipe / file-transfer packet and reported with
  raw hex so a live capture can characterise it.
* Decodes boot HID interrupt reports: EP3 mouse (4 bytes: buttons,
  signed X/Y/Wheel) and EP4 keyboard (8 bytes: modifiers + 6 keys).
  This is how a peer-active session differs from the idle capture
  (which has zero Wormhole interrupt traffic).
* Pairs HID interrupt reports with the accepted 0xD9 vendor-HID sends
  that caused them (`--orphans`) and flags reports with no matching
  send.  A report at one cable end is caused by a send submitted at
  the *other* end, so on a single-sided capture every received report
  is an orphan.  The orphan label itself stays neutral: it means "no
  matching accepted send in the analysed packets".  Reading it as
  forwarded peer-side input (e.g. for the bus3_live2 EP3 x=+60 report,
  issue #15) is an inference that needs the peer capture or other
  outside evidence -- the tool shows the absence, not the origin.
* Summarises control / bulk / interrupt traffic per device, which is
  how "the Wormhole HID interfaces are idle" can be verified.

usb-linux-mmap header (64 bytes, little-endian, offsets verified
against ``captures/wormhole_bus3_2026-11-06.pcap`` and tshark 4.4.19)
-------------------------------------------------------------------
    0  u64  URB id
    8  u8   type           'S' submit / 'C' complete
    9  u8   xfer_type      1 interrupt, 2 control, 3 bulk
   10  u8   endpoint       high bit = IN, low bits = EP number
   11  u8   device number
   12  u8   bus number
   13  u8   reserved (observed 0)
   14  u8   flag_setup     '\\0' setup packet present, '-' not relevant
   15  u8   flag_data      '\\0' data present, '<' submit/no-data,
                          '>' complete/no-data
   16  i32  ts_sec
   20  i32  reserved (observed 0)
   24  i32  ts_usec
   28  i32  status         0 on complete, -115 (-EINPROGRESS) on submit
   32  u32  length         URB transfer length
   36  u32  data_len       bytes of payload after the 64-byte header
   40  8B   setup packet   only when flag_setup == '\\0'
   48  u32  interval       interrupt polling interval
   52  u32  start_frame
   56  u32  transfer_flags
   60  u32  num_iso_descs
   64  ...  payload (data_len bytes)

Bulk-Only framing inside bulk payloads
---------------------------------------
    CBW (31 B): 'USBC' u32 tag, u32 data_len, u8 flags (0x80 = IN),
                u8 LUN, u8 CDB length, CDB bytes
    CSW (13 B): 'USBS' u32 tag, u32 residue, u8 status
                (0 good, 1 CHECK CONDITION, 2 phase error)

A CBW *complete* packet in usbmon carries only the first 8 bytes of
the CBW; only SUBMIT packets carry the full 31 bytes.  This parser
therefore creates a transaction only on a SUBMIT CBW and ignores the
truncated COMPLETE echo -- counting both would double-count and
previously led to a truncated-payload index error.

Usage
-----
    python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap
    python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap --json
    python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap --device 14
    python3 tools/wormhole_parse.py captures/wormhole_bus3_2026-11-06.pcap --all --no-transactions
    python3 tools/wormhole_parse.py live.pcap --hid   # focus HID + vendor sections
    python3 tools/wormhole_parse.py live.pcap --orphans   # pair reports <-> 0xD9 sends
    python3 tools/wormhole_parse.py live.pcap --orphans --peer peer.pcap
    python3 tools/wormhole_parse.py live.pcap --orphans --peer peer.pcap --peer-offset auto

Exit codes: 0 success, 1 usage/IO error, 2 unsupported file format.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

# pcap LINKTYPE_USB_LINUX_MMAPPED.  Wireshark reports this as
# encapsulation 115 (usb-linux-mmap); the on-disk pcap linktype field
# is 220.  195 is the legacy DLT_USB_LINUX_MMAPPED with the same
# 64-byte header layout in practice, so it is accepted too.
LINKTYPE_USB_LINUX_MMAPPED = 220
LINKTYPE_USB_LINUX_MMAPPED_LEGACY = 195
HEADER_LEN = 64
WORMHOLE_VID = 0x0711
WORMHOLE_PID = 0x2211

XFER_NAMES = {1: "interrupt", 2: "control", 3: "bulk"}
CSW_STATUS_NAMES = {0: "good", 1: "CHECK CONDITION", 2: "phase error"}

# SCSI opcodes observed from / relevant to this device.  Unknown opcodes
# are reported as UNKNOWN 0xNN rather than dropped.
SCSI_OPCODES = {
    0x00: "TEST UNIT READY",
    0x03: "REQUEST SENSE",
    0x04: "FORMAT UNIT",
    0x12: "INQUIRY",
    0x1C: "RECEIVE DIAGNOSTIC RESULTS",
    0x25: "READ CAPACITY(10)",
    0x28: "READ(10)",
    0x2A: "WRITE(10)",
    0x43: "READ TOC/PMA/ATIP",
    0x46: "GET CONFIGURATION",
    0x4A: "LOG SENSE",
    0x5A: "MODE SENSE(10)",
    0x9E: "READ CAPACITY(16)",
    0xA0: "RECEIVE DIAGNOSTIC",
    0xA3: "REPORT LUNs",
    0xD9: "WORMHOLE VENDOR HID (0xD9)",
}
SENSE_KEYS = {
    0: "No Sense", 1: "Recovered Error", 2: "Not Ready", 3: "Medium Error",
    4: "Hardware Error", 5: "Illegal Request", 6: "Unit Attention",
    7: "Data Protect", 8: "Checksum Error", 9: "Copy Abort",
    10: "Aborted Command", 11: "Volume Overflow", 12: "Miscompare",
    13: "User Initiated Abort",
}
ASC_NAMES = {
    0x0000: "No additional sense information",
    0x2000: "Invalid command operation code",
    0x2400: "Invalid field in CDB",
    0x3000: "Incompatible medium installed",
    0x0400: "Not ready",
    0x3A00: "Medium not present",
}

# --- Wormhole vendor HID protocol (OTiTransfer) --------------------------
# OTiTransporter::sendHIDPacket builds a 16-byte buffer that *is* the
# SCSI CDB.  See docs/mac-gobridge.md for the decompiler trail.
VENDOR_HID_MAGIC = 0xD9               # CDB byte 0
VENDOR_HID_TYPES = {
    0x33: "mouse",                   # '3', type 1
    0x34: "keyboard",                # '4', type 2
    0x36: "multimedia",              # '6', type 3
}
VENDOR_HID_FOOTER = b"OT"             # CDB bytes 14-15
VENDOR_HID_LEN = 16
VENDOR_RANGE = (0xC0, 0xFF)           # SPC vendor-specific opcodes

# HID report identification (from the config descriptor in the capture:
# If 1 = boot mouse EP3 IN, If 2 = boot keyboard EP4 IN)
WORMHOLE_MOUSE_EP = 3
WORMHOLE_KEYBOARD_EP = 4
HID_MODIFIERS = [
    "LCtrl", "LShift", "LAlt", "LWin",
    "RCtrl", "RShift", "RAlt", "RWin",
]


# --------------------------------------------------------------------------
# pcap + usbmon decoding
# --------------------------------------------------------------------------

@dataclass
class UrbPacket:
    frame: int
    ts: float                      # seconds, from the pcap record header
    urb_id: int
    kind: str                      # 'S' or 'C'
    xfer: int
    endpoint: int                  # raw, e.g. 0x81 = EP1 IN
    dev: int
    bus: int
    flag_setup: int
    flag_data: int
    status: int
    length: int
    data_len: int
    setup: bytes | None
    interval: int
    transfer_flags: int
    payload: bytes
    capture_id: str = "main"       # which pcap the packet came from

    @property
    def direction(self) -> str:
        return "IN" if self.endpoint & 0x80 else "OUT"

    @property
    def ep_num(self) -> int:
        return self.endpoint & 0x0F


@dataclass
class PcapData:
    path: str
    sha256: str
    linktype: int
    packets: list[UrbPacket]
    duration: float
    first_ts: float | None


def _pcap_endian(magic: bytes) -> str:
    if magic == bytes.fromhex("d4c3b2a1"):
        return "<"
    if magic == bytes.fromhex("a1b2c3d4"):
        return ">"
    if magic == bytes.fromhex("4d3cb2a1"):
        return "<"  # nanosecond variant, timestamps still usec-scaled below
    if magic == bytes.fromhex("a1b23c4d"):
        return ">"
    raise ValueError(
        "not a classic pcap (magic %s); pcapng is not supported -- "
        "re-capture with tcpdump -w file.pcap" % magic.hex()
    )


def decode_usbmon_header(raw: bytes) -> dict:
    """Decode one 64-byte usb-linux-mmap header + payload."""
    if len(raw) < HEADER_LEN:
        raise ValueError("packet shorter than 64-byte usbmon header")
    hdr = raw[:HEADER_LEN]
    (urb_id,) = struct.unpack_from("<Q", hdr, 0)
    kind = chr(hdr[8])
    xfer, endpoint, dev, bus = hdr[9], hdr[10], hdr[11], hdr[12]
    flag_setup, flag_data = hdr[14], hdr[15]
    _ts_sec, _reserved, _ts_usec = struct.unpack_from("<iii", hdr, 16)
    (status,) = struct.unpack_from("<i", hdr, 28)
    length, data_len = struct.unpack_from("<II", hdr, 32)
    setup = hdr[40:48] if flag_setup == 0 else None
    (interval,) = struct.unpack_from("<I", hdr, 48)
    (transfer_flags,) = struct.unpack_from("<I", hdr, 56)
    payload = raw[HEADER_LEN:HEADER_LEN + data_len]
    return {
        "urb_id": urb_id, "kind": kind, "xfer": xfer, "endpoint": endpoint,
        "dev": dev, "bus": bus, "flag_setup": flag_setup,
        "flag_data": flag_data, "status": status, "length": length,
        "data_len": data_len, "setup": setup, "interval": interval,
        "transfer_flags": transfer_flags, "payload": payload,
    }


def read_pcap(path: str | Path, capture_id: str = "main") -> PcapData:
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise ValueError("file too short for a pcap global header")
    endian = _pcap_endian(data[:4])
    _magic, _vmaj, _vmin, _zone, _sig, _snap, linktype = struct.unpack_from(
        endian + "IHHiiii", data, 0)
    if linktype not in (LINKTYPE_USB_LINUX_MMAPPED, LINKTYPE_USB_LINUX_MMAPPED_LEGACY):
        raise ValueError(
            "linktype %d, expected 220 (usb-linux-mmap, Wireshark "
            "encapsulation 115); this parser only handles "
            "`tcpdump -i usbmonN` captures" % linktype)
    packets: list[UrbPacket] = []
    off, frame = 24, 0
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if off + incl > len(data):
            break  # truncated final record
        raw = data[off:off + incl]
        off += incl
        frame += 1
        if len(raw) < HEADER_LEN:
            continue
        d = decode_usbmon_header(raw)
        packets.append(UrbPacket(
            frame=frame, ts=ts_sec + ts_usec / 1e6,
            capture_id=capture_id, **d))
    first = packets[0].ts if packets else None
    last = packets[-1].ts if packets else None
    duration = (last - first) if first is not None and last is not None else 0.0
    return PcapData(
        path=str(path), sha256=hashlib.sha256(data).hexdigest(),
        linktype=linktype, packets=packets, duration=duration, first_ts=first)


# --------------------------------------------------------------------------
# USB descriptor decoding (control enumeration)
# --------------------------------------------------------------------------

@dataclass
class DeviceInfo:
    bus: int
    dev: int
    vid: int | None = None
    pid: int | None = None
    bcd_device: int | None = None
    device_descriptor: bytes | None = None
    config_descriptors: list[bytes] = field(default_factory=list)
    interfaces: list[dict] = field(default_factory=list)

    @property
    def key(self) -> tuple[int, int]:
        return (self.bus, self.dev)


def parse_device_descriptor(payload: bytes) -> dict | None:
    if len(payload) < 18 or payload[0] != 18 or payload[1] != 1:
        return None
    vid, pid, bcd = struct.unpack_from("<HHH", payload, 8)
    return {"vid": vid, "pid": pid, "bcd_device": bcd,
            "usb_version": struct.unpack_from("<H", payload, 2)[0],
            "b_max_packet0": payload[7], "i_manufacturer": payload[14],
            "i_product": payload[15], "i_serial": payload[16]}


def parse_config_descriptor(payload: bytes) -> dict | None:
    if len(payload) < 9 or payload[0] < 9 or payload[1] != 2:
        return None
    total, num_if = struct.unpack_from("<HB", payload, 2)
    ifaces: list[dict] = []
    off = 9
    while off + 2 <= len(payload):
        blen, btype = payload[off], payload[off + 1]
        if blen < 2 or off + blen > len(payload):
            break
        if btype == 4 and blen >= 9:  # INTERFACE
            ifaces.append({
                "number": payload[off + 2], "alt": payload[off + 3],
                "num_endpoints": payload[off + 4],
                "class": payload[off + 5], "subclass": payload[off + 6],
                "protocol": payload[off + 7], "endpoints": []})
        elif btype == 5 and blen >= 7 and ifaces:  # ENDPOINT
            addr = payload[off + 2]
            ifaces[-1]["endpoints"].append({
                "address": "0x%02x" % addr,
                "direction": "IN" if addr & 0x80 else "OUT",
                "attributes": payload[off + 3],
                "max_packet": struct.unpack_from("<H", payload, off + 4)[0]})
        off += blen
    return {"total_length": total, "num_interfaces": num_if,
            "bm_attributes": payload[7], "max_power_units": payload[8],
            "interfaces": ifaces}


def discover_devices(packets: list[UrbPacket]) -> dict[tuple[int, int], DeviceInfo]:
    devices: dict[tuple[int, int], DeviceInfo] = {}
    pending_setup: dict[tuple[int, int, int], bytes] = {}
    for p in packets:
        key = (p.bus, p.dev)
        devices.setdefault(key, DeviceInfo(bus=p.bus, dev=p.dev))
        if p.xfer != 2:  # control only
            continue
        if p.kind == "S" and p.setup is not None:
            pending_setup[(p.bus, p.dev, p.urb_id)] = p.setup
        elif p.kind == "C" and p.payload:
            setup = pending_setup.pop((p.bus, p.dev, p.urb_id), None)
            if setup is None or len(setup) < 8:
                continue
            _bm, b_req, w_val, _w_idx, w_len = struct.unpack("<BBHHH", setup)
            if b_req != 6:  # GET_DESCRIPTOR
                continue
            dtype = (w_val >> 8) & 0xFF
            dev_info = devices[key]
            if dtype == 1 and w_len >= 18:
                parsed = parse_device_descriptor(p.payload)
                if parsed:
                    dev_info.vid = parsed["vid"]
                    dev_info.pid = parsed["pid"]
                    dev_info.bcd_device = parsed["bcd_device"]
                    dev_info.device_descriptor = p.payload
            elif dtype == 2 and w_len > 9:
                parsed = parse_config_descriptor(p.payload)
                if parsed:
                    dev_info.config_descriptors.append(p.payload)
                    dev_info.interfaces = parsed["interfaces"]
    return devices


# --------------------------------------------------------------------------
# SCSI Bulk-Only decoding
# --------------------------------------------------------------------------

@dataclass
class CbW:
    tag: int
    data_len: int
    flags: int
    lun: int
    cdb: bytes
    frame: int
    ts: float


@dataclass
class CsW:
    tag: int
    residue: int
    status: int
    frame: int
    ts: float


@dataclass
class Transaction:
    bus: int
    dev: int
    cbw: CbW
    data: bytes = b""
    csw: CsW | None = None
    capture_id: str = "main"

    @property
    def opcode(self) -> int:
        return self.cbw.cdb[0] if self.cbw.cdb else 0

    @property
    def opcode_name(self) -> str:
        return SCSI_OPCODES.get(self.opcode, "UNKNOWN 0x%02X" % self.opcode)

    @property
    def is_vendor(self) -> bool:
        return bool(self.cbw.cdb) and VENDOR_RANGE[0] <= self.cbw.cdb[0] <= VENDOR_RANGE[1]

    @property
    def is_vendor_hid(self) -> bool:
        return bool(self.cbw.cdb) and self.cbw.cdb[0] == VENDOR_HID_MAGIC


def parse_cbw(payload: bytes) -> CbW | None:
    if len(payload) < 31 or payload[:4] != b"USBC":
        return None
    tag, data_len = struct.unpack_from("<II", payload, 4)
    flags, lun, cdb_len = payload[12], payload[13], payload[14]
    cdb = payload[15:15 + cdb_len] if cdb_len else b""
    return CbW(tag=tag, data_len=data_len, flags=flags, lun=lun,
               cdb=cdb, frame=0, ts=0.0)  # frame/ts filled by caller


def parse_csw(payload: bytes) -> CsW | None:
    if len(payload) < 13 or payload[:4] != b"USBS":
        return None
    tag, residue = struct.unpack_from("<II", payload, 4)
    return CsW(tag=tag, residue=residue, status=payload[12], frame=0, ts=0.0)


def parse_transactions(packets: list[UrbPacket]) -> list[Transaction]:
    """Pair CBW (SUBMIT) -> data (COMPLETE) -> CSW (COMPLETE) per device.

    Bulk-Only is strictly sequential per device, so one pending
    transaction per (bus, dev) is sufficient and interleaved devices
    do not cross-pair.
    """
    txns: list[Transaction] = []
    pending: dict[tuple[int, int], Transaction] = {}
    for p in packets:
        if p.xfer != 3 or not p.payload:
            continue
        if p.payload[:4] == b"USBC":
            if p.kind != "S":
                continue  # truncated 8-byte COMPLETE echo, not a new CBW
            cbw = parse_cbw(p.payload)
            if cbw is None:
                continue
            cbw.frame, cbw.ts = p.frame, p.ts
            txn = Transaction(bus=p.bus, dev=p.dev, cbw=cbw,
                              capture_id=p.capture_id)
            pending[(p.bus, p.dev)] = txn
            txns.append(txn)
        elif p.payload[:4] == b"USBS":
            if p.kind != "C":
                continue
            csw = parse_csw(p.payload)
            if csw is None:
                continue
            csw.frame, csw.ts = p.frame, p.ts
            txn = pending.pop((p.bus, p.dev), None)
            if txn is not None:
                txn.csw = csw
            # Orphan CSW (no pending CBW seen): still surface it.
            else:
                txn = Transaction(bus=p.bus, dev=p.dev,
                                  capture_id=p.capture_id,
                                  cbw=CbW(0, 0, 0, 0, b"", p.frame, p.ts))
                txn.csw = csw
                txns.append(txn)
        elif p.kind == "C":
            txn = pending.get((p.bus, p.dev))
            if txn is not None:
                txn.data += p.payload
    return txns


def decode_vendor_cdb(cdb: bytes) -> dict:
    """Decode a Wormhole vendor HID CDB (opcode 0xD9) or generic vendor CDB.

    Returns a dict describing the packet; returns {} for non-vendor
    opcodes so callers can branch.  The 0xD9 layout is from
    OTiTransporter::sendHIDPacket (see module docstring): a 16-byte
    buffer that is both the CDB and the packet.
    """
    if not cdb:
        return {}
    op = cdb[0]
    if not (VENDOR_RANGE[0] <= op <= VENDOR_RANGE[1]):
        return {}
    out: dict = {
        "is_vendor": True,
        "opcode": "0x%02X" % op,
        "cdb_hex": cdb.hex(),
        "cdb_len": len(cdb),
    }
    if op == VENDOR_HID_MAGIC:
        out["is_vendor_hid"] = True
        out["name"] = "WORMHOLE VENDOR HID (0xD9)"
        # byte 1: type char
        if len(cdb) >= 2:
            type_byte = cdb[1]
            out["type_byte"] = "0x%02X" % type_byte
            try:
                out["type_char"] = chr(type_byte)
            except ValueError:
                out["type_char"] = "?"
            out["hid_type"] = VENDOR_HID_TYPES.get(type_byte, "unknown")
        # bytes 2-13: 12-byte HID payload
        if len(cdb) >= 14:
            payload = cdb[2:14]
            out["payload_hex"] = payload.hex()
            out["payload"] = list(payload)
            out["payload_len"] = len(payload)
        # bytes 14-15: 'O' 'T' footer
        if len(cdb) >= 16:
            footer = cdb[14:16]
            out["footer_hex"] = footer.hex()
            out["footer_ascii"] = _ascii(footer)
            out["footer_ok"] = footer == VENDOR_HID_FOOTER
        out["valid_hid_framing"] = bool(
            len(cdb) == VENDOR_HID_LEN
            and (len(cdb) < 2 or cdb[1] in VENDOR_HID_TYPES)
            and (len(cdb) < 16 or cdb[14:16] == VENDOR_HID_FOOTER)
        )
        # Any trailing bytes beyond the 16-byte HID packet are
        # reported verbatim (possible UPipe/data-phase spill).
        if len(cdb) > VENDOR_HID_LEN:
            out["trailing_hex"] = cdb[VENDOR_HID_LEN:].hex()
    else:
        out["is_vendor_hid"] = False
        # Generic vendor CDB: likely a file/clipboard UPipe packet.
        # Magic is unknown; report raw bytes so a live capture can
        # characterise it.
        out["name"] = "VENDOR CDB 0x%02X (possible UPipe)" % op
        out["candidate_upipe"] = True
    return out


def build_vendor_hid_cdb(hid_type: str, payload: bytes) -> bytes:
    """Build a 16-byte 0xD9 CDB for tests / sg_raw injection.

    hid_type: '3' (mouse), '4' (keyboard) or '6' (multimedia).
    payload: 0-12 bytes, zero-padded to 12.
    """
    if hid_type not in ("3", "4", "6"):
        raise ValueError("hid_type must be '3', '4' or '6'")
    payload = (payload + b"\x00" * 12)[:12]
    return bytes([VENDOR_HID_MAGIC, ord(hid_type)]) + payload + VENDOR_HID_FOOTER


def decode_cdb(cdb: bytes) -> dict:
    """Decode common CDB fields per opcode. Unknown fields stay raw."""
    if not cdb:
        return {}
    op = cdb[0]
    # Vendor opcodes (including the 0xD9 HID packet) first -- they are
    # not SPC opcodes and must not fall through to the standard decoder.
    if VENDOR_RANGE[0] <= op <= VENDOR_RANGE[1]:
        return decode_vendor_cdb(cdb)
    out: dict = {"opcode": "0x%02X" % op,
                 "name": SCSI_OPCODES.get(op, "UNKNOWN 0x%02X" % op),
                 "cdb_hex": cdb.hex()}
    if op == 0x03 and len(cdb) >= 6:                      # REQUEST SENSE
        out["alloc_len"] = cdb[4]
    elif op == 0x12 and len(cdb) >= 6:                    # INQUIRY
        out["evpd"] = bool(cdb[1] & 0x01)
        out["page_code"] = cdb[2] if out["evpd"] else None
        out["alloc_len"] = struct.unpack_from(">H", cdb, 3)[0]
    elif op == 0x25 and len(cdb) >= 10:                   # READ CAPACITY(10)
        pass
    elif op in (0x28, 0x2A) and len(cdb) >= 10:           # READ/WRITE(10)
        out["lba"] = struct.unpack_from(">I", cdb, 2)[0]
        out["transfer_len_blocks"] = struct.unpack_from(">H", cdb, 7)[0]
    elif op == 0x43 and len(cdb) >= 10:                   # READ TOC/PMA/ATIP
        out["format"] = cdb[1] & 0x0F
        out["track/session"] = cdb[6]
        out["alloc_len"] = struct.unpack_from(">H", cdb, 7)[0]
    elif op == 0x46 and len(cdb) >= 10:                   # GET CONFIGURATION
        out["starting_feature"] = struct.unpack_from(">H", cdb, 2)[0]
        out["alloc_len"] = struct.unpack_from(">H", cdb, 7)[0]
    elif op == 0x4A and len(cdb) >= 10:                   # LOG SENSE
        out["page_code"] = cdb[2]
        out["subpage_code"] = cdb[3]
        out["alloc_len"] = struct.unpack_from(">H", cdb, 7)[0]
    elif op == 0x9E and len(cdb) >= 16:                   # READ CAPACITY(16)
        out["service_action"] = cdb[10] & 0x1F
    return out


def _signed8(v: int) -> int:
    return v - 256 if v >= 128 else v


def decode_hid_mouse_report(payload: bytes) -> dict:
    """Decode a boot-mouse report (EP3, 4 bytes per report descriptor)."""
    if len(payload) < 4:
        return {"len": len(payload), "hex": payload.hex(), "decoded": False,
                "error": "short mouse report (need >= 4 bytes)"}
    buttons = payload[0]
    return {
        "len": len(payload),
        "hex": payload.hex(),
        "decoded": True,
        "kind": "mouse",
        "buttons": buttons,
        "left": bool(buttons & 0x01),
        "right": bool(buttons & 0x02),
        "middle": bool(buttons & 0x04),
        "reserved_bits": buttons & ~0x07,
        "x": _signed8(payload[1]),
        "y": _signed8(payload[2]),
        "wheel": _signed8(payload[3]),
    }


def decode_hid_keyboard_report(payload: bytes) -> dict:
    """Decode a boot-keyboard report (EP4, 8 bytes per report descriptor)."""
    if len(payload) < 8:
        return {"len": len(payload), "hex": payload.hex(), "decoded": False,
                "error": "short keyboard report (need >= 8 bytes)"}
    mods = payload[0]
    keys = [b for b in payload[2:8] if b != 0]
    return {
        "len": len(payload),
        "hex": payload.hex(),
        "decoded": True,
        "kind": "keyboard",
        "modifiers": mods,
        "modifier_names": [HID_MODIFIERS[i] for i in range(8) if mods & (1 << i)],
        "constant": payload[1],
        "keys": keys,
        "key_hex": [hex(k) for k in keys],
        "idle": len(keys) == 0 and mods == 0,
    }


def decode_hid_report(ep_num: int, payload: bytes) -> dict:
    """Dispatch to mouse/keyboard decoding by endpoint number."""
    if ep_num == WORMHOLE_MOUSE_EP:
        return decode_hid_mouse_report(payload)
    if ep_num == WORMHOLE_KEYBOARD_EP:
        return decode_hid_keyboard_report(payload)
    return {"len": len(payload), "hex": payload.hex(), "decoded": False,
            "error": "unknown HID endpoint 0x%x" % ep_num}


def parse_hid_reports(packets: list[UrbPacket]) -> list[dict]:
    """Collect decoded HID interrupt IN reports from usbmon packets.

    Only COMPLETE interrupt transfers with a payload count as a report;
    SUBMIT packets are the host polling.  This mirrors the transaction
    logic for bulk (which keys on SUBMIT CBWs) -- for HID the data is
    only in COMPLETEs.
    """
    reports: list[dict] = []
    for p in packets:
        if p.xfer != 1 or p.kind != "C" or not p.payload:
            continue
        if p.direction != "IN":
            continue
        decoded = decode_hid_report(p.ep_num, p.payload)
        reports.append({
            "capture_id": p.capture_id,
            "bus": p.bus, "dev": p.dev, "frame": p.frame, "ts": p.ts,
            "endpoint": "0x%02x" % p.endpoint,
            "ep_num": p.ep_num,
            "data_len": len(p.payload),
            **decoded,
        })
    reports.sort(key=lambda r: (r["bus"], r["dev"], r["frame"]))
    return reports


# --------------------------------------------------------------------------
# HID report <-> accepted 0xD9 send pairing (timeline walk)
# --------------------------------------------------------------------------

def wormhole_device_keys(packets: list[UrbPacket]) -> set[tuple[str, int, int]]:
    """(capture_id, bus, dev) of the devices each capture enumerates as
    WormholeSwitch (VID:PID).  Keys are scoped per capture: bus:dev
    numbers are host-local, so the same numbers in two captures are
    two devices."""
    keys: set[tuple[str, int, int]] = set()
    for capture_id in sorted({p.capture_id for p in packets}):
        capture_packets = [p for p in packets if p.capture_id == capture_id]
        for key, info in discover_devices(capture_packets).items():
            if info.vid == WORMHOLE_VID and info.pid == WORMHOLE_PID:
                keys.add((capture_id, key[0], key[1]))
    return keys


# A report pairs only with a send inside this gap window.
# Empirical basis: the 10 merged live3 + bus1_live pairs span -0.56 to
# +2.02 ms (median +1.3 ms, 9 of 10 positive), measured on the committed
# captures.  All 10 still match with +5/-1 ms bounds, so those bounds
# work.  (The re-run's 1-4 ms-before figure in
# docs/live-capture-2026-11-06.md line 110 is measured against the peer's
# send log in a different session -- a different kind of timestamp -- and
# is not the basis here.)  50 ms forward is ~25x the largest observed
# delay; 10 ms backward is ~5x the largest observed early arrival and
# tolerates host clock skew.
PAIR_WINDOW_S = 0.05
PAIR_SKEW_S = 0.01


def pair_hid_reports_to_sends(
        packets: list[UrbPacket],
        device_keys: set[tuple[int, int]] | None = None,
        peer_offset: float = 0.0,
        estimate_offset: bool = False,
        peer_capture_id: str | None = None) -> dict:
    """Pair Wormhole HID IN reports with the accepted 0xD9 sends behind them.

    Walks the capture timeline.  Eligible sends are 0xD9 vendor-HID CBWs
    whose CSW status is good -- CHECK CONDITION sends never forward
    (docs/live-capture-2026-11-06.md, re-run phase P4).  Reports are
    decoded EP3/EP4 interrupt IN reports.  A report pairs with the
    earliest unconsumed send of the same HID type whose payload prefix
    equals the report bytes (mouse '3': payload[0:4] = buttons/X/Y/wheel;
    keyboard '4': payload[0:8] = mods/reserved/keys), one send per
    report, so a second identical report with no second send stays an
    orphan.

    Matching crosses device numbers on purpose: the two cable ends
    enumerate as different bus:dev pairs and a report received at one
    end is caused by a send submitted at the other, so merging both
    ends' captures pairs 1:1 (verified on live3 + bus1_live: 10/10).
    Within one capture, a send and a report on the same device never
    pair: a host's own send does not echo back to it
    (wormhole_bus3_synth: 1 accepted send, 0 reports).  Two cable ends
    captured together on one host do pair, across their two devices.
    Device identity is per capture -- (capture_id, bus, dev) -- so two
    captures that enumerate the same bus:dev numbers still pair across
    each other; bus:dev alone is not a device identity across hosts.

    The orphan label is deliberately neutral.  An orphan means only
    "no matching accepted send in the analysed packets": on a
    single-sided capture that is true of every report by construction,
    because a matching send could only exist in the missing peer
    capture.  Calling such a report forwarded peer-side input (e.g.
    the bus3_live2 EP3 x=+60 report, issue #15) is an inference from
    outside the tool -- the capture shows the absence, not the origin.

    Causality and time window: a send can only cause a report that
    arrives at (or, within clock skew, just before) the report, so only
    sends whose gap falls in [-PAIR_SKEW_S, PAIR_WINDOW_S] are
    considered, and a report never pairs with a send later than that
    skew allows.  Measured on the committed captures, the 10 merged
    live3 + bus1_live pairs span -0.56 to +2.02 ms (median +1.3 ms, 9
    of 10 positive); all 10 still match with +5/-1 ms bounds.  (The
    re-run's 1-4 ms-before-peer-send-log figure is a different session
    and timestamp, not the basis here.)  50 ms forward is ~25x the
    largest observed delay; 10 ms backward is ~5x the largest observed
    early arrival and tolerates host clock skew.  Out-of-window and
    report-much-later-than-send cases stay orphans, and the reported gap
    keeps its sign so skew stays visible.

    Clock offset between hosts: the fixed window assumes the two capture
    clocks agree.  `peer_offset` (seconds) corrects the peer capture's
    clock when a skew is known.  With `peer_capture_id` set (the --peer
    CLI path), every timestamp from that capture -- reports AND sends --
    is corrected by -peer_offset, which is what a clock error means
    physically; without it (a pre-merged list), the correction falls
    back to report timestamps only.  `estimate_offset=True` picks the
    offset in [-100 ms, +100 ms] on a 0.5 ms grid that maximises the
    pair count (ties keep the offset closest to zero: the least
    correction consistent with the data), so captures recorded by
    unsynchronised hosts still pair.  The chosen value comes back in
    the result ("peer_offset_s" / "peer_offset_source"); a non-zero
    estimate is a hint of skew, not proof of causation.

    device_keys restricts the analysis, as (capture_id, bus, dev)
    triples.  Default: per capture, the devices that capture enumerates
    as VID 0711:PID 2211; a capture with no enumeration falls back on
    its own to the devices its accepted 0xD9 sends and EP3/EP4 reports
    point at, so one end's missing enumeration cannot drop the other
    end's device.  Scoping by VID:PID per capture keeps other bus
    devices' reports (input receivers, etc.) -- and another host's
    device that happens to reuse a peer bus:dev number -- out of the
    pairing.

    Returns a JSON-serialisable dict: counts plus pairs (report + the
    send frame and gap), orphans (reports with no matching send) and
    unpaired_sends (accepted sends no report consumed -- their reports,
    if any, went to the other cable end).
    """
    if device_keys is None:
        # Per-capture scoping: each capture contributes the devices it
        # enumerates as WormholeSwitch; a capture without enumeration
        # falls back on its own to what its traffic points at, so one
        # end's missing plug-in window cannot drop the other end's
        # device.
        device_keys = wormhole_device_keys(packets)
        enumerated = {c for c, _b, _d in device_keys}
        for capture_id in sorted({p.capture_id for p in packets}):
            if capture_id in enumerated:
                continue
            capture_packets = [p for p in packets
                               if p.capture_id == capture_id]
            for t in parse_transactions(capture_packets):
                if (t.is_vendor_hid and t.csw is not None
                        and t.csw.status == 0):
                    device_keys.add((capture_id, t.bus, t.dev))
            for r in parse_hid_reports(capture_packets):
                if (r.get("decoded") and r["ep_num"]
                        in (WORMHOLE_MOUSE_EP, WORMHOLE_KEYBOARD_EP)):
                    device_keys.add((capture_id, r["bus"], r["dev"]))

    sends: list[dict] = []
    for t in parse_transactions(packets):
        if ((t.capture_id, t.bus, t.dev) not in device_keys
                or not t.is_vendor_hid
                or t.csw is None or t.csw.status != 0):
            continue
        dec = decode_vendor_cdb(t.cbw.cdb)
        sends.append({
            "capture_id": t.capture_id,
            "bus": t.bus, "dev": t.dev,
            "frame": t.cbw.frame, "ts": t.cbw.ts,
            "hid_type": dec.get("hid_type", "unknown"),
            "payload_hex": bytes(dec.get("payload") or []).hex(),
        })
    sends.sort(key=lambda s: (s["ts"], s["frame"]))
    send_payloads = [bytes.fromhex(s["payload_hex"]) for s in sends]

    reports = [r for r in parse_hid_reports(packets)
               if (r["capture_id"], r["bus"], r["dev"]) in device_keys
               and r.get("decoded")
               and r["ep_num"] in (WORMHOLE_MOUSE_EP, WORMHOLE_KEYBOARD_EP)]
    reports.sort(key=lambda r: r["ts"])

    def _ts_adj(ts: float, capture_id: str, is_report: bool) -> float:
        # --peer path: correct the whole peer capture's clock (its sends
        # and its reports both carry the same clock error).  Pre-merged
        # lists have no peer id: fall back to correcting reports only.
        if peer_capture_id is not None:
            return ts - offset_fix[0] if capture_id == peer_capture_id else ts
        return ts - offset_fix[0] if is_report else ts

    offset_fix = [0.0]

    def _attempt(offset: float) -> tuple[list[dict], list[dict], list[bool]]:
        offset_fix[0] = offset
        consumed = [False] * len(sends)
        pairs: list[dict] = []
        orphans: list[dict] = []
        for r in reports:
            report_bytes = bytes.fromhex(r["hex"])
            n = 4 if r["kind"] == "mouse" else 8
            match = None
            for i, s in enumerate(sends):
                if consumed[i] or s["hid_type"] != r["kind"]:
                    continue
                if ((s["capture_id"], s["bus"], s["dev"])
                        == (r["capture_id"], r["bus"], r["dev"])):
                    continue  # a capture's own send never echoes back to it
                gap = (_ts_adj(r["ts"], r["capture_id"], True)
                       - _ts_adj(s["ts"], s["capture_id"], False))
                if not (-PAIR_SKEW_S <= gap <= PAIR_WINDOW_S):
                    continue  # a send cannot cause a report far before it
                              # exists, and a send older than the window is
                              # stale; small negative gaps are clock skew
                if send_payloads[i][:n] == report_bytes[:n]:
                    match = i  # sends are ts-sorted: FIFO within the window
                    break
            if match is None:
                orphans.append(r)
                continue
            consumed[match] = True
            s = sends[match]
            pairs.append({
                "report": r,
                "send_capture": s["capture_id"],
                "send_bus": s["bus"], "send_dev": s["dev"],
                "send_frame": s["frame"],
                "send_hid_type": s["hid_type"],
                "send_payload_hex": s["payload_hex"],
                "gap_s": round(gap, 6),
            })
        return pairs, orphans, consumed

    if estimate_offset:
        # 0.5 ms grid over +/-100 ms; ties keep the offset closest to
        # zero (iterate by |step|, keep the first strict improvement).
        offset, best = 0.0, -1
        for step in sorted(range(-200, 201), key=abs):
            d = step * 0.0005
            n_pairs = len(_attempt(d)[0])
            if n_pairs > best:
                offset, best = d, n_pairs
        source = "estimated"
    elif peer_offset:
        offset, source = peer_offset, "flag"
    else:
        offset, source = 0.0, "none"
    pairs, orphans, consumed = _attempt(offset)

    unpaired = [s for i, s in enumerate(sends) if not consumed[i]]
    return {
        "device_keys": sorted("%s %d:%d" % (c, b, d)
                              for c, b, d in device_keys),
        "peer_offset_s": offset,
        "peer_offset_source": source,
        "accepted_sends": len(sends),
        "reports": len(reports),
        "pairs": pairs,
        "orphans": orphans,
        "unpaired_sends": unpaired,
    }


def _ascii(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def decode_data(txn: Transaction) -> dict:
    """Decode the data phase. Returns {} when there is no data."""
    data = txn.data
    if not data:
        return {}
    op = txn.opcode
    out: dict = {"len": len(data), "hex": data.hex(), "ascii": _ascii(data)}
    # Vendor HID packets have no data phase in the observed path
    # (SendSCSICommandSendData with CFData NULL), but if one appears
    # (e.g. a UPipe packet) keep it raw and flagged.
    if VENDOR_RANGE[0] <= op <= VENDOR_RANGE[1]:
        out["vendor_data"] = True
        if op == VENDOR_HID_MAGIC:
            out["note"] = "unexpected data phase on 0xD9 HID packet"
        else:
            out["note"] = "possible UPipe / file-transfer payload -- magic unknown"
        return out
    if op == 0x12 and len(data) >= 36:                    # INQUIRY (standard)
        out.update({
            "pdt": data[0] & 0x1F,
            "rmb": bool(data[1] & 0x80),
            "version": data[2],
            "response_format": data[3] & 0x0F,
            "additional_length": data[4],
            "vendor": data[8:16].decode("ascii", "replace").strip(),
            "product": data[16:32].decode("ascii", "replace").strip(),
            "revision": data[32:36].decode("ascii", "replace").strip(),
        })
        if len(data) > 36:
            out["trailing_ascii"] = _ascii(data[36:])
    elif op == 0x25 and len(data) >= 8:                   # READ CAPACITY(10)
        last_lba, block_len = struct.unpack_from(">II", data, 0)
        out.update({"last_lba": last_lba, "block_len": block_len,
                    "capacity_bytes": (last_lba + 1) * block_len})
    elif op == 0x03 and len(data) >= 18:                  # REQUEST SENSE
        key = data[2] & 0x0F
        asc = struct.unpack_from(">H", data, 12)[0]
        out.update({
            "response_code": data[0] & 0x7F,
            "sense_key": key,
            "sense_key_name": SENSE_KEYS.get(key, "unknown"),
            "asc": "0x%02X" % (asc >> 8),
            "ascq": "0x%02X" % (asc & 0xFF),
            "asc_name": ASC_NAMES.get(asc, "unknown"),
        })
    elif op == 0x43 and len(data) >= 4:                   # READ TOC
        out.update({"toc_data_len": struct.unpack_from(">H", data, 0)[0],
                    "first_track": data[2], "last_track": data[3]})
    return out


def transaction_to_dict(txn: Transaction, first_ts: float) -> dict:
    csw = txn.csw
    status = csw.status if csw else None
    d: dict = {
        "bus": txn.bus, "dev": txn.dev,
        "cbw_frame": txn.cbw.frame,
        "t_offset_s": round(txn.cbw.ts - first_ts, 6) if first_ts else None,
        "tag": "0x%x" % txn.cbw.tag,
        "lun": txn.cbw.lun,
        "direction": "IN" if txn.cbw.flags & 0x80 else "OUT",
        "cbw_data_len": txn.cbw.data_len,
       **decode_cdb(txn.cbw.cdb),
        "data": decode_data(txn),
        "csw_frame": csw.frame if csw else None,
        "csw_status": status,
        "csw_status_name": CSW_STATUS_NAMES.get(status, "unknown") if status is not None else None,
        "csw_residue": csw.residue if csw else None,
    }
    # Compact vendor markers for histogram consumers.
    if d.get("is_vendor_hid"):
        d["vendor_hid_type"] = d.get("hid_type")
    if d.get("candidate_upipe"):
        d["candidate_upipe"] = True
    return d


# --------------------------------------------------------------------------
# Summaries
# --------------------------------------------------------------------------

def summarise(pcap: PcapData) -> dict:
    devices = discover_devices(pcap.packets)
    txns = parse_transactions(pcap.packets)
    hid_reports = parse_hid_reports(pcap.packets)
    per_device: dict[str, dict] = {}
    for key, info in sorted(devices.items()):
        bus, dev = key
        pkts = [p for p in pcap.packets if p.bus == bus and p.dev == dev]
        xfer_counts = collections.Counter(XFER_NAMES.get(p.xfer, str(p.xfer)) for p in pkts)
        ep_counts = collections.Counter(
            "EP%d %s" % (p.ep_num, p.direction) for p in pkts)
        dev_txns = [t for t in txns if t.bus == bus and t.dev == dev]
        opcode_hist = collections.Counter(t.opcode_name for t in dev_txns)
        csw_hist = collections.Counter(
            CSW_STATUS_NAMES.get(t.csw.status, "unknown")
            for t in dev_txns if t.csw is not None)
        vendor_hid = [t for t in dev_txns if t.is_vendor_hid]
        vendor_all = [t for t in dev_txns if t.is_vendor]
        hid_hist = collections.Counter(
            r.get("kind", "unknown") for r in hid_reports
            if r["bus"] == bus and r["dev"] == dev)
        dev_hid = [r for r in hid_reports if r["bus"] == bus and r["dev"] == dev]
        per_device["%d:%d" % (bus, dev)] = {
            "vid": ("0x%04x" % info.vid) if info.vid is not None else None,
            "pid": ("0x%04x" % info.pid) if info.pid is not None else None,
            "is_wormhole": info.vid == WORMHOLE_VID and info.pid == WORMHOLE_PID,
            "packets": len(pkts),
            "by_xfer": dict(xfer_counts),
            "by_endpoint": dict(sorted(ep_counts.items())),
            "interfaces": info.interfaces,
            "scsi_transactions": len(dev_txns),
            "opcode_histogram": dict(opcode_hist),
            "csw_status_histogram": dict(csw_hist),
            "vendor_hid_packets": len(vendor_hid),
            "vendor_hid_types": dict(collections.Counter(
                decode_vendor_cdb(t.cbw.cdb).get("hid_type", "unknown")
                for t in vendor_hid)),
            "vendor_cdb_packets": len(vendor_all),
            "candidate_upipe_packets": sum(
                1 for t in vendor_all if not t.is_vendor_hid),
            "hid_reports": len(dev_hid),
            "hid_kind_histogram": dict(hid_hist),
            "hid_samples": dev_hid[:5],
        }
    wormholes = [k for k, v in per_device.items() if v["is_wormhole"]]
    return {
        "file": pcap.path, "sha256": pcap.sha256, "linktype": pcap.linktype,
        "packets": len(pcap.packets), "duration_s": round(pcap.duration, 6),
        "first_ts": pcap.first_ts,
        "devices": per_device,
        "wormhole_devices": wormholes,
        "total_vendor_hid_packets": sum(
            d["vendor_hid_packets"] for d in per_device.values()),
        "total_candidate_upipe_packets": sum(
            d["candidate_upipe_packets"] for d in per_device.values()),
        "total_hid_reports": len(hid_reports),
        "hid_reports": hid_reports,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _fmt_device_table(summary: dict) -> list[str]:
    lines = ["Devices (Bus:Dev  VID:PID  packets  control/bulk/interrupt  SCSI txns  vendorHID  HID)"]
    for key, d in sorted(summary["devices"].items()):
        vidpid = "%s:%s" % (d["vid"], d["pid"]) if d["vid"] else "unknown"
        mark = "  <-- WormholeSwitch" if d["is_wormhole"] else ""
        lines.append("  %s  %s  %d  %s  %d  %d  %d%s" % (
            key, vidpid, d["packets"],
            "/".join(str(d["by_xfer"].get(k, 0)) for k in ("control", "bulk", "interrupt")),
            d["scsi_transactions"],
            d.get("vendor_hid_packets", 0),
            d.get("hid_reports", 0),
            mark))
    return lines


def _fmt_interfaces(interfaces: list[dict]) -> list[str]:
    lines = []
    for iface in interfaces:
        lines.append("    If %d: class 0x%02x/0x%02x/0x%02x" % (
            iface["number"], iface["class"], iface["subclass"], iface["protocol"]))
        for ep in iface["endpoints"]:
            lines.append("      EP %s %s attr 0x%02x maxpkt %d" % (
                ep["address"], ep["direction"], ep["attributes"], ep["max_packet"]))
    return lines


def _fmt_txn(t: dict) -> str:
    data = t.get("data") or {}
    extra = ""
    if t.get("is_vendor_hid"):
        extra = " vendorHID type=%s payload=%s footer_ok=%s framing=%s" % (
            t.get("hid_type", "?"), t.get("payload_hex", "")[:24],
            t.get("footer_ok"), t.get("valid_hid_framing"))
        if data.get("len"):
            extra += " data[%d]=%s" % (data["len"], data["hex"][:48])
    elif t.get("candidate_upipe"):
        extra = " candidateUPipe CDB=%s dataLen=%d %s" % (
            t.get("cdb_hex", "")[:32], t.get("cbw_data_len", 0),
            ("data[%d]=%s" % (data["len"], data["hex"][:48])) if data.get("len") else "")
    elif "vendor" in data:
        extra = " %r/%r rev %r PDT=%d" % (data["vendor"], data["product"],
                                          data["revision"], data["pdt"])
    elif "last_lba" in data:
        extra = " last_LBA=%d block=%d capacity=%d B" % (
            data["last_lba"], data["block_len"], data["capacity_bytes"])
    elif "sense_key_name" in data:
        extra = " key=%d (%s) ASC=%s/%s (%s)" % (
            data["sense_key"], data["sense_key_name"], data["asc"],
            data["ascq"], data["asc_name"])
    elif data.get("len"):
        extra = " data[%d]=%s" % (data["len"], data["hex"][:64])
    return "  f%-5d t=%8.3fs tag=%-8s %-28s CDB=%-24s dir=%s len=%-4d CSW=%s%s" % (
        t["cbw_frame"], t["t_offset_s"] or 0, t["tag"], t["name"],
        t.get("cdb_hex", ""), t["direction"], t["cbw_data_len"],
        t["csw_status_name"], extra)


def _fmt_hid_section(hid_reports: list[dict], limit: int = 20) -> list[str]:
    if not hid_reports:
        return ["  (no HID interrupt reports -- interfaces idle)"]
    lines = ["  %d HID report(s) total, showing up to %d:" % (len(hid_reports), min(limit, len(hid_reports)))]
    for r in hid_reports[:limit]:
        if r.get("kind") == "mouse":
            lines.append("    f%-5d %d:%d EP%d mouse buttons=0x%02x L=%s R=%s M=%s x=%+d y=%+d wheel=%+d" % (
                r["frame"], r["bus"], r["dev"], r["ep_num"],
                r.get("buttons", 0), r.get("left"), r.get("right"), r.get("middle"),
                r.get("x", 0), r.get("y", 0), r.get("wheel", 0)))
        elif r.get("kind") == "keyboard":
            mods = ",".join(r.get("modifier_names", [])) or "(none)"
            keys = ",".join(r.get("key_hex", [])) or "(none)"
            lines.append("    f%-5d %d:%d EP%d keyboard mods=[%s] keys=[%s] idle=%s" % (
                r["frame"], r["bus"], r["dev"], r["ep_num"], mods, keys, r.get("idle")))
        else:
            lines.append("    f%-5d %d:%d EP%d %s" % (
                r["frame"], r["bus"], r["dev"], r["ep_num"], r.get("error", "unknown")))
    return lines


def _fmt_pairing(pairing: dict) -> list[str]:
    lines = ["HID reports vs accepted 0xD9 sends (devices %s):"
             % (", ".join(pairing["device_keys"]) or "none")]
    lines.append("  accepted sends: %d  reports: %d  paired: %d  orphans: %d"
                 "  unpaired sends: %d" % (
                     pairing["accepted_sends"], pairing["reports"],
                     len(pairing["pairs"]), len(pairing["orphans"]),
                     len(pairing["unpaired_sends"])))
    if pairing.get("peer_offset_s"):
        src = pairing.get("peer_offset_source", "flag")
        how = ("auto-estimated from pairing yield" if src == "estimated"
               else "from --peer-offset")
        lines.append("  peer clock offset applied: %+.1f ms (%s)"
                     % (pairing["peer_offset_s"] * 1000.0, how))
        if src == "estimated":
            lines.append("  NOTE: pairing pairs more with this correction"
                         " -- the two hosts' clocks differ.  Treat the result"
                         " as skew-corrected; single-ended conclusions stay"
                         " inferred, not verified.")
    for p in pairing["pairs"]:
        r = p["report"]
        lines.append("  PAIRED  report f%-5d %d:%d EP%d %s hex=%s"
                     " <- send f%d %d:%d payload=%s gap=%+.3fs" % (
                         r["frame"], r["bus"], r["dev"], r["ep_num"],
                         r["kind"], r["hex"], p["send_frame"],
                         p["send_bus"], p["send_dev"],
                         p["send_payload_hex"], p["gap_s"]))
    for r in pairing["orphans"]:
        lines.append("  ORPHAN  report f%-5d %d:%d EP%d %s hex=%s -- no"
                     " matching accepted 0xD9 send in the analysed packets"
                     % (
                         r["frame"], r["bus"], r["dev"], r["ep_num"],
                         r["kind"], r["hex"]))
    for s in pairing["unpaired_sends"]:
        lines.append("  UNPAIRED send  f%-5d %d:%d %s payload=%s -- not"
                     " consumed by any report in the analysed packets" % (
                         s["frame"], s["bus"], s["dev"], s["hid_type"],
                         s["payload_hex"]))
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("pcap", help="usbmon pcap (linktype 220)")
    ap.add_argument("--device", metavar="BUS:DEV",
                    help="only summarise this device, e.g. 3:15 (default: "
                         "WormholeSwitch if found, else all devices); for "
                         "--orphans the filter applies to both captures")
    ap.add_argument("--all", action="store_true",
                    help="show transactions for every device, not just Wormhole")
    ap.add_argument("--no-transactions", action="store_true",
                    help="summary only, no per-transaction list")
    ap.add_argument("--hid", action="store_true",
                    help="emphasise HID + vendor sections (verbose HID list)")
    ap.add_argument("--orphans", action="store_true",
                    help="pair HID reports with accepted 0xD9 sends and "
                         "flag reports with no matching send (issue #15)")
    ap.add_argument("--peer", metavar="PCAP", default=None,
                    help="second capture from the other cable end; reports "
                         "and sends pair across the two captures (device "
                         "identity is per capture, so equal bus:dev is fine)")
    ap.add_argument("--peer-offset", metavar="SECONDS", default="0",
                    help="shift every timestamp in the peer capture "
                         "(reports and sends alike) by -SECONDS before "
                         "pairing; positive means the peer clock is "
                         "ahead.  Float seconds, or 'auto' to pick the "
                         "value in [+-100 ms] that maximises pairs "
                         "(default: 0)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    try:
        pcap = read_pcap(args.pcap)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1 if isinstance(e, OSError) else 2

    summary = summarise(pcap)
    first_ts = summary["first_ts"] or 0.0
    txns = parse_transactions(pcap.packets)

    # Decide which devices get a transaction listing.
    want: set[tuple[int, int]] | None
    device_filter: set[tuple[str, int, int]] | None = None
    if args.device:
        try:
            bus_s, dev_s = args.device.split(":")
            want = {(int(bus_s), int(dev_s))}
        except ValueError:
            print("error: --device must be BUS:DEV", file=sys.stderr)
            return 1
        # Pairing keys are (capture_id, bus, dev); the BUS:DEV filter
        # applies to both captures.
        device_filter = {(capture_id, int(bus_s), int(dev_s))
                         for capture_id in
                         ["main"] + (["peer"] if args.peer else [])}
    elif args.all:
        want = None  # all
    elif summary["wormhole_devices"]:
        want = {(int(k.split(":")[0]), int(k.split(":")[1])) for k in summary["wormhole_devices"]}
    else:
        want = None
    shown = [t for t in txns if want is None or (t.bus, t.dev) in want]
    txn_dicts = [transaction_to_dict(t, first_ts) for t in sorted(shown, key=lambda t: t.cbw.frame)]

    pairing = None
    if args.orphans:
        packets = pcap.packets
        if args.peer:
            peer = read_pcap(args.peer, capture_id="peer")
            packets = pcap.packets + peer.packets
        offset_arg = str(args.peer_offset).strip().lower()
        if offset_arg == "auto":
            peer_offset, estimate = 0.0, True
        else:
            try:
                peer_offset, estimate = float(offset_arg), False
            except ValueError:
                print("error: --peer-offset must be a float or 'auto'",
                      file=sys.stderr)
                return 1
        pairing = pair_hid_reports_to_sends(
            packets, device_filter,
            peer_offset=peer_offset, estimate_offset=estimate,
            peer_capture_id="peer" if args.peer else None)

    if args.json:
        out = dict(summary)
        out["transactions"] = txn_dicts
        if pairing is not None:
            out["hid_send_pairing"] = pairing
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0

    print("File: %s" % summary["file"])
    print("SHA-256: %s" % summary["sha256"])
    print("Packets: %d  duration: %.3fs  linktype: %d (usb-linux-mmap)" % (
        summary["packets"], summary["duration_s"], summary["linktype"]))
    print("Vendor HID (0xD9) packets: %d  candidate UPipe: %d  HID reports: %d" % (
        summary.get("total_vendor_hid_packets", 0),
        summary.get("total_candidate_upipe_packets", 0),
        summary.get("total_hid_reports", 0)))
    print()
    print("\n".join(_fmt_device_table(summary)))

    # Enumeration detail for the focused device(s).
    devices = discover_devices(pcap.packets)
    focus: set[tuple[int, int]] = want if want is not None else {(t.bus, t.dev) for t in shown}
    for key in sorted(focus):
        info = devices.get(key)
        if info and info.interfaces:
            print("\nEnumeration %d:%d:" % key)
            print("\n".join(_fmt_interfaces(info.interfaces)))

    if not args.no_transactions:
        print("\nSCSI Bulk-Only transactions (%d):" % len(txn_dicts))
        for t in txn_dicts:
            print(_fmt_txn(t))

    # HID detail for focused devices.
    hid = [r for r in summary.get("hid_reports", [])
           if want is None or (r["bus"], r["dev"]) in want]
    print("\nHID interrupt reports (%d in focus):" % len(hid))
    print("\n".join(_fmt_hid_section(hid, limit=50 if args.hid else 20)))

    if pairing is not None:
        print()
        print("\n".join(_fmt_pairing(pairing)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
