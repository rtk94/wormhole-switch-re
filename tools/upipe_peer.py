#!/usr/bin/env python3
"""UPipe peer for the Wormhole cable (Linux, SG_IO).

Plays the OTiTransfer state machine so that the GoBridge software on the
*other* end of the cable sees a live peer and starts sending UPipe packets.
Every fetched 64 KiB packet is written to --out together with a JSONL log.

Without --login the tool is receive-only: it sends only the status poll and
the fetch command.  With --login NAME it also answers the peer's LoginCommand
with a ResponseResult and logs in to the peer under NAME, which is what the
GoBridge daemon waits for before going any further.  --clipboard TEXT then
pushes TEXT to the peer's clipboard as a Cmd_Transfer_Clipboard XmlPacket.

Layers (decompiled from macOS OTiTransfer + GoBridgeDemon; see
docs/upipe-protocol.md):

  SCSI   poll  d8 00 03 <txHi> <txLo> 00.. 4f 54   data-in 16 B
               reply byte 0 = state; 5 => bytes 1-2 = packets waiting (BE16);
               6 => may send one packet; 7 => may send <tx> packets
         fetch d9 28 64 00.. 4f 54                  data-in 65536 B
         send  d9 2a ff 00.. 4f 54                  data-out 65536 B
  OTi    packet = 0xffec-byte body + body[0:20]     (integrity tail)
  chunk  body = <u32 seq> <u32 session> <u32 index> <u32 total> <u32 len>
               + len bytes of the command (all u32 little-endian);
               a command ends with an all-zero chunk (seq 0)
  cmd    byte 0 = command ID (0x01 Login, 0x02 Logout, 0xA1 ResponseResult,
               ...); the rest is per command, multi-byte fields big-endian

Raw packets can carry host names and user data: keep --out outside the repo.

Usage:
  python3 tools/upipe_peer.py /dev/sgN --out ~/wormhole-private/upipe/RUN --seconds 60
  python3 tools/upipe_peer.py /dev/sgN --out ... --login linux-peer
  python3 tools/upipe_peer.py /dev/sgN --out ... --login linux-peer --clipboard "hello"
"""

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import struct
import sys
import time

SG_IO = 0x2285
SG_DXFER_TO_DEV = -2
SG_DXFER_FROM_DEV = -3
SENSE_LEN = 32
PACKET_LEN = 0x10000
BODY_LEN = PACKET_LEN - 20          # 0xffec
CHECK_LEN = 20
HEADER = struct.Struct("<5I")       # seq, session, index, total, length
CHUNK_DATA = BODY_LEN - HEADER.size  # 0xffd8

STATES = {
    0x00: "remote-device-offline",
    0x01: "remote-device-online-app-offline",
    0x04: "remote-packet-size",
    0x05: "data-waiting",
    0x06: "ready-for-tx-single",
    0x07: "remote-app-online",
    0x08: "remote-device-offline",
    0x09: "remote-requests-resend",
    0x0A: "remote-requests-remove-last",
    0x10: "remote-device-offline",
}

CMD_LOGIN = 0x01
CMD_LOGOUT = 0x02
CMD_XML = 0x39
CMD_RESPONSE = 0xA1
COMMANDS = {
    0x00: "Dummy", 0x01: "Login", 0x02: "Logout", 0x04: "GetDirectoryInfo",
    0x06: "DeleteDirectory", 0x07: "MakeNewDirectory", 0x08: "DeleteFile",
    0x09: "RenameFile", 0x0C: "ChangeFileAttribute", 0x37: "SyncDynamic",
    0x39: "XmlPacket", 0xA1: "ResponseResult",
}

# GB OS byte: high nibble = type, low nibble = version (KMClipboard.dylib).
OS_WIN, OS_MAC, OS_LINUX = 0x00, 0x10, 0x20
OS_NAMES = {OS_WIN: "windows", OS_MAC: "mac", OS_LINUX: "linux"}


class SgIoHdr(ctypes.Structure):
    """struct sg_io_hdr from linux/scsi/sg.h (88 bytes on x86-64)."""
    _fields_ = [
        ("interface_id", ctypes.c_int),
        ("dxfer_direction", ctypes.c_int),
        ("cmd_len", ctypes.c_ubyte),
        ("mx_sb_len", ctypes.c_ubyte),
        ("iovec_count", ctypes.c_ushort),
        ("dxfer_len", ctypes.c_uint),
        ("dxferp", ctypes.c_void_p),
        ("cmdp", ctypes.c_void_p),
        ("sbp", ctypes.c_void_p),
        ("timeout", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("pack_id", ctypes.c_int),
        ("usr_ptr", ctypes.c_void_p),
        ("status", ctypes.c_ubyte),
        ("masked_status", ctypes.c_ubyte),
        ("msg_status", ctypes.c_ubyte),
        ("sb_len_wr", ctypes.c_ubyte),
        ("host_status", ctypes.c_ushort),
        ("driver_status", ctypes.c_ushort),
        ("resid", ctypes.c_int),
        ("duration", ctypes.c_uint),
        ("info", ctypes.c_uint),
    ]


# ---------------------------------------------------------------- SCSI CDBs

def build_poll_cdb(tx_pending=0):
    """GetRemoteHostStatus CDB; tx_pending = packets this side has queued."""
    if not 0 <= tx_pending <= 0xFFFF:
        raise ValueError("tx_pending out of range")
    return bytes([0xD8, 0x00, 0x03, tx_pending >> 8, tx_pending & 0xFF]) + bytes(9) + b"OT"


def build_fetch_cdb():
    """GetData CDB (64 KiB data-in)."""
    return bytes([0xD9, 0x28, 0x64]) + bytes(11) + b"OT"


def build_send_cdb():
    """PutData CDB (64 KiB data-out).  The Mac leaves bytes 3-13 as stack garbage."""
    return bytes([0xD9, 0x2A, 0xFF]) + bytes(11) + b"OT"


def parse_status(reply):
    """Decode the 16-byte poll reply."""
    if len(reply) < 3:
        raise ValueError("short status reply")
    state = reply[0]
    out = {"state": state, "name": STATES.get(state, "unknown"), "raw": bytes(reply).hex()}
    if state == 0x05:
        out["waiting"] = (reply[1] << 8) | reply[2]
    return out


def tx_allowance(state, queued):
    """Packets OTiTransporter::ProcessIdleState would send for this poll state."""
    if state == 0x07:
        return queued
    if state == 0x06:
        return min(queued, 1)
    return 0


# ------------------------------------------------------------ OTi packets

def packet_tail_ok(pkt):
    """True when the first 20 bytes repeat at the end of the 64 KiB packet."""
    if len(pkt) != PACKET_LEN:
        return False
    return pkt[:CHECK_LEN] == pkt[PACKET_LEN - CHECK_LEN:]


def wrap_packet(body):
    """Pad a chunk body to 0xffec bytes and append its first 20 bytes."""
    if len(body) > BODY_LEN:
        raise ValueError("body too long")
    body = bytes(body) + bytes(BODY_LEN - len(body))
    return body + body[:CHECK_LEN]


# ----------------------------------------------------------- chunk framing

class Framer:
    """CommandSender.wrappedCommandDataWith: split a command into chunks.

    seq counts packets (never 0), session counts commands (starts at 1).
    """

    def __init__(self, seq=0, session=1):
        self.seq = seq
        self.session = session

    def frame(self, command):
        total = max(1, -(-len(command) // CHUNK_DATA))
        out = []
        for index in range(total):
            self.seq = (self.seq + 1) & 0xFFFFFFFF or 1
            part = command[index * CHUNK_DATA:(index + 1) * CHUNK_DATA]
            out.append(wrap_packet(HEADER.pack(self.seq, self.session, index, total, len(part)) + part))
        out.append(wrap_packet(b""))  # all-zero terminator chunk
        self.session += 1
        return out


def parse_chunk(pkt):
    """Split a fetched packet into its chunk header and command bytes."""
    seq, session, index, total, length = HEADER.unpack_from(pkt)
    if length > CHUNK_DATA:
        raise ValueError("chunk length %d too large" % length)
    return {"seq": seq, "session": session, "index": index, "total": total,
            "length": length, "data": bytes(pkt[HEADER.size:HEADER.size + length])}


class Reassembler:
    """CommandDataBuffer: collect chunks per session until all have arrived."""

    def __init__(self):
        self.pending = {}

    def add(self, chunk):
        """Return the full command bytes once a session is complete, else None."""
        if chunk["seq"] == 0:
            return None  # terminator
        parts = self.pending.setdefault(chunk["session"], {})
        parts[chunk["index"]] = chunk["data"]
        if len(parts) < chunk["total"]:
            return None
        del self.pending[chunk["session"]]
        return b"".join(parts[i] for i in sorted(parts))


# --------------------------------------------------------------- commands

def encode_login(name, os_byte=OS_LINUX, code_page=0):
    """LoginCommand.encodeData: 01 <os> <codepage BE16> <len> <utf-8 name>."""
    raw = name.encode("utf-8")
    if len(raw) > 0xFF:
        raise ValueError("login name too long")
    return bytes([CMD_LOGIN, os_byte]) + struct.pack(">H", code_page) + bytes([len(raw)]) + raw


def decode_login(cmd):
    if len(cmd) < 5 or cmd[0] != CMD_LOGIN:
        raise ValueError("not a LoginCommand")
    n = cmd[4]
    os_byte = cmd[1]
    return {"os": os_byte, "os_type": OS_NAMES.get(os_byte & 0xF0, "unknown"),
            "os_version": os_byte & 0x0F, "code_page": struct.unpack(">H", cmd[2:4])[0],
            "name": cmd[5:5 + n].decode("utf-8", "replace")}


def encode_response(request_command, result=0, os_byte=None, session_id=0, error_code=0):
    """ResponseResult.encodeData (big-endian fields, as the Mac encodes them).

    With os_byte set, extraInfoFlag = 3 and extraInfo = b"OSVERSION" + os
    (setExtraInfoWithOSVersion:); extraInfoLength stays 0 in that case.
    Ends with the 6-byte tag and an empty error string, as the Mac sends.
    """
    extra, flag = b"", 0
    if os_byte is not None:
        extra, flag = b"OSVERSION" + bytes([os_byte]), 3
    return (bytes([CMD_RESPONSE, request_command, result])
            + struct.pack(">IIII", session_id, error_code, 0, 0)
            + bytes([flag]) + struct.pack(">I", 0 if flag == 3 else len(extra)) + extra
            + bytes(6) + struct.pack(">I", 0))


def decode_response(cmd):
    if len(cmd) < 24 or cmd[0] != CMD_RESPONSE:
        raise ValueError("not a ResponseResult")
    out = {"request_command": cmd[1], "result": cmd[2],
           "session_id": struct.unpack(">I", cmd[3:7])[0],
           "error_code": struct.unpack(">I", cmd[7:11])[0],
           "extra_flag": cmd[19]}
    if cmd[19] == 3 and cmd[24:33] == b"OSVERSION":
        out["os"] = cmd[33]
    return out


def encode_xml_packet(xml):
    """XmlPacketCommand: 39 <xml length BE32> <xml, UTF-8, no terminator>."""
    raw = xml.encode("utf-8")
    return bytes([CMD_XML]) + struct.pack(">I", len(raw)) + raw


def decode_xml_packet(cmd):
    if len(cmd) < 5 or cmd[0] != CMD_XML:
        raise ValueError("not an XmlPacket")
    n = struct.unpack(">I", cmd[1:5])[0]
    if 5 + n > len(cmd):
        raise ValueError("XmlPacket length %d exceeds command" % n)
    return cmd[5:5 + n].decode("utf-8", "replace")


# Clipboard push as the Mac sends it (2026-11-11 capture); the pipe name and
# HookAppService are the Windows clipboard agent's routing, kept verbatim.
CLIPBOARD_XML = (
    "<ExtraXmlCommand>HookAppService</ExtraXmlCommand><ExtraXmlParam><OTIMSG>"
    "<Param_Clipboard_Info_2><OTIMSG>{body}</OTIMSG></Param_Clipboard_Info_2>"
    "<NP_Cmd>Cmd_Transfer_Clipboard</NP_Cmd>"
    "<NP_Up_Notice_NamePipe_Name>\\\\.\\pipe\\OTI_ClipboardAgent</NP_Up_Notice_NamePipe_Name>"
    "</OTIMSG></ExtraXmlParam>")


def encode_clipboard_text(text):
    """Cmd_Transfer_Clipboard XmlPacket carrying text (UTF-16LE + NUL, uppercase hex)."""
    content = (text + "\0").encode("utf-16le").hex().upper()
    body = "<CP_Content>%s</CP_Content><CB_Format_Type>CB_Format_Text</CB_Format_Type>" % content
    return encode_xml_packet(CLIPBOARD_XML.format(body=body))


def _tag(xml, name):
    start, end = "<%s>" % name, "</%s>" % name
    i = xml.find(start)
    j = xml.find(end, i + len(start)) if i >= 0 else -1
    return xml[i + len(start):j] if i >= 0 and j >= 0 else None


def decode_clipboard(xml):
    """Pull the clipboard fields out of a Cmd_Transfer_Clipboard XmlPacket."""
    out = {"np_cmd": _tag(xml, "NP_Cmd"), "cb_format": _tag(xml, "CB_Format_Type")}
    content = _tag(xml, "CP_Content")
    if content is not None:
        try:
            out["text"] = bytes.fromhex(content).decode("utf-16le").rstrip("\0")
        except ValueError as e:
            out["text_error"] = str(e)
    if "<NodeInfo>" in xml:
        out["files"] = xml.count("<NodeInfo>")
    return out


def describe_command(cmd):
    if not cmd:
        return {"command": None}
    out = {"command": cmd[0], "command_name": COMMANDS.get(cmd[0], "unknown"), "len": len(cmd)}
    try:
        if cmd[0] == CMD_LOGIN:
            out.update(decode_login(cmd))
        elif cmd[0] == CMD_RESPONSE:
            out.update(decode_response(cmd))
        elif cmd[0] == CMD_XML:
            out.update(decode_clipboard(decode_xml_packet(cmd)))
    except ValueError as e:
        out["decode_error"] = str(e)
    return out


# ------------------------------------------------------------------ SG_IO

def sgio(fd, cdb, direction, buf, timeout_ms=5000):
    length = len(buf)
    cbuf = (ctypes.c_ubyte * length).from_buffer(buf) if length else None
    cmd = (ctypes.c_ubyte * len(cdb))(*cdb)
    sense = (ctypes.c_ubyte * SENSE_LEN)()
    hdr = SgIoHdr()
    hdr.interface_id = ord("S")
    hdr.dxfer_direction = direction
    hdr.cmd_len = len(cdb)
    hdr.mx_sb_len = SENSE_LEN
    hdr.dxfer_len = length
    hdr.dxferp = ctypes.cast(cbuf, ctypes.c_void_p) if cbuf is not None else None
    hdr.cmdp = ctypes.cast(cmd, ctypes.c_void_p)
    hdr.sbp = ctypes.cast(sense, ctypes.c_void_p)
    hdr.timeout = timeout_ms
    fcntl.ioctl(fd, SG_IO, hdr)
    ok = hdr.status == 0 and hdr.host_status == 0 and hdr.driver_status == 0
    return ok, hdr.resid, {
        "status": hdr.status, "host_status": hdr.host_status,
        "driver_status": hdr.driver_status, "resid": hdr.resid,
        "sense": bytes(sense[:hdr.sb_len_wr]).hex(), "duration_ms": hdr.duration,
    }


def sgio_read(fd, cdb, length, timeout_ms=5000):
    buf = bytearray(length)
    ok, resid, info = sgio(fd, cdb, SG_DXFER_FROM_DEV, buf, timeout_ms)
    return ok, bytes(buf[:length - resid]), info


def sgio_write(fd, cdb, data, timeout_ms=5000):
    ok, _, info = sgio(fd, cdb, SG_DXFER_TO_DEV, bytearray(data), timeout_ms)
    return ok, info


# ------------------------------------------------------------------- main

def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("dev", help="Wormhole SCSI generic node, e.g. /dev/sg1")
    ap.add_argument("--out", required=True, help="output directory (keep outside the repo)")
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--interval", type=float, default=0.02, help="poll gap in seconds")
    ap.add_argument("--login", metavar="NAME",
                    help="answer the peer's login and log in to it as NAME (enables sending)")
    ap.add_argument("--os", choices=sorted(OS_NAMES.values()), default="linux",
                    help="OS type to announce with --login (default linux)")
    ap.add_argument("--clipboard", metavar="TEXT",
                    help="with --login: push TEXT to the peer's clipboard once logged in")
    args = ap.parse_args(argv)
    if args.clipboard is not None and not args.login:
        ap.error("--clipboard needs --login")
    os_byte = {v: k for k, v in OS_NAMES.items()}[args.os]

    os.makedirs(args.out, exist_ok=True)
    log = open(os.path.join(args.out, "upipe_peer.jsonl"), "a")

    def emit(rec):
        rec["t"] = time.time()
        log.write(json.dumps(rec) + "\n")
        log.flush()

    fd = os.open(args.dev, os.O_RDWR)
    fetch, send = build_fetch_cdb(), build_send_cdb()
    framer, reasm, txq = Framer(), Reassembler(), []
    clipboard_sent = False
    end = time.time() + args.seconds
    last_state, n_rx, n_tx = None, 0, 0
    emit({"event": "start", "dev": args.dev, "fetch_cdb": fetch.hex(), "send_cdb": send.hex(),
          "login": args.login, "os": os_byte if args.login else None})

    def queue(cmd, why):
        pkts = framer.frame(cmd)
        txq.extend(pkts)
        emit({"event": "queue", "why": why, "packets": len(pkts), **describe_command(cmd),
              "cmd_hex": cmd.hex()})
        print("queue", why, len(pkts), "packets", cmd[:24].hex(), flush=True)

    # Log in straight away: a peer that still thinks we are logged in from an
    # earlier run sends no new Login of its own to trigger ours.
    if args.login:
        queue(encode_login(args.login, os_byte), "login")

    try:
        while time.time() < end:
            ok, reply, info = sgio_read(fd, build_poll_cdb(len(txq)), 16)
            if not ok:
                emit({"event": "poll-error", **info})
                time.sleep(0.5)
                continue
            st = parse_status(reply)
            if st["raw"] != last_state:
                emit({"event": "state", "tx_pending": len(txq), **st})
                print("state", st["name"], st["raw"], flush=True)
                last_state = st["raw"]

            for _ in range(st.get("waiting", 0)):
                ok, pkt, info = sgio_read(fd, fetch, PACKET_LEN)
                n_rx += 1
                name = "pkt_%04d.bin" % n_rx
                with open(os.path.join(args.out, name), "wb") as f:
                    f.write(pkt)
                rec = {"event": "packet", "file": name, "ok": ok, "len": len(pkt),
                       "sha256": hashlib.sha256(pkt).hexdigest(),
                       "tail_ok": packet_tail_ok(pkt), "head64": pkt[:64].hex(), **info}
                cmd = None
                if ok and len(pkt) == PACKET_LEN:
                    try:
                        chunk = parse_chunk(pkt)
                        rec["chunk"] = {k: v for k, v in chunk.items() if k != "data"}
                        cmd = reasm.add(chunk)
                    except ValueError as e:
                        rec["chunk_error"] = str(e)
                emit(rec)
                print("packet", n_rx, "ok=%s tail_ok=%s" % (ok, rec["tail_ok"]),
                      pkt[:32].hex(), flush=True)
                if cmd is not None:
                    desc = describe_command(cmd)
                    emit({"event": "command", **desc, "cmd_head": cmd[:64].hex()})
                    print("command", desc, flush=True)
                    if args.login and cmd[:1] == bytes([CMD_LOGIN]):
                        queue(encode_response(CMD_LOGIN, 0, os_byte), "login-response")
                    # The peer's ResponseResult to our Login = we are logged in.
                    if (args.clipboard is not None and not clipboard_sent
                            and cmd[:2] == bytes([CMD_RESPONSE, CMD_LOGIN])):
                        queue(encode_clipboard_text(args.clipboard), "clipboard")
                        clipboard_sent = True
                if not ok:
                    break

            for _ in range(tx_allowance(st["state"], len(txq))):
                ok, info = sgio_write(fd, send, txq[0])
                n_tx += 1
                emit({"event": "sent", "n": n_tx, "ok": ok, "head32": txq[0][:32].hex(), **info})
                print("sent", n_tx, "ok=%s" % ok, txq[0][:20].hex(), info["sense"], flush=True)
                if not ok:
                    break
                txq.pop(0)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        emit({"event": "stop", "received": n_rx, "sent": n_tx, "unsent": len(txq)})
        os.close(fd)
        log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
