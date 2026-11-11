#!/usr/bin/env python3
"""UPipe peer for the Wormhole cable (Linux, SG_IO).

Plays the OTiTransfer state machine so that the GoBridge software on the
*other* end of the cable sees a live peer and starts sending UPipe packets.
Every fetched 64 KiB packet is written to --out together with a JSONL log.

Without --login the tool is receive-only: it sends only the status poll and
the fetch command.  With --login NAME it also answers the peer's LoginCommand
with a ResponseResult and logs in to the peer under NAME, which is what the
GoBridge daemon waits for before going any further.  --clipboard TEXT then
pushes TEXT to the peer's clipboard as a Cmd_Transfer_Clipboard XmlPacket,
--download PATH fetches a file from the peer, and --offer FILE puts a local
file on the peer's clipboard and serves it when it is pasted there.

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
               ...); the rest is per command.  The Mac sends multi-byte
               fields big-endian but reads a Linux peer's little-endian

Raw packets can carry host names and user data: keep --out outside the repo.

Usage:
  python3 tools/upipe_peer.py /dev/sgN --out ~/wormhole-private/upipe/RUN --seconds 60
  python3 tools/upipe_peer.py /dev/sgN --out ... --login linux-peer
  python3 tools/upipe_peer.py /dev/sgN --out ... --login linux-peer --clipboard "hello"
  python3 tools/upipe_peer.py /dev/sgN --out ... --login linux-peer --offer ./file.bin
"""

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import shutil
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
CMD_GET_DIRECTORY_INFO = 0x04
CMD_DELETE_DIRECTORY = 0x06
CMD_MAKE_NEW_DIRECTORY = 0x07
CMD_DELETE_FILE = 0x08
CMD_RENAME_FILE = 0x09
CMD_UPLOAD_FILE_DATA = 0x0C
CMD_UPLOAD_MULTI = 0x12
CMD_UPLOAD_CONFIRM = 0x13
CMD_UPLOAD_ABORT = 0x14
CMD_UPLOAD_ZERO = 0x15
CMD_UPLOAD_CONFIRMATION = 0xA8
CMD_DIRECTORY_INFO = 0xA2
CMD_DOWNLOAD_MULTI = 0x10
CMD_XML = 0x39
CMD_PACKAGE = 0x3A
CMD_CHANGE_ATTRIBUTE = 0x37
CMD_DRIVE_INFO = 0xA4
CMD_DOMAIN_FOLDERS = 0xAD
CMD_RESPONSE = 0xA1
CMD_FILE_DATA = 0xA3
CMD_DOWNLOAD_FINISHED = 0xA7; CMD_UPLOAD_ERROR = 0xA9
COMMANDS = {   # -[<Class> init] setCommandID: values (GoBridgeDemon 152311cb)
    0x00: "Dummy", 0x01: "Login", 0x02: "Logout", 0x04: "GetDirectoryInfo",
    0x06: "DeleteDirectory", 0x07: "MakeNewDirectory", 0x08: "DeleteFile",
    0x09: "RenameFile", 0x0A: "UploadFile", 0x0B: "DownloadFile", 0x0C: "UploadFileData",
    0x0D: "UploadFileAbort", 0x0E: "FileTransferFail", 0x0F: "DownloadFileAbort",
    0x10: "DownloadMultipleFile", 0x11: "DownloadMultipleFileAbort",
    0x12: "UploadMultipleFile", 0x13: "UploadMultipleFileConfirm",
    0x14: "UploadMultipleFileAbort", 0x15: "UploadMultipleFileZeroLength",
    0x34: "SyncDynamic", 0x35: "DownloadMultipleFileDynamic",
    0x36: "DownloadMultipleFileDynamicExt", 0x37: "ChangeFileAttribute",
    0x38: "QueryErrorCodeString", 0x39: "XmlPacket", 0x3A: "MultipleFilePackage",
    0xA1: "ResponseResult",
    0xA2: "DirectoryInfo", 0xA3: "DownloadFileData", 0xA4: "DriveInfo",
    0xA5: "DownloadFileDataFailed", 0xA6: "ResponseDownloadMultiFileZeroLength",
    0xA7: "DownloadMultiFileFinished", 0xA8: "UploadMultiFileConfirmation",
    0xA9: "UploadMultiFileError", 0xAA: "UploadMultiFileConfirmationExt",
    0xAB: "DownloadMultiFileException", 0xAC: "ErrorCodeStringResult",
    0xAD: "DomainFolders",
}
FILE_DATA_HEADER = 17   # FileDataCommand headerLength: id + 4 x u32

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


def encode_response(request_command, result=0, os_byte=None, session_id=0, error_code=0,
                    endian=">"):
    """ResponseResult.encodeData (big-endian fields, as the Mac encodes them).

    With os_byte set, extraInfoFlag = 3 and extraInfo = b"OSVERSION" + os
    (setExtraInfoWithOSVersion:); extraInfoLength stays 0 in that case.
    Ends with the 6-byte tag and an empty error string, as the Mac sends.
    """
    extra, flag = b"", 0
    if os_byte is not None:
        extra, flag = b"OSVERSION" + bytes([os_byte]), 3
    return (bytes([CMD_RESPONSE, request_command, result])
            + struct.pack(endian + "IIII", session_id, error_code, 0, 0)
            + bytes([flag]) + struct.pack(endian + "I", 0 if flag == 3 else len(extra)) + extra
            + bytes(6) + struct.pack(endian + "I", 0))


def decode_response(cmd, endian=">"):
    if len(cmd) < 24 or cmd[0] != CMD_RESPONSE:
        raise ValueError("not a ResponseResult")
    out = {"request_command": cmd[1], "result": cmd[2],
           "session_id": struct.unpack(endian + "I", cmd[3:7])[0],
           "error_code": struct.unpack(endian + "I", cmd[7:11])[0],
           "extra_flag": cmd[19]}
    if cmd[19] == 3 and cmd[24:33] == b"OSVERSION":
        out["os"] = cmd[33]
    return out


def encode_xml_packet(xml):
    """XmlPacketCommand: 39 <xml length BE32> <xml, UTF-8, no terminator>."""
    raw = xml.encode("utf-8")
    return bytes([CMD_XML]) + struct.pack(">I", len(raw)) + raw


def decode_xml_packet(cmd, endian=">"):
    """The XML of an XmlPacket.  The length is in the sender's byte order:
    big-endian from the Mac, little-endian from Windows (#50)."""
    if len(cmd) < 5 or cmd[0] != CMD_XML:
        raise ValueError("not an XmlPacket")
    n = struct.unpack(endian + "I", cmd[1:5])[0]
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


NODE_INFO_LEN = 824
NODE_PATH_LEN = 260                 # MAX_PATH; 8-bit at 0, UTF-16LE (520 bytes) at 260
NODE_TAIL = struct.Struct("<QQQII")  # creation, last access, last write, size high, size low
FILETIME_UNIX_EPOCH = 116444736000000000


def filetime_from_unix(t):
    """Windows FILETIME (100 ns ticks since 1601) for a Unix timestamp."""
    return FILETIME_UNIX_EPOCH + int(round(t * 10 ** 7))


def unix_from_filetime(ft):
    """Unix seconds (rounded) for a Windows FILETIME."""
    return int(round((ft - FILETIME_UNIX_EPOCH) / 10 ** 7))


CHANGE_ATTRIBUTE_HEADER = 33   # id + attributes u32 + 3 FILETIMEs + path length u32


def encode_change_file_attribute(path, attributes, ctime, atime, mtime, endian="<"):
    """ChangeFileAttribute (0x37) as a Windows peer sends it after each
    downloaded file (#50): 37 <attributes u32> <ctime> <atime> <mtime>
    (FILETIME u64 each) <path length u32, bytes> <path, UTF-16, no NUL>.
    The path is the receiver's destination path."""
    raw = path.encode("utf-16-be" if endian == ">" else "utf-16-le")
    return (bytes([CMD_CHANGE_ATTRIBUTE])
            + struct.pack(endian + "IQQQI", attributes, filetime_from_unix(ctime),
                          filetime_from_unix(atime), filetime_from_unix(mtime), len(raw))
            + raw)


def decode_change_file_attribute(cmd, endian="<"):
    if len(cmd) < CHANGE_ATTRIBUTE_HEADER or cmd[0] != CMD_CHANGE_ATTRIBUTE:
        raise ValueError("not a ChangeFileAttribute")
    attributes, ct, at, mt, n = struct.unpack(endian + "IQQQI",
                                              cmd[1:CHANGE_ATTRIBUTE_HEADER])
    if CHANGE_ATTRIBUTE_HEADER + n > len(cmd):
        raise ValueError("ChangeFileAttribute path truncated")
    raw = cmd[CHANGE_ATTRIBUTE_HEADER:CHANGE_ATTRIBUTE_HEADER + n]
    return {"attributes": attributes, "ctime": unix_from_filetime(ct),
            "atime": unix_from_filetime(at), "mtime": unix_from_filetime(mt),
            "path": raw.decode("utf-16-be" if endian == ">" else "utf-16-le").rstrip("\0")}


def encode_node_info(path, size, ctime, atime, mtime):
    """One CB_Format_File NodeInfo record (824 bytes, little-endian).

    Times are FILETIMEs (creation, last access, last write).  Bytes 812-823
    were zero in the Mac's record; their meaning is unconfirmed.
    """
    raw8, raw16 = path.encode("utf-8"), path.encode("utf-16le")
    if len(raw8) >= NODE_PATH_LEN or len(raw16) >= 2 * NODE_PATH_LEN:
        raise ValueError("path longer than MAX_PATH")
    return (raw8.ljust(NODE_PATH_LEN, b"\0") + raw16.ljust(2 * NODE_PATH_LEN, b"\0")
            + NODE_TAIL.pack(ctime, atime, mtime, size >> 32, size & 0xFFFFFFFF)
            + bytes(NODE_INFO_LEN - 3 * NODE_PATH_LEN - NODE_TAIL.size))


def decode_node_info(rec):
    if len(rec) != NODE_INFO_LEN:
        raise ValueError("NodeInfo is %d bytes, expected %d" % (len(rec), NODE_INFO_LEN))
    ctime, atime, mtime, hi, lo = NODE_TAIL.unpack_from(rec, 3 * NODE_PATH_LEN)
    path = rec[NODE_PATH_LEN:3 * NODE_PATH_LEN].decode("utf-16le").split("\0", 1)[0]
    return {"path": path, "size": (hi << 32) | lo, "ctime": ctime, "atime": atime,
            "mtime": mtime}


def node_info_for_file(path):
    """NodeInfo for a local file under its absolute POSIX path.

    The Mac writes its own paths as /\\Users\\x, but it names a pasted
    file after the part behind the last '/', so a Linux peer must send the
    plain path.  The Mac asks for the file by the same path.  Linux has no
    portable creation time, so the last-write time stands in.
    """
    st = os.stat(path)
    return encode_node_info(os.path.abspath(path), st.st_size,
                            filetime_from_unix(st.st_mtime), filetime_from_unix(st.st_atime),
                            filetime_from_unix(st.st_mtime))


def encode_clipboard_files(nodes):
    """Cmd_Transfer_Clipboard XmlPacket offering files (CB_Format_File)."""
    lines = "".join("<Line><NodeInfo>%s</NodeInfo></Line>" % n.hex().upper() for n in nodes)
    body = ("<NodeInfoList>%s</NodeInfoList><CB_Format_Type>CB_Format_File</CB_Format_Type>"
            % lines)
    return encode_xml_packet(CLIPBOARD_XML.format(body=body))


IMAGE_FORMAT_TIFF = "Apple TIFF Format"


def _hex_path(path):
    return (path + "\0").encode("utf-16-le").hex().upper() if path else ""


def encode_clipboard_image(image_path, bitmap_path=None, fmt=IMAGE_FORMAT_TIFF):
    """Cmd_Transfer_Clipboard XmlPacket for an image, as the Mac sends a copied
    picture: no pixels, only paths the receiver fetches with 0x10.
    CP_Content_ImageFile is the image in fmt (the Mac: the TIFF from the
    pasteboard); CP_Content_Bitmap_ImageFile, optional, any image NSImage
    reads (the Mac sends a Windows BMP); the Mac adds its TIFFRepresentation."""
    # An empty Bitmap element crashes GoBridgeDemon; an absent one is skipped.
    bitmap = ("<CP_Content_Bitmap_ImageFile>%s</CP_Content_Bitmap_ImageFile>"
              % _hex_path(bitmap_path) if bitmap_path else "")
    body = ("<CP_Content_Text></CP_Content_Text>%s"
            "<CP_Content_ImageFile>%s</CP_Content_ImageFile>"
            "<CB_Format_Type>%s</CB_Format_Type>"
            % (bitmap, _hex_path(image_path), fmt))
    return encode_xml_packet(CLIPBOARD_XML.format(body=body))


def posix_path(path):
    """A Mac clipboard path (/\\var\\folders\\…) as the POSIX path to request."""
    if path.startswith("/\\"):
        return "/" + path[2:].replace("\\", "/")
    return path


class ClipboardImageFetcher:
    """Fetch each image the peer copies (its CP_Content_ImageFile) with 0x10,
    saving it as clipboard_<n>.tiff.  IDs start at 1001 to stay clear of
    --download's session 1."""

    def __init__(self, first_id=1001):
        self.next_id, self.names = first_id, {}

    def request(self, peer_path, endian="<"):
        fid = self.next_id
        self.next_id += 1
        self.names[fid] = "clipboard_%d.tiff" % (len(self.names) + 1)
        return encode_download_request(fid, [(fid, posix_path(peer_path))], endian)

    def filename(self, file_id):
        return self.names.get(file_id)


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
    for key, tag in (("image_file", "CP_Content_ImageFile"),
                     ("bitmap_file", "CP_Content_Bitmap_ImageFile")):
        content = _tag(xml, tag)
        if content:
            try:
                out[key] = bytes.fromhex(content).decode("utf-16le").rstrip("\0")
            except ValueError as e:
                out[key + "_error"] = str(e)
    if "<NodeInfo>" in xml:
        out["files"] = xml.count("<NodeInfo>")
        nodes, pos = [], 0
        while True:
            i = xml.find("<NodeInfo>", pos)
            j = xml.find("</NodeInfo>", i)
            if i < 0 or j < 0:
                break
            try:
                nodes.append(decode_node_info(bytes.fromhex(xml[i + 10:j])))
            except ValueError as e:
                nodes.append({"decode_error": str(e)})
            pos = j
        out["nodes"] = nodes
    return out


def encode_download_request(multi_session_id, files, endian="<"):
    """DownloadMultipleFile (0x10): ask the peer's server to send us files.

    10 <multiSessionID u32> <count u16> { <fileID u32> <pathLen u16> <path UTF-16> }*
    The Mac decodes a remote's fields with a byte swap, and picks the UTF-16
    order, by remoteIsBigEndian, which is false for a Linux peer: so a Linux
    peer sends little-endian fields and UTF-16LE paths (the default).  Sending
    big-endian crashed GoBridgeDemon (NSRangeException on the swapped length).
    A non-Linux sender would append <destLen u16> <dest> per file; the Mac
    skips that for Linux peers.
    """
    utf16 = "utf-16-be" if endian == ">" else "utf-16-le"
    out = bytes([CMD_DOWNLOAD_MULTI]) + struct.pack(endian + "IH", multi_session_id, len(files))
    for file_id, path in files:
        raw = path.encode(utf16)
        out += struct.pack(endian + "IH", file_id, len(raw)) + raw
    return out


def decode_download_request(cmd, endian=">"):
    """DownloadMultipleFile (0x10) in the requester's byte order.

    The Mac sends it big-endian with a NUL-terminated UTF-16BE path and,
    to a Linux peer, no destination field.  The trailing NUL is stripped.
    """
    if len(cmd) < 7 or cmd[0] != CMD_DOWNLOAD_MULTI:
        raise ValueError("not a DownloadMultipleFile")
    utf16 = "utf-16-be" if endian == ">" else "utf-16-le"
    multi, count = struct.unpack(endian + "IH", cmd[1:7])
    files, off = [], 7
    for _ in range(count):
        if off + 6 > len(cmd):
            raise ValueError("DownloadMultipleFile truncated")
        file_id, n = struct.unpack(endian + "IH", cmd[off:off + 6])
        off += 6
        if off + n > len(cmd):
            raise ValueError("DownloadMultipleFile path truncated")
        path = cmd[off:off + n].decode(utf16).rstrip("\0")
        off += n
        files.append({"file_id": file_id, "path": path})
    return {"multi_session_id": multi, "files": files}


def encode_file_data(file_id, total, index, data, endian="<"):
    """DownloadFileData (0xA3) piece; index counts from 1."""
    return (bytes([CMD_FILE_DATA]) + struct.pack(endian + "IIII", file_id, total, index, len(data))
            + data)


def encode_download_finished(multi_session_id, endian="<"):
    return bytes([CMD_DOWNLOAD_FINISHED]) + struct.pack(endian + "I", multi_session_id)


def encode_upload_error(session_id, code, file_id, error, endian="<"):
    """UploadMultiFileError (0xA9); see decode_upload_error for the layout."""
    raw = (error + "\0").encode("utf-16-be" if endian == ">" else "utf-16-le")
    return (bytes([CMD_UPLOAD_ERROR]) + struct.pack(endian + "III", session_id, code, file_id)
            + bytes(6) + struct.pack(endian + "I", len(raw)) + raw)


MAX_FILE_PIECE = 0x800000           # the Mac sends at most 8 MiB per 0xA3
READ_FILE_ERROR = 6                 # "Read file data error", as the Mac reports a missing file


PACKAGE_RESERVED = 11      # bytes the Mac skips between the count and the commands


def encode_multiple_file_package(commands):
    """MultipleFilePackage (0x3a): 3a <count u32> <11 bytes> <commands>.
    MultipleFilePackage initFromData: reads the count without a byte swap
    (little-endian on the Mac), starts at offset 15 and steps by each
    command's header plus data length; THMFileManager hands every command
    to the server (< 0xa0) or client (>= 0xa0).  The Mac's encodeData writes
    no commands, so only a peer sends a usable one."""
    return (bytes([CMD_PACKAGE]) + struct.pack("<I", len(commands)) + bytes(PACKAGE_RESERVED)
            + b"".join(commands))


def decode_multiple_file_package(cmd, endian="<"):
    """The commands inside a MultipleFilePackage: file data (0xa3, 0x0c) and,
    from a Windows peer, ChangeFileAttribute (0x37) after each file (#50).
    Windows fills the 11 reserved bytes with stale buffer contents."""
    if len(cmd) < 5 + PACKAGE_RESERVED or cmd[0] != CMD_PACKAGE:
        raise ValueError("not a MultipleFilePackage")
    (count,) = struct.unpack("<I", cmd[1:5])
    off, out = 5 + PACKAGE_RESERVED, []
    for _ in range(count):
        if off < len(cmd) and cmd[off] in (CMD_FILE_DATA, CMD_UPLOAD_FILE_DATA):
            header, length_at = FILE_DATA_HEADER, 13
        elif off < len(cmd) and cmd[off] == CMD_CHANGE_ATTRIBUTE:
            header, length_at = CHANGE_ATTRIBUTE_HEADER, 29
        else:
            raise ValueError("MultipleFilePackage command %d truncated or unsupported"
                             % len(out))
        if off + header > len(cmd):
            raise ValueError("MultipleFilePackage command %d truncated" % len(out))
        (length,) = struct.unpack(endian + "I", cmd[off + length_at:off + length_at + 4])
        end = off + header + length
        if end > len(cmd):
            raise ValueError("MultipleFilePackage command %d truncated" % len(out))
        out.append(cmd[off:end])
        off = end
    return out


def package_file_data(replies, limit=MAX_FILE_PIECE):
    """Bundle runs of whole-file 0xa3 replies (totalCount 1) into 0x3a
    packages of at most limit data bytes; a run of one stays bare."""
    out, run, size = [], [], 0

    def flush():
        out.extend([encode_multiple_file_package(run)] if len(run) > 1 else run)

    for r in replies:
        whole = r[0] == CMD_FILE_DATA and struct.unpack("<I", r[5:9])[0] == 1
        n = len(r) - FILE_DATA_HEADER
        if whole and run and size + n <= limit:
            run.append(r)
            size += n
            continue
        flush()
        run, size = ([r], n) if whole else ([], 0)
        if not whole:
            out.append(r)
    flush()
    return out


def serve_download(cmd, offered, endian="<", piece=MAX_FILE_PIECE, request_endian=">",
                   package=True):
    """Answer a peer's DownloadMultipleFile the way THMGBServer does.

    offered maps the peer-side path we put on its clipboard to the local
    file; nothing else is served.  Replies: ResponseResult, then 0xA3
    pieces per file and 0xA7, or 0xA9 at the first file that cannot be
    read (the Mac then sends nothing more for the request).  With package,
    small whole files travel together in MultipleFilePackage (0x3a).
    """
    finish = (lambda r: package_file_data(r, piece)) if package and endian == "<" \
        else (lambda r: r)
    req = decode_download_request(cmd, request_endian)
    multi = req["multi_session_id"]
    out = [encode_response(CMD_DOWNLOAD_MULTI, 0, session_id=multi, endian=endian)]
    for f in req["files"]:
        local = offered.get(f["path"])
        try:
            if local is None:
                raise OSError("not offered")
            with open(local, "rb") as fh:
                data = fh.read()
        except OSError:
            out.append(encode_upload_error(multi, READ_FILE_ERROR, f["file_id"],
                                           "Read file data error", endian))
            return finish(out)
        total = max(1, -(-len(data) // piece))
        for i in range(total):
            out.append(encode_file_data(f["file_id"], total, i + 1,
                                        data[i * piece:(i + 1) * piece], endian))
    out.append(encode_download_finished(multi, endian))
    return finish(out)


def decode_file_data(cmd, endian=">"):
    """DownloadFileData (0xA3): a3 <sessionFileID> <totalCount> <index> <dataLength> <data>."""
    if len(cmd) < FILE_DATA_HEADER or cmd[0] != CMD_FILE_DATA:
        raise ValueError("not a DownloadFileData")
    file_id, total, index, length = struct.unpack(endian + "IIII", cmd[1:FILE_DATA_HEADER])
    data = cmd[FILE_DATA_HEADER:FILE_DATA_HEADER + length]
    if len(data) != length:
        raise ValueError("DownloadFileData truncated: %d of %d bytes" % (len(data), length))
    return {"file_id": file_id, "total": total, "index": index, "data_length": length,
            "data": data}


def decode_upload_error(cmd, endian=">"):
    """UploadMultiFileError (0xA9), big-endian; the Mac sends it for a missing
    file and ends the whole request (no further files, no 0xA7):
    a9 <sessionID u32> <errorCode u32> <errorFileID u32> <tag 6 B>
       <errorStringLength u32> <errorString UTF-16BE, NUL-terminated>
    """
    if len(cmd) < 23 or cmd[0] != CMD_UPLOAD_ERROR:
        raise ValueError("not an UploadMultiFileError")
    session_id, code, file_id = struct.unpack(endian + "III", cmd[1:13])
    (length,) = struct.unpack(endian + "I", cmd[19:23])
    raw = cmd[23:23 + length]
    if len(raw) != length:
        raise ValueError("UploadMultiFileError string truncated")
    return {"session_id": session_id, "error_code": code, "file_id": file_id,
            "tag": cmd[13:19].hex(),
            "error": raw.decode("utf-16-be" if endian == ">" else "utf-16-le").rstrip("\0")}


# ------------------------------------------- DomainFolders (0xad), DriveInfo (0xa4)
# Sent right after Login between a Mac and a Windows peer
# (forwardDomainFoldersInfoToRemote; 2026-11-11 capture, #50).

DOMAIN_FOLDER_TAG = 0x0FF0          # high half of each entry's first u32
DOMAIN_FOLDER_NAMES = {0: "Desktop", 1: "Documents", 2: "MiscInfoFile", 3: "Music",
                       4: "Pictures"}


def encode_domain_folders(folders, endian=">"):
    """DomainFolders (0xad): ad <length u32 LE> <count u8> {<tag u32> <len u32> <path>}.

    tag is 0x0ff0 << 16 | folder type (0 Desktop, 1 Documents, 2 the peer's
    misc-info file, 3 Music, 4 Pictures).  As captured: the Mac writes the u32s
    big-endian and NUL-terminates its paths, and its length covers the
    entries; Windows writes little-endian without NULs, and its length also
    counts the count byte.  The length itself is little-endian from both."""
    entries = b""
    for kind, path in folders:
        raw = path.encode(_utf16(endian)) + (b"\0\0" if endian == ">" else b"")
        entries += struct.pack(endian + "II", DOMAIN_FOLDER_TAG << 16 | kind, len(raw)) + raw
    length = len(entries) + (0 if endian == ">" else 1)
    return bytes([CMD_DOMAIN_FOLDERS]) + struct.pack("<I", length) + bytes([len(folders)]) + entries


def decode_domain_folders(cmd, endian=">"):
    if len(cmd) < 6 or cmd[0] != CMD_DOMAIN_FOLDERS:
        raise ValueError("not a DomainFolders")
    (length,) = struct.unpack("<I", cmd[1:5])
    off, folders = 6, []
    for _ in range(cmd[5]):
        if off + 8 > len(cmd):
            raise ValueError("DomainFolders entry %d truncated" % len(folders))
        tag, n = struct.unpack(endian + "II", cmd[off:off + 8])
        if tag >> 16 != DOMAIN_FOLDER_TAG:
            raise ValueError("DomainFolders entry %d tag 0x%08x" % (len(folders), tag))
        if off + 8 + n > len(cmd):
            raise ValueError("DomainFolders entry %d path truncated" % len(folders))
        kind = tag & 0xFFFF
        folders.append({"type": kind, "name": DOMAIN_FOLDER_NAMES.get(kind, "unknown"),
                        "path": cmd[off + 8:off + 8 + n].decode(_utf16(endian)).rstrip("\0")})
        off += 8 + n
    return {"length_field": length, "folders": folders}


def encode_drive_info_volumes(volumes, endian=">"):
    """DriveInfo (0xa4) as the Mac sends it: a4 <count u16 LE>
    {<entry length u16> <name length u16> <name> <path length u16> <path>},
    the u16s in the sender's order, UTF-16 with a NUL; entry length counts
    itself."""
    out = bytes([CMD_DRIVE_INFO]) + struct.pack("<H", len(volumes))
    for name, path in volumes:
        n = name.encode(_utf16(endian)) + b"\0\0"
        p = path.encode(_utf16(endian)) + b"\0\0"
        out += (struct.pack(endian + "HH", 6 + len(n) + len(p), len(n)) + n
                + struct.pack(endian + "H", len(p)) + p)
    return out


def encode_drive_info_letters(drives):
    """DriveInfo (0xa4) as Windows sends it: a4 <count u16 LE> {<letter> <type>}.
    Observed types: 2 for C:, 4 for the two CD-ROM drives."""
    return (bytes([CMD_DRIVE_INFO]) + struct.pack("<H", len(drives))
            + b"".join(bytes([ord(letter), kind]) for letter, kind in drives))


def decode_drive_info(cmd, endian=">"):
    """Either DriveInfo form; the letter form is recognised by its shape."""
    if len(cmd) < 3 or cmd[0] != CMD_DRIVE_INFO:
        raise ValueError("not a DriveInfo")
    (count,) = struct.unpack("<H", cmd[1:3])
    pairs = cmd[3:]
    if len(pairs) == 2 * count and all(0x41 <= pairs[i] <= 0x5A for i in range(0, len(pairs), 2)):
        return {"drives": [{"letter": chr(pairs[i]), "type": pairs[i + 1]}
                           for i in range(0, len(pairs), 2)]}
    off, drives = 3, []
    for _ in range(count):
        if off + 4 > len(cmd):
            raise ValueError("DriveInfo entry %d truncated" % len(drives))
        entry, n = struct.unpack(endian + "HH", cmd[off:off + 4])
        if off + 6 + n > len(cmd):
            raise ValueError("DriveInfo entry %d name truncated" % len(drives))
        (m,) = struct.unpack(endian + "H", cmd[off + 4 + n:off + 6 + n])
        if entry != 6 + n + m or off + entry > len(cmd):
            raise ValueError("DriveInfo entry %d length mismatch" % len(drives))
        drives.append({"name": cmd[off + 4:off + 4 + n].decode(_utf16(endian)).rstrip("\0"),
                       "path": cmd[off + 6 + n:off + entry].decode(_utf16(endian)).rstrip("\0")})
        off += entry
    return {"drives": drives}


def describe_command(cmd, endian=">"):
    """Decode a command for logging.

    endian is the sender's byte order: the Mac's commands are big-endian,
    the replies this tool sends to the Mac and a Windows peer's commands
    little-endian.  When a command does not decode in that byte order the
    other one is tried; fields with no internal check (session ids) can
    only be right if endian is.
    """
    if not cmd:
        return {"command": None}
    out = {"command": cmd[0], "command_name": COMMANDS.get(cmd[0], "unknown"), "len": len(cmd)}
    other = "<" if endian == ">" else ">"
    try:
        out.update(_command_fields(cmd, endian))
    except (ValueError, UnicodeDecodeError, struct.error) as e:
        try:
            out.update(_command_fields(cmd, other))
        except (ValueError, UnicodeDecodeError, struct.error):
            out["decode_error"] = str(e)
    return out


def _command_fields(cmd, endian):
    """The decoded fields of cmd, read in byte order endian."""
    out = {}
    if cmd[0] == CMD_LOGIN:
        out.update(decode_login(cmd))
    elif cmd[0] == CMD_RESPONSE:
        out.update(decode_response(cmd, endian))
    elif cmd[0] == CMD_XML:
        out.update(decode_clipboard(decode_xml_packet(cmd, endian)))
    elif cmd[0] == CMD_CHANGE_ATTRIBUTE:
        out.update(decode_change_file_attribute(cmd, endian))
    elif cmd[0] == CMD_DOMAIN_FOLDERS:
        out.update(decode_domain_folders(cmd, endian))
    elif cmd[0] == CMD_DRIVE_INFO:
        out.update(decode_drive_info(cmd, endian))
    elif cmd[0] == CMD_FILE_DATA:
        d = decode_file_data(cmd, endian)
        d.pop("data")
        out.update(d)
    elif cmd[0] == CMD_DOWNLOAD_FINISHED and len(cmd) >= 5:
        out["session_id"] = struct.unpack(endian + "I", cmd[1:5])[0]
    elif cmd[0] == CMD_UPLOAD_ERROR:
        out.update(decode_upload_error(cmd, endian))
    elif cmd[0] == CMD_GET_DIRECTORY_INFO:
        out["path"] = decode_get_directory_info(cmd, endian)
    elif cmd[0] == CMD_MAKE_NEW_DIRECTORY:
        out.update(decode_make_new_directory(cmd, endian))
    elif cmd[0] == CMD_PACKAGE:
        subs = decode_multiple_file_package(cmd, endian)
        out["count"] = len(subs)
        out["commands"] = [describe_command(c, endian) for c in subs]
    elif cmd[0] in (CMD_DELETE_FILE, CMD_DELETE_DIRECTORY):
        out.update(decode_delete(cmd, endian))
    elif cmd[0] == CMD_RENAME_FILE:
        out.update(decode_rename(cmd, endian))
    elif cmd[0] == CMD_UPLOAD_CONFIRM:
        out.update(decode_upload_files(cmd, endian))
    elif cmd[0] in (CMD_UPLOAD_MULTI, CMD_UPLOAD_ZERO):
        out.update(decode_upload_multi(cmd, endian))
    elif cmd[0] == CMD_UPLOAD_FILE_DATA and len(cmd) >= FILE_DATA_HEADER:
        out.update(zip(("file_id", "total", "index", "data_length"),
                       struct.unpack(endian + "IIII", cmd[1:FILE_DATA_HEADER])))
    elif cmd[0] == CMD_DIRECTORY_INFO:
        d = decode_directory_info(cmd, endian)
        out.update({"entries": len(d["entries"]), "free_space": d.get("free_space")})
    elif cmd[0] == CMD_DOWNLOAD_MULTI:
        out.update(decode_download_request(cmd, endian))
    return out


def after_login_commands(clipboard=None, offer=None, download=None, endian="<", share=None,
                         image=None):
    """Commands to queue once the peer accepts our Login, as (command, why)."""
    out = []
    if share:
        drives = []
        for root in share:
            st = os.statvfs(root)
            drives.append((os.path.abspath(root), st.f_blocks * st.f_frsize,
                           st.f_bavail * st.f_frsize))
        out.append((encode_drive_list(drives), "drives"))
    if clipboard is not None:
        out.append((encode_clipboard_text(clipboard), "clipboard"))
    if offer:
        out.append((encode_clipboard_files([node_info_for_file(p) for p in offer]), "offer"))
    if image:
        out.append((encode_clipboard_image(os.path.abspath(image)), "image"))
    if download:
        out.append((encode_download_request(1, list(enumerate(download, start=1)), endian),
                    "download"))
    return out


# ------------------------------------------------------- remote browsing
# Wormhole.app's remote file browser.  A Linux (Android) peer reports its
# "drives" in an XmlPacket (THMFileManager upNotifyUpipeMessage:); the Mac
# then lists a folder with GetDirectoryInfo (0x04) and expects the answer
# THMGBServer handleGetDirectoryInfo: gives: ResponseResult, then DirectoryInfo
# (0xA2) with fixed 552-byte records (THMRemoteFileWrapper
# initFromRemoteListData:withOSVersion:), in the sender's byte order.

DIR_RECORD_LEN = 0x228
DIR_NAME_MAX = DIR_RECORD_LEN - 40   # name bytes after the ten u32 words
ATTR_HIDDEN, ATTR_DIRECTORY = 0x02, 0x10
REMOTE_OPERATION_ERROR = 3           # errorCode THMGBServer sends for an unreadable folder


def encode_drive_list(drives):
    """NP_Cmd_Post_Drive_Update_Info: (path, total bytes, free bytes) per drive."""
    from xml.sax.saxutils import escape
    lines = "".join(
        "<Line><NP_Misc_Drive_Letter>%s</NP_Misc_Drive_Letter>"
        "<NP_Misc_Drive_Total_Space_Number>%d</NP_Misc_Drive_Total_Space_Number>"
        "<NP_Misc_Drive_Free_Space_Number>%d</NP_Misc_Drive_Free_Space_Number></Line>"
        % (escape(path), total, free) for path, total, free in drives)
    return encode_xml_packet(
        "<ExtraXmlCommand>HookAppService</ExtraXmlCommand><ExtraXmlParam><OTIMSG>"
        "<NP_Cmd>NP_Cmd_Post_Drive_Update_Info</NP_Cmd><NP_Remote_Request_Info>"
        "<NP_Misc_Drive_ListMRS>%s</NP_Misc_Drive_ListMRS></NP_Remote_Request_Info>"
        "</OTIMSG></ExtraXmlParam>" % lines)


def encode_get_directory_info(path, endian=">"):
    raw = path.encode("utf-16-be" if endian == ">" else "utf-16-le")
    return bytes([CMD_GET_DIRECTORY_INFO]) + struct.pack(endian + "H", len(raw)) + raw


def decode_get_directory_info(cmd, endian=">"):
    """GetDirectoryInfo: 04 <path length u16> <path, UTF-16>; the Mac sends no NUL."""
    if len(cmd) < 3 or cmd[0] != CMD_GET_DIRECTORY_INFO:
        raise ValueError("not a GetDirectoryInfo")
    (n,) = struct.unpack(endian + "H", cmd[1:3])
    if 3 + n > len(cmd):
        raise ValueError("GetDirectoryInfo path truncated")
    return cmd[3:3 + n].decode("utf-16-be" if endian == ">" else "utf-16-le").rstrip("\0")


def encode_directory_record(name, attrs, size, ctime, atime, mtime, endian="<"):
    """One 552-byte DirectoryInfo record.  Times are 64-bit Unix seconds and
    the size 64-bit bytes, each as (low, high) u32 words from a non-Mac sender
    (the time order was checked live in Wormhole.app)."""
    raw = name.encode("utf-16-le" if endian == "<" else "utf-16-be")[:DIR_NAME_MAX]
    words = (attrs, ctime & 0xFFFFFFFF, ctime >> 32, atime & 0xFFFFFFFF, atime >> 32,
             mtime & 0xFFFFFFFF, mtime >> 32, size & 0xFFFFFFFF, size >> 32, len(raw))
    return (struct.pack(endian + "10I", *words) + raw).ljust(DIR_RECORD_LEN, b"\0")


def encode_directory_info(entries, free_space=None, endian="<"):
    """DirectoryInfo (0xA2): count u16, records, optional free space u64.
    entries: (name, attrs, size, ctime, atime, mtime).  The Mac reads the free
    space only when at least one more byte follows it, hence the pad byte."""
    entries = list(entries)[:0xFFFF]
    out = bytes([CMD_DIRECTORY_INFO]) + struct.pack(endian + "H", len(entries))
    out += b"".join(encode_directory_record(*e, endian=endian) for e in entries)
    if free_space is not None:
        out += struct.pack(endian + "Q", free_space) + b"\0"
    return out


def decode_directory_info(cmd, endian="<"):
    if len(cmd) < 3 or cmd[0] != CMD_DIRECTORY_INFO:
        raise ValueError("not a DirectoryInfo")
    (count,) = struct.unpack(endian + "H", cmd[1:3])
    off, entries = 3, []
    utf16 = "utf-16-le" if endian == "<" else "utf-16-be"
    for _ in range(count):
        rec = cmd[off:off + DIR_RECORD_LEN]
        if len(rec) != DIR_RECORD_LEN:
            raise ValueError("DirectoryInfo truncated")
        w = struct.unpack_from(endian + "10I", rec)
        entries.append({"name": rec[40:40 + min(w[9], DIR_NAME_MAX)].decode(utf16),
                        "attrs": w[0], "directory": bool(w[0] & ATTR_DIRECTORY),
                        "size": (w[8] << 32) | w[7], "ctime": (w[2] << 32) | w[1],
                        "atime": (w[4] << 32) | w[3], "mtime": (w[6] << 32) | w[5]})
        off += DIR_RECORD_LEN
    out = {"entries": entries}
    if len(cmd) > off + 8:              # as the Mac: only with something after it
        (out["free_space"],) = struct.unpack(endian + "Q", cmd[off:off + 8])
    return out


def list_directory(path):
    """(name, attrs, size, ctime, atime, mtime) for each entry; Linux has no
    portable creation time, so the last-write time stands in."""
    out = []
    with os.scandir(path) as it:
        for e in it:
            try:
                st = e.stat()
            except OSError:
                continue
            attrs = ATTR_DIRECTORY if e.is_dir() else 0
            if e.name.startswith("."):
                attrs |= ATTR_HIDDEN
            out.append((e.name, attrs, 0 if attrs & ATTR_DIRECTORY else st.st_size,
                        int(st.st_mtime), int(st.st_atime), int(st.st_mtime)))
    return sorted(out)


def shared_path(path, roots):
    """The real path if it lies inside one of roots (after symlinks), else None."""
    real = os.path.realpath(path)
    for root in roots:
        root = os.path.realpath(root)
        if real == root or real.startswith(root.rstrip("/") + "/"):
            return real
    return None


class FileResolver:
    """Which local file answers a peer's path: offered files by their exact
    path, and regular files inside a shared folder (symlinks resolved)."""

    def __init__(self, offered, roots):
        self.offered, self.roots = dict(offered), list(roots)

    def get(self, path):
        if path in self.offered:
            return self.offered[path]
        real = shared_path(path, self.roots)
        return real if real is not None and os.path.isfile(real) else None


def encode_make_new_directory(session_id, path, endian=">"):
    raw = (path + "\0").encode("utf-16-be" if endian == ">" else "utf-16-le")
    return (bytes([CMD_MAKE_NEW_DIRECTORY]) + struct.pack(endian + "IH", session_id, len(raw))
            + raw)


def decode_make_new_directory(cmd, endian=">"):
    """MakeNewDirectory: 07 <sessionID u32> <path length u16> <path, UTF-16 + NUL>."""
    if len(cmd) < 7 or cmd[0] != CMD_MAKE_NEW_DIRECTORY:
        raise ValueError("not a MakeNewDirectory")
    session_id, n = struct.unpack(endian + "IH", cmd[1:7])
    if 7 + n > len(cmd):
        raise ValueError("MakeNewDirectory path truncated")
    path = cmd[7:7 + n].decode("utf-16-be" if endian == ">" else "utf-16-le").rstrip("\0")
    return {"session_id": session_id, "path": path}


def serve_make_new_directory(cmd, roots, endian="<", request_endian=">"):
    """Create the folder if it lies inside a share; an existing one is fine.
    THMGBServer answers with a ResponseResult that carries no session ID."""
    path = decode_make_new_directory(cmd, request_endian)["path"]
    parent = shared_path(os.path.dirname(path.rstrip("/")) or "/", roots)
    target = shared_path(path, roots)
    try:
        if parent is None and target is None:
            raise OSError("not shared")
        os.makedirs(target or os.path.join(parent, os.path.basename(path.rstrip("/"))),
                    exist_ok=True)
    except OSError:
        return [encode_response(CMD_MAKE_NEW_DIRECTORY, 1, error_code=REMOTE_OPERATION_ERROR,
                                endian=endian)]
    return [encode_response(CMD_MAKE_NEW_DIRECTORY, 0, endian=endian)]


def _decode_upload_paths(cmd, off, count, endian):
    """{ <fileID u32> <pathLen u16> <path, UTF-16 + NUL> } * count."""
    utf16 = "utf-16-be" if endian == ">" else "utf-16-le"
    files = []
    for _ in range(count):
        if off + 6 > len(cmd):
            raise ValueError("upload file list truncated")
        file_id, n = struct.unpack(endian + "IH", cmd[off:off + 6])
        off += 6
        if off + n > len(cmd):
            raise ValueError("upload file path truncated")
        files.append({"file_id": file_id, "path": cmd[off:off + n].decode(utf16).rstrip("\0")})
        off += n
    return files


def _utf16(endian):
    return "utf-16-be" if endian == ">" else "utf-16-le"


def encode_delete(command, session_id, path, endian=">"):
    raw = (path + "\0").encode(_utf16(endian))
    return bytes([command]) + struct.pack(endian + "IH", session_id, len(raw)) + raw


def decode_delete(cmd, endian=">"):
    """DeleteFile (0x08) / DeleteDirectory (0x06):
    <sessionFileID u32> <pathLen u16> <path, UTF-16>."""
    if len(cmd) < 7 or cmd[0] not in (CMD_DELETE_FILE, CMD_DELETE_DIRECTORY):
        raise ValueError("not a DeleteFile/DeleteDirectory")
    session_id, n = struct.unpack(endian + "IH", cmd[1:7])
    if 7 + n > len(cmd):
        raise ValueError("delete path truncated")
    return {"session_id": session_id,
            "path": cmd[7:7 + n].decode(_utf16(endian)).rstrip("\0")}


def encode_rename(session_id, path, new_path, endian=">"):
    old, new = ((p + "\0").encode(_utf16(endian)) for p in (path, new_path))
    return (bytes([CMD_RENAME_FILE]) + struct.pack(endian + "IHH", session_id, len(old), len(new))
            + old + new)


def decode_rename(cmd, endian=">"):
    """RenameFile (0x09): <sessionFileID u32> <originalLen u16> <newLen u16>
    <original path> <new path>, both UTF-16."""
    if len(cmd) < 9 or cmd[0] != CMD_RENAME_FILE:
        raise ValueError("not a RenameFile")
    session_id, n_old, n_new = struct.unpack(endian + "IHH", cmd[1:9])
    if 9 + n_old + n_new > len(cmd):
        raise ValueError("rename paths truncated")
    old = cmd[9:9 + n_old].decode(_utf16(endian)).rstrip("\0")
    new = cmd[9 + n_old:9 + n_old + n_new].decode(_utf16(endian)).rstrip("\0")
    return {"session_id": session_id, "path": old, "new_path": new}


def default_trash_dir():
    """The freedesktop.org home trash, where file managers look for it."""
    data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(data, "Trash")


def move_to_trash(path, trash):
    """Move path into trash/files with a trash/info/<name>.trashinfo record
    (freedesktop.org Trash spec), as the Mac's server moves items to its Trash."""
    from urllib.parse import quote
    files, info = os.path.join(trash, "files"), os.path.join(trash, "info")
    os.makedirs(files, exist_ok=True)
    os.makedirs(info, exist_ok=True)
    base = os.path.basename(path.rstrip("/"))
    stem, ext = os.path.splitext(base)
    name, n = base, 1
    while True:
        try:        # O_EXCL claims the name, so two deletes cannot pick the same one
            fd = os.open(os.path.join(info, name + ".trashinfo"),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            n += 1
            name = "%s.%d%s" % (stem, n, ext)
    with os.fdopen(fd, "w") as f:
        f.write("[Trash Info]\nPath=%s\nDeletionDate=%s\n"
                % (quote(path), time.strftime("%Y-%m-%dT%H:%M:%S")))
    try:
        shutil.move(path, os.path.join(files, name))
    except OSError:
        os.unlink(os.path.join(info, name + ".trashinfo"))
        raise


def _entry_in_share(path, roots):
    """The entry path names (its folder resolved, the entry itself not, so a
    symlink is acted on, not its target) if it lies inside a share and is not
    a share itself; else None."""
    parent = shared_path(os.path.dirname(path.rstrip("/")) or "/", roots)
    if parent is None:
        return None
    entry = os.path.join(parent, os.path.basename(path.rstrip("/")))
    if not os.path.islink(entry) and any(os.path.realpath(entry) == os.path.realpath(r)
                                         for r in roots):
        return None
    return entry


def serve_delete(cmd, roots, trash, endian="<", request_endian=">"):
    """Move to Trash from the remote browser.  THMGBServer answers result 0
    on success, 1 otherwise, with no error code."""
    target = _entry_in_share(decode_delete(cmd, request_endian)["path"], roots)
    try:
        if target is None or not os.path.lexists(target):
            raise OSError("not shared")
        move_to_trash(target, trash)
    except OSError:
        return [encode_response(cmd[0], 1, endian=endian)]
    return [encode_response(cmd[0], 0, endian=endian)]


def serve_rename(cmd, roots, endian="<", request_endian=">"):
    """Rename within the shares; never onto an existing name."""
    req = decode_rename(cmd, request_endian)
    old, new = (_entry_in_share(req[k], roots) for k in ("path", "new_path"))
    try:
        if old is None or new is None or not os.path.lexists(old) or os.path.lexists(new):
            raise OSError("cannot rename")
        os.rename(old, new)
    except OSError:
        return [encode_response(CMD_RENAME_FILE, 1, error_code=REMOTE_OPERATION_ERROR,
                                endian=endian)]
    return [encode_response(CMD_RENAME_FILE, 0, endian=endian)]


def decode_upload_files(cmd, endian=">"):
    """UploadMultipleFileConfirm (0x13): <multiSessionID u32> <allFileSize u64>
    <largeFilesCount u16> <count u16> then the destination paths."""
    if len(cmd) < 17 or cmd[0] != CMD_UPLOAD_CONFIRM:
        raise ValueError("not an UploadMultipleFileConfirm")
    multi, total, large, count = struct.unpack(endian + "IQHH", cmd[1:17])
    return {"multi_session_id": multi, "total_size": total, "large_files": large,
            "files": _decode_upload_paths(cmd, 17, count, endian)}


def decode_upload_multi(cmd, endian=">"):
    """UploadMultipleFile (0x12) and UploadMultipleFileZeroLength (0x15, the
    empty files of a paste): <multiSessionID u32> <count u16> then the
    destination paths -- no size or large-file count, unlike 0x13."""
    if len(cmd) < 7 or cmd[0] not in (CMD_UPLOAD_MULTI, CMD_UPLOAD_ZERO):
        raise ValueError("not an UploadMultipleFile")
    multi, count = struct.unpack(endian + "IH", cmd[1:7])
    return {"multi_session_id": multi, "files": _decode_upload_paths(cmd, 7, count, endian)}


def encode_upload_confirmation(session_id, existing_ids, free_space_ok=True,
                               dest_read_only=False, endian="<"):
    """UploadMultiFileConfirmation (0xA8): readOnly, freeSpace, fileSystem and
    destRootPathReadOnly flags, sessionID, then the IDs of files that already
    exist.  The Mac stops the upload when freeSpace is 0 or destRootPathReadOnly 1."""
    return (bytes([CMD_UPLOAD_CONFIRMATION, 0, 1 if free_space_ok else 0, 0,
                   1 if dest_read_only else 0])
            + struct.pack(endian + "II", session_id, len(existing_ids))
            + b"".join(struct.pack(endian + "I", i) for i in existing_ids))


REMOTE_OPERATION_ERROR_TEXT = "Remote operation error"


class UploadReceiver:
    """Server side of an upload into a shared folder (THMGBServer's handlers):
    0x13 -> 0xA8; 0x12 registers the files (answered only on error); 0x15
    creates the empty ones (answered only on error); 0x0C
    pieces are written in order; when every file of a session is complete,
    DownloadMultiFileFinished (0xA7) carries the session ID; 0x14 aborts."""

    def __init__(self, roots, endian="<", request_endian=">"):
        self.roots, self.endian, self.req = list(roots), endian, request_endian
        self.files = {}                 # fileID -> {"path", "multi", "fh"}
        self.pending = {}               # multiSessionID -> set of fileIDs

    def _error(self, session_id, file_id):
        return [encode_upload_error(session_id, REMOTE_OPERATION_ERROR, file_id,
                                    REMOTE_OPERATION_ERROR_TEXT, self.endian)]

    def _drop(self, multi):
        for fid in self.pending.pop(multi, set()):
            fh = self.files.pop(fid, {}).get("fh")
            if fh:
                fh.close()

    def handle(self, cmd):
        if not cmd:
            return []
        if cmd[0] == CMD_UPLOAD_CONFIRM:
            req = decode_upload_files(cmd, self.req)
            reals = [shared_path(f["path"], self.roots) for f in req["files"]]
            outside = any(r is None for r in reals)
            existing = [f["file_id"] for f, r in zip(req["files"], reals)
                        if r is not None and os.path.exists(r)]
            free_ok = False
            if not outside and reals:
                d = os.path.dirname(reals[0])
                while not os.path.isdir(d):
                    d = os.path.dirname(d)
                st = os.statvfs(d)
                free_ok = st.f_bavail * st.f_frsize >= req["total_size"]
            return [encode_upload_confirmation(req["multi_session_id"], existing, free_ok,
                                               outside, self.endian)]
        if cmd[0] == CMD_UPLOAD_MULTI:
            req = decode_upload_multi(cmd, self.req)
            reals = [shared_path(f["path"], self.roots) for f in req["files"]]
            if any(r is None for r in reals):
                return [encode_response(CMD_UPLOAD_MULTI, 1, error_code=REMOTE_OPERATION_ERROR,
                                        endian=self.endian)]
            multi = req["multi_session_id"]
            self.pending[multi] = {f["file_id"] for f in req["files"]}
            for f, real in zip(req["files"], reals):
                self.files[f["file_id"]] = {"path": real, "multi": multi, "fh": None}
            return []
        if cmd[0] == CMD_UPLOAD_ZERO:
            # THMGBServer createZeroLengthFiles:withErrorFileID: -- no reply on
            # success, UploadMultiFileError (code 3) naming the failed file.
            req = decode_upload_multi(cmd, self.req)
            for f in req["files"]:
                real = shared_path(f["path"], self.roots)
                try:
                    if real is None:
                        raise OSError("not shared")
                    os.makedirs(os.path.dirname(real), exist_ok=True)
                    open(real, "wb").close()
                except OSError:
                    return self._error(req["multi_session_id"], f["file_id"])
            return []
        if cmd[0] == CMD_UPLOAD_FILE_DATA:
            if len(cmd) < FILE_DATA_HEADER:
                raise ValueError("UploadFileData truncated")
            fid, total, index, length = struct.unpack(self.req + "IIII", cmd[1:FILE_DATA_HEADER])
            entry = self.files.get(fid)
            if entry is None:
                return self._error(fid, fid)
            multi = entry["multi"]
            try:
                if entry["fh"] is None:
                    os.makedirs(os.path.dirname(entry["path"]), exist_ok=True)
                    entry["fh"] = open(entry["path"], "wb")
                entry["fh"].write(cmd[FILE_DATA_HEADER:FILE_DATA_HEADER + length])
                if index < total:
                    return []
                entry["fh"].close()
            except OSError:
                self._drop(multi)
                return self._error(multi, fid)
            del self.files[fid]
            self.pending[multi].discard(fid)
            if self.pending[multi]:
                return []
            del self.pending[multi]
            return [encode_download_finished(multi, self.endian)]
        if cmd[0] == CMD_UPLOAD_ABORT and len(cmd) >= 5:
            self._drop(struct.unpack(self.req + "I", cmd[1:5])[0])
            return []
        return []


def server_replies(cmd, roots, resolver, uploads=None, trash=None):
    """Replies, as (command, why), to a request the peer sent our server side.
    Only shared folders are browsed or changed, only resolvable files served.
    A request we cannot parse gets ResponseResult(cmd, 1) instead of an exception."""
    if not cmd:
        return []
    try:
        return _server_replies(cmd, roots, resolver, uploads, trash)
    except ValueError:
        return [(encode_response(cmd[0], 1, error_code=REMOTE_OPERATION_ERROR, endian="<"),
                 "error")]


def _server_replies(cmd, roots, resolver, uploads, trash):
    if roots and cmd[0] in (CMD_DELETE_FILE, CMD_DELETE_DIRECTORY):
        return [(r, "delete") for r in serve_delete(cmd, roots, trash or default_trash_dir())]
    if roots and cmd[0] == CMD_RENAME_FILE:
        return [(r, "rename") for r in serve_rename(cmd, roots)]
    if roots and cmd[0] == CMD_GET_DIRECTORY_INFO:
        return [(r, "browse") for r in serve_get_directory_info(cmd, roots)]
    if roots and cmd[0] == CMD_MAKE_NEW_DIRECTORY:
        return [(r, "mkdir") for r in serve_make_new_directory(cmd, roots)]
    if roots and uploads is not None and cmd[0] in (
            CMD_UPLOAD_CONFIRM, CMD_UPLOAD_MULTI, CMD_UPLOAD_FILE_DATA, CMD_UPLOAD_ABORT,
            CMD_UPLOAD_ZERO):
        return [(r, "upload") for r in uploads.handle(cmd)]
    if cmd[0] == CMD_DOWNLOAD_MULTI and (resolver.offered or resolver.roots):
        return [(r, "serve") for r in serve_download(cmd, resolver)]
    return []


def serve_get_directory_info(cmd, roots, endian="<", request_endian=">"):
    """Answer GetDirectoryInfo for folders inside roots, as THMGBServer does."""
    path = decode_get_directory_info(cmd, request_endian)
    real = shared_path(path, roots)
    try:
        if real is None:
            raise OSError("not shared")
        entries = list_directory(real)
        free = os.statvfs(real)
    except OSError:
        return [encode_response(CMD_GET_DIRECTORY_INFO, 1, error_code=REMOTE_OPERATION_ERROR,
                                endian=endian)]
    return [encode_response(CMD_GET_DIRECTORY_INFO, 0, endian=endian),
            encode_directory_info(entries, free.f_bavail * free.f_frsize, endian)]


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
    ap.add_argument("--clipboard-image", metavar="TIFF",
                    help="with --login: put this TIFF image on the peer's clipboard "
                         "(Apple TIFF Format) and serve it when the peer fetches it")
    ap.add_argument("--save-clipboard-images", action="store_true",
                    help="with --login: fetch every image the peer copies to its "
                         "clipboard; saved as clipboard_<n>.tiff in --out")
    ap.add_argument("--offer", metavar="LOCAL_PATH", action="append",
                    help="with --login: put this local file on the peer's clipboard "
                         "(CB_Format_File, repeatable) and serve it when the peer pastes "
                         "it; only offered files are served; exits once a request is "
                         "answered")
    ap.add_argument("--share", metavar="LOCAL_DIR", action="append",
                    help="with --login: show this folder as a drive in Wormhole.app's remote "
                         "browser: list, copy from, upload into, rename, create folders; "
                         "Move to Trash goes to the freedesktop.org Trash (repeatable); "
                         "runs for --seconds")
    ap.add_argument("--download", metavar="PEER_PATH", action="append",
                    help="with --login: ask the peer to send this file (repeatable); "
                         "saved as download_<n>.bin in --out; exits when the peer "
                         "reports the request finished or failed")
    ap.add_argument("--endian", choices=["big", "little"], default="little",
                    help="byte order for --download fields (default little: the Mac decodes "
                         "a Linux peer little-endian; big crashed its daemon)")
    args = ap.parse_args(argv)
    if (args.clipboard is not None or args.download or args.offer or args.share
            or args.clipboard_image or args.save_clipboard_images) and not args.login:
        ap.error("--clipboard, --clipboard-image, --save-clipboard-images, --offer, --share "
                 "and --download need --login")
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
    after_login_sent = False
    relogin = False                     # set by a Logout from the peer
    endian = ">" if args.endian == "big" else "<"
    started = set()                     # file IDs whose download file we have opened
    images = ClipboardImageFetcher()
    # Paths as the peer will ask for them -> local files; only these are served.
    offered = {os.path.abspath(p): os.path.abspath(p)
               for p in (args.offer or []) + ([args.clipboard_image] if args.clipboard_image else [])}
    shares = [os.path.abspath(d) for d in args.share or []]
    resolver = FileResolver(offered, shares)
    uploads = UploadReceiver(shares)
    served = False                      # answered a DownloadMultipleFile with 0xA7/0xA9
    download_done = False               # 0xA7 or 0xA9 received: stop once txq drains
    end = time.time() + args.seconds
    last_state, n_rx, n_tx = None, 0, 0
    emit({"event": "start", "dev": args.dev, "fetch_cdb": fetch.hex(), "send_cdb": send.hex(),
          "login": args.login, "os": os_byte if args.login else None})

    def queue(cmd, why, cmd_endian=">"):
        pkts = framer.frame(cmd)
        txq.extend(pkts)
        emit({"event": "queue", "why": why, "packets": len(pkts),
              **describe_command(cmd, cmd_endian),
              "cmd_hex": cmd[:4096].hex()})
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
                    # The peer logged out (e.g. Wormhole.app restarted): log in
                    # again when its restarted daemon logs in (a Login sent
                    # straight after the Logout reaches no one), so the
                    # after-login commands (drive list) go out anew.
                    if args.login and cmd[:1] == bytes([CMD_LOGOUT]):
                        after_login_sent = False
                        relogin = True
                    elif relogin and cmd[:1] == bytes([CMD_LOGIN]):
                        relogin = False
                        queue(encode_login(args.login, os_byte), "relogin")
                    if args.login and cmd[:1] == bytes([CMD_LOGIN]):
                        queue(encode_response(CMD_LOGIN, 0, os_byte), "login-response")
                    # The peer's ResponseResult to our Login = we are logged in.
                    if cmd[:2] == bytes([CMD_RESPONSE, CMD_LOGIN]) and not after_login_sent:
                        after_login_sent = True
                        for c, why in after_login_commands(args.clipboard, args.offer,
                                                           args.download, endian, shares,
                                                           args.clipboard_image):
                            queue(c, why)
                    if args.save_clipboard_images and desc.get("image_file"):
                        queue(images.request(desc["image_file"]), "fetch-image")
                    if cmd[:1] == bytes([CMD_FILE_DATA]) and "decode_error" not in desc:
                        piece = decode_file_data(cmd)
                        path = os.path.join(args.out, images.filename(piece["file_id"])
                                            or "download_%d.bin" % piece["file_id"])
                        # currentIndex starts at 1; truncate on the first piece seen.
                        with open(path, "ab" if piece["file_id"] in started else "wb") as f:
                            f.write(piece["data"])
                        started.add(piece["file_id"])
                    for reply, why in server_replies(cmd, shares, resolver, uploads):
                        queue(reply, why, "<")
                        if why == "serve":
                            served = True
                    if args.download and cmd[:1] in (bytes([CMD_DOWNLOAD_FINISHED]),
                                                     bytes([CMD_UPLOAD_ERROR])):
                        download_done = True
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
            # Stop once the request we were waiting for is answered and sent.
            if not txq and not shares and (served if offered else download_done):
                break
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
