import ctypes
import hashlib
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import upipe_peer as u  # noqa: E402

# A 28-character stand-in for the Mac's host name (same length as the capture).
NAME28 = "example-host-name-mac0.local"


class TestCdbs(unittest.TestCase):
    def test_poll_matches_observed_mac_cdb(self):
        # GoBridgeDemon dtrace, 2026-11-11: d8 00 03 00 02 <stack garbage> .. 4f 54
        cdb = u.build_poll_cdb(2)
        self.assertEqual(len(cdb), 16)
        self.assertEqual(cdb[:5].hex(), "d800030002")
        self.assertEqual(cdb[-2:], b"OT")

    def test_poll_idle(self):
        self.assertEqual(u.build_poll_cdb().hex(), "d8000300000000000000000000004f54")

    def test_poll_range(self):
        with self.assertRaises(ValueError):
            u.build_poll_cdb(0x10000)

    def test_fetch(self):
        self.assertEqual(u.build_fetch_cdb().hex(), "d9286400000000000000000000004f54")

    def test_send(self):
        cdb = u.build_send_cdb()
        self.assertEqual(len(cdb), 16)
        self.assertEqual(cdb[:3].hex(), "d92aff")
        self.assertEqual(cdb[-2:], b"OT")


class TestStatus(unittest.TestCase):
    def test_data_waiting(self):
        st = u.parse_status(bytes.fromhex("05000200000000ffffffffffffffffff"))
        self.assertEqual(st["name"], "data-waiting")
        self.assertEqual(st["waiting"], 2)

    def test_app_online(self):
        st = u.parse_status(bytes.fromhex("07000000000000ffffffffffffffffff"))
        self.assertEqual(st["name"], "remote-app-online")
        self.assertNotIn("waiting", st)

    def test_app_offline(self):
        self.assertEqual(u.parse_status(bytes([1] + [0] * 15))["name"],
                         "remote-device-online-app-offline")

    def test_unknown(self):
        self.assertEqual(u.parse_status(bytes([0x42] + [0] * 15))["name"], "unknown")

    def test_short(self):
        with self.assertRaises(ValueError):
            u.parse_status(b"\x05")

    def test_tx_allowance(self):
        self.assertEqual(u.tx_allowance(7, 3), 3)
        self.assertEqual(u.tx_allowance(6, 3), 1)
        self.assertEqual(u.tx_allowance(6, 0), 0)
        self.assertEqual(u.tx_allowance(5, 3), 0)
        self.assertEqual(u.tx_allowance(1, 3), 0)


class TestPacket(unittest.TestCase):
    def test_tail_ok(self):
        head = bytes(range(20))
        pkt = head + bytes(u.PACKET_LEN - 40) + head
        self.assertTrue(u.packet_tail_ok(pkt))

    def test_tail_mismatch(self):
        pkt = bytes(range(20)) + bytes(u.PACKET_LEN - 20)
        self.assertFalse(u.packet_tail_ok(pkt))

    def test_wrong_length(self):
        self.assertFalse(u.packet_tail_ok(bytes(100)))

    def test_wrap(self):
        pkt = u.wrap_packet(bytes(range(1, 30)))
        self.assertEqual(len(pkt), u.PACKET_LEN)
        self.assertTrue(u.packet_tail_ok(pkt))

    def test_wrap_too_long(self):
        with self.assertRaises(ValueError):
            u.wrap_packet(bytes(u.BODY_LEN + 1))


class TestFraming(unittest.TestCase):
    def test_mac_login_layout(self):
        # Second login attempt in the 2026-11-11 capture: seq 2, session 2.
        cmd = u.encode_login(NAME28, 0x16)
        pkts = u.Framer(seq=1, session=2).frame(cmd)
        self.assertEqual(len(pkts), 2)
        self.assertEqual(pkts[0][:25].hex(),
                         "0200000002000000000000000100000021000000" "011600001c")
        self.assertEqual(pkts[0][25:53], NAME28.encode())
        self.assertTrue(u.packet_tail_ok(pkts[0]))
        self.assertEqual(pkts[1], bytes(u.PACKET_LEN))  # terminator

    def test_counters(self):
        f = u.Framer()
        a = u.parse_chunk(f.frame(b"\x02")[0])
        b = u.parse_chunk(f.frame(b"\x02")[0])
        self.assertEqual((a["seq"], a["session"]), (1, 1))
        self.assertEqual((b["seq"], b["session"]), (2, 2))

    def test_multichunk_roundtrip(self):
        cmd = bytes([0x39]) + bytes(range(256)) * 600  # > one chunk
        pkts = u.Framer().frame(cmd)
        self.assertEqual(len(pkts), 4)  # 3 data chunks + terminator
        r = u.Reassembler()
        got = [r.add(u.parse_chunk(p)) for p in pkts]
        self.assertEqual(got[:2], [None, None])
        self.assertEqual(got[2], cmd)
        self.assertIsNone(got[3])

    def test_chunk_length_guard(self):
        bad = u.wrap_packet(u.HEADER.pack(1, 1, 0, 1, u.CHUNK_DATA + 1))
        with self.assertRaises(ValueError):
            u.parse_chunk(bad)


class TestCommands(unittest.TestCase):
    def test_login_roundtrip(self):
        d = u.decode_login(u.encode_login("linux-peer"))
        self.assertEqual(d["name"], "linux-peer")
        self.assertEqual(d["os_type"], "linux")
        self.assertEqual(d["code_page"], 0)

    def test_mac_os_byte(self):
        d = u.decode_login(u.encode_login(NAME28, 0x16))
        self.assertEqual((d["os_type"], d["os_version"]), ("mac", 6))

    def test_response_layout(self):
        r = u.encode_response(u.CMD_LOGIN, 0, u.OS_LINUX)
        # 3 + 4*4 + flag + extraLen + 10 extra + 6 tag + 4 errorString length
        self.assertEqual(len(r), 44)
        self.assertEqual(r[:3].hex(), "a10100")
        self.assertEqual(r[19], 3)             # extraInfoFlag
        self.assertEqual(r[20:24], bytes(4))   # extraInfoLength left at 0
        self.assertEqual(r[24:34], b"OSVERSION\x20")
        d = u.decode_response(r)
        self.assertEqual((d["request_command"], d["result"], d["os"]), (1, 0, 0x20))

    def test_describe(self):
        self.assertEqual(u.describe_command(u.encode_login("x"))["command_name"], "Login")
        self.assertEqual(u.describe_command(bytes([0x77]))["command_name"], "unknown")


class TestClipboard(unittest.TestCase):
    # Text the Mac pushed in the 2026-11-11 xfer capture (587-byte command).
    MAC_TEXT = "Test Test Test.\nThis is a test.\nCopying some test text."
    MAC_SHA256 = "1e2db0d59c6ddc615fd33f3ac603bbd82cba0920aafe11ad6802fd301e7a5186"

    def test_matches_mac_capture(self):
        cmd = u.encode_clipboard_text(self.MAC_TEXT)
        self.assertEqual(len(cmd), 587)
        self.assertEqual(cmd[:5].hex(), "3900000246")
        self.assertEqual(hashlib.sha256(cmd).hexdigest(), self.MAC_SHA256)

    def test_text_roundtrip(self):
        text = "héllo ✓ from linux\n"
        d = u.describe_command(u.encode_clipboard_text(text))
        self.assertEqual(d["command_name"], "XmlPacket")
        self.assertEqual((d["np_cmd"], d["cb_format"], d["text"]),
                         ("Cmd_Transfer_Clipboard", "CB_Format_Text", text))

    def test_content_is_uppercase_utf16_hex(self):
        xml = u.decode_xml_packet(u.encode_clipboard_text("A"))
        self.assertIn("<CP_Content>41000000</CP_Content>", xml)
        self.assertIn(r"\\.\pipe\OTI_ClipboardAgent", xml)

    def test_file_entries_counted(self):
        xml = u.CLIPBOARD_XML.format(body="<NodeInfoList><Line><NodeInfo>00</NodeInfo></Line>"
                                     "</NodeInfoList><CB_Format_Type>CB_Format_File</CB_Format_Type>")
        d = u.decode_clipboard(xml)
        self.assertEqual((d["cb_format"], d["files"]), ("CB_Format_File", 1))
        self.assertNotIn("text", d)

    def test_bad_length(self):
        with self.assertRaises(ValueError):
            u.decode_xml_packet(b"\x39\x00\x00\x00\x09abc")


class TestNodeInfo(unittest.TestCase):
    """CB_Format_File NodeInfo: 824-byte little-endian record (xfer capture)."""

    # FILETIMEs and size from the Mac's Finder copy of a .jpg (2026-11-11).
    CTIME, ATIME, MTIME, SIZE = (131202562990000000, 131609002270000000,
                                 131202562990000000, 91713)
    PATH = "/\\Users\\user\\Desktop\\photo.jpg"

    def _node(self, **kw):
        args = dict(path=self.PATH, size=self.SIZE, ctime=self.CTIME,
                    atime=self.ATIME, mtime=self.MTIME)
        args.update(kw)
        return u.encode_node_info(**args)

    def test_layout_matches_mac_record(self):
        rec = self._node()
        self.assertEqual(len(rec), 824)
        self.assertEqual(rec[:260], self.PATH.encode() + bytes(260 - len(self.PATH)))
        self.assertEqual(rec[260:780].decode("utf-16le").rstrip("\0"), self.PATH)
        # Bytes 780-823 exactly as in the Mac's record.
        self.assertEqual(rec[780:].hex(),
                         "80c7a3300920d201" "80038cb5b091d301" "80c7a3300920d201"
                         "00000000" "41660100" + "00" * 12)

    def test_large_size_uses_high_word(self):
        rec = self._node(size=(5 << 32) + 7)
        self.assertEqual(struct.unpack_from("<II", rec, 804), (5, 7))

    def test_roundtrip(self):
        d = u.decode_node_info(self._node())
        self.assertEqual(d, {"path": self.PATH, "size": self.SIZE, "ctime": self.CTIME,
                             "atime": self.ATIME, "mtime": self.MTIME})

    def test_path_too_long(self):
        with self.assertRaises(ValueError):
            self._node(path="/" + "a" * 260)

    def test_decode_wrong_length(self):
        with self.assertRaises(ValueError):
            u.decode_node_info(bytes(823))

    def test_filetime_from_unix(self):
        self.assertEqual(u.filetime_from_unix(0), 116444736000000000)
        self.assertEqual(u.filetime_from_unix(1475782699), self.CTIME)


    def test_clipboard_files_packet_matches_mac_size(self):
        # Same template as the Mac's: one NodeInfo -> a 2049-byte command.
        cmd = u.encode_clipboard_files([self._node()])
        self.assertEqual(len(cmd), 2049)
        d = u.describe_command(cmd)
        self.assertEqual((d["np_cmd"], d["cb_format"], d["files"]),
                         ("Cmd_Transfer_Clipboard", "CB_Format_File", 1))
        self.assertEqual(d["nodes"][0]["path"], self.PATH)
        self.assertEqual(d["nodes"][0]["size"], self.SIZE)

    def test_clipboard_two_files_one_line_each(self):
        cmd = u.encode_clipboard_files([self._node(), self._node(path="/\\b")])
        xml = u.decode_xml_packet(cmd)
        self.assertEqual(xml.count("<Line><NodeInfo>"), 2)
        self.assertEqual([n["path"] for n in u.decode_clipboard(xml)["nodes"]],
                         [self.PATH, "/\\b"])

    def test_offer_file_reads_local_metadata(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "f.bin")
            with open(path, "wb") as f:
                f.write(b"x" * 1234)
            os.utime(path, (1475782699, 1475782699))
            d = u.decode_node_info(u.node_info_for_file(path))
        # Plain POSIX path: the Mac names the pasted file after the part
        # behind the last '/', so the Mac's own /\Users\x form would make
        # the whole path the file name (offer run, 2026-11-11).
        self.assertEqual(d["path"], path)
        self.assertEqual((d["size"], d["mtime"], d["atime"]), (1234, self.CTIME, self.CTIME))


class TestDescribeEndian(unittest.TestCase):
    """Our replies to the Mac are little-endian; the log must decode them so."""

    def test_file_data_little_endian(self):
        d = u.describe_command(u.encode_file_data(103, 3, 2, b"ab", "<"), "<")
        self.assertEqual((d["file_id"], d["total"], d["index"], d["data_length"]),
                         (103, 3, 2, 2))

    def test_response_and_finished_little_endian(self):
        d = u.describe_command(u.encode_response(0x10, session_id=103, endian="<"), "<")
        self.assertEqual((d["request_command"], d["session_id"]), (0x10, 103))
        self.assertEqual(u.describe_command(u.encode_download_finished(103, "<"), "<")
                         ["session_id"], 103)

    def test_upload_error_little_endian(self):
        d = u.describe_command(u.encode_upload_error(7, 6, 7, "Read file data error", "<"), "<")
        self.assertEqual((d["session_id"], d["error_code"], d["error"]),
                         (7, 6, "Read file data error"))

    def test_default_stays_big_endian(self):
        d = u.describe_command(u.encode_download_finished(103, ">"))
        self.assertEqual(d["session_id"], 103)


class TestAfterLogin(unittest.TestCase):
    """What the peer queues once the Mac accepts our Login."""

    def test_nothing_by_default(self):
        self.assertEqual(u.after_login_commands(), [])

    def test_order_clipboard_offer_download(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "f.bin")
            open(path, "wb").close()
            cmds = u.after_login_commands(clipboard="hi", offer=[path],
                                          download=["/Users/x/a"])
        self.assertEqual([why for _cmd, why in cmds], ["clipboard", "offer", "download"])
        offer = u.describe_command(cmds[1][0])
        self.assertEqual(offer["cb_format"], "CB_Format_File")
        self.assertEqual(offer["nodes"][0]["path"], path)
        self.assertEqual(cmds[2][0], u.encode_download_request(1, [(1, "/Users/x/a")]))


def mac_download_request(multi, files):
    """A 0x10 request as the Mac sends it to a Linux peer (offer run,
    2026-11-11): big-endian, UTF-16BE path with a NUL, no destination."""
    out = bytes([0x10]) + struct.pack(">IH", multi, len(files))
    for fid, path in files:
        raw = (path + "\0").encode("utf-16-be")
        out += struct.pack(">IH", fid, len(raw)) + raw
    return out


class TestServeDownload(unittest.TestCase):
    """Linux as the server for the Mac's DownloadMultipleFile (0x10)."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "f.bin")
        self.data = bytes(range(256)) * 40          # 10 240 bytes
        with open(self.path, "wb") as f:
            f.write(self.data)
        self.offered = {self.path: self.path}

    def tearDown(self):
        self.tmp.cleanup()

    def test_decode_mac_request(self):
        req = u.decode_download_request(
            mac_download_request(101, [(101, self.path)]), ">")
        self.assertEqual(req, {"multi_session_id": 101,
                               "files": [{"file_id": 101, "path": self.path}]})

    def test_decode_little_endian_request_roundtrip(self):
        cmd = u.encode_download_request(7, [(1, "/a"), (2, "/b")])
        req = u.decode_download_request(cmd, "<")
        self.assertEqual([(f["file_id"], f["path"]) for f in req["files"]],
                         [(1, "/a"), (2, "/b")])

    def test_decode_truncated(self):
        with self.assertRaises(ValueError):
            u.decode_download_request(mac_download_request(1, [(1, "/a")])[:-3], ">")

    def test_describe_decodes_request(self):
        d = u.describe_command(mac_download_request(101, [(101, "/\\x")]))
        self.assertEqual((d["multi_session_id"], d["files"][0]["path"]), (101, "/\\x"))

    def test_reply_encoders_roundtrip_big_endian(self):
        piece = u.encode_file_data(3, 2, 1, b"abc", ">")
        self.assertEqual(u.decode_file_data(piece)["data"], b"abc")
        self.assertEqual(u.encode_download_finished(9, ">"), bytes.fromhex("a700000009"))
        err = u.encode_upload_error(1, 6, 1, "Read file data error", ">")
        self.assertEqual(u.decode_upload_error(err)["error"], "Read file data error")
        self.assertEqual(len(err), 65)               # the Mac's 0xa9 was 65 bytes

    def test_reply_encoders_little_endian(self):
        self.assertEqual(u.encode_file_data(3, 2, 1, b"abc", "<")[:17].hex(),
                         "a3" "03000000" "02000000" "01000000" "03000000")
        self.assertEqual(u.encode_download_finished(9, "<"), bytes.fromhex("a709000000"))
        resp = u.encode_response(0x10, session_id=101, endian="<")
        self.assertEqual(resp[3:7], struct.pack("<I", 101))
        self.assertEqual(len(resp), 34)              # as the Mac's 0x10 reply

    def test_serve_one_file_in_pieces(self):
        req = mac_download_request(101, [(101, self.path)])
        cmds = u.serve_download(req, self.offered, piece=4096)
        self.assertEqual([c[0] for c in cmds], [0xA1, 0xA3, 0xA3, 0xA3, 0xA7])
        self.assertEqual(cmds[0][1:3], bytes([0x10, 0]))
        self.assertEqual(cmds[0][3:7], struct.pack("<I", 101))
        pieces = [struct.unpack("<IIII", c[1:17]) for c in cmds[1:4]]
        self.assertEqual([p[:3] for p in pieces], [(101, 3, 1), (101, 3, 2), (101, 3, 3)])
        self.assertEqual(b"".join(c[17:] for c in cmds[1:4]), self.data)
        self.assertEqual(cmds[-1], u.encode_download_finished(101, "<"))

    def test_serve_default_piece_is_8_mib(self):
        self.assertEqual(u.MAX_FILE_PIECE, 0x800000)

    def test_serve_refuses_unoffered_path(self):
        other = os.path.join(self.tmp.name, "secret")
        req = mac_download_request(5, [(5, other)])
        cmds = u.serve_download(req, self.offered)
        self.assertEqual([c[0] for c in cmds], [0xA1, 0xA9])
        err = u.decode_upload_error(u.encode_upload_error(5, 6, 5, "Read file data error", ">"))
        self.assertEqual(err["error_code"], 6)
        self.assertEqual(struct.unpack("<III", cmds[1][1:13]), (5, 6, 5))

    def test_serve_missing_offered_file_errors(self):
        os.remove(self.path)
        req = mac_download_request(5, [(5, self.path)])
        self.assertEqual([c[0] for c in u.serve_download(req, self.offered)], [0xA1, 0xA9])

    def test_serve_empty_file_sends_one_empty_piece(self):
        open(self.path, "wb").close()
        req = mac_download_request(5, [(5, self.path)])
        cmds = u.serve_download(req, self.offered)
        self.assertEqual([c[0] for c in cmds], [0xA1, 0xA3, 0xA7])
        self.assertEqual(struct.unpack("<IIII", cmds[1][1:17]), (5, 1, 1, 0))


class TestDownload(unittest.TestCase):
    def test_request_layout_big_endian(self):
        cmd = u.encode_download_request(1, [(7, "/a/b")], endian=">")
        self.assertEqual(cmd.hex(), "10" "00000001" "0001" "00000007" "0008"
                         + "/a/b".encode("utf-16-be").hex())

    def test_request_little_endian_default(self):
        # What the Mac accepted from a Linux peer (dl_2026-11-11_0919le run).
        cmd = u.encode_download_request(1, [(7, "/a")])
        self.assertEqual(cmd.hex(), "10" "01000000" "0100" "07000000" "0400"
                         + "/a".encode("utf-16-le").hex())

    def test_request_two_files(self):
        cmd = u.encode_download_request(3, [(1, "/x"), (2, "/yy")])
        self.assertEqual(cmd[5:7], b"\x02\x00")
        self.assertEqual(len(cmd), 7 + (6 + 4) + (6 + 6))

    def test_file_data(self):
        cmd = bytes([0xA3]) + struct.pack(">IIII", 5, 2, 0, 3) + b"abc"
        d = u.decode_file_data(cmd)
        self.assertEqual((d["file_id"], d["total"], d["index"], d["data"]), (5, 2, 0, b"abc"))
        desc = u.describe_command(cmd)
        self.assertEqual((desc["command_name"], desc["data_length"]), ("DownloadFileData", 3))
        self.assertNotIn("data", desc)

    def test_file_data_truncated(self):
        cmd = bytes([0xA3]) + struct.pack(">IIII", 5, 1, 0, 9) + b"abc"
        self.assertIn("decode_error", u.describe_command(cmd))

    def test_finished(self):
        d = u.describe_command(bytes([0xA7, 0, 0, 0, 1]))
        self.assertEqual((d["command_name"], d["session_id"]), ("DownloadMultiFileFinished", 1))

    def test_upload_error_from_mac(self):
        # 65-byte 0xA9 the Mac sent for a missing file (dl_2026-11-11_0928missing).
        cmd = bytes.fromhex(
            "a9" "00000001" "00000006" "00000001" "000000000000" "0000002a"
            + "Read file data error\0".encode("utf-16-be").hex())
        self.assertEqual(len(cmd), 65)
        d = u.describe_command(cmd)
        self.assertEqual((d["command_name"], d["session_id"], d["error_code"], d["file_id"],
                          d["error"]), ("UploadMultiFileError", 1, 6, 1, "Read file data error"))

    def test_upload_error_truncated(self):
        cmd = bytes([0xA9]) + bytes(18) + struct.pack(">I", 10) + b"ab"
        self.assertIn("decode_error", u.describe_command(cmd))


class TestHeader(unittest.TestCase):
    def test_sg_io_hdr_size(self):
        self.assertEqual(ctypes.sizeof(u.SgIoHdr), 88)


if __name__ == "__main__":
    unittest.main()
