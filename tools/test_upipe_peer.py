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

    # The Mac's image copy (img run): temp files under a 51-character
    # /\var\folders\…\-Tmp-\ prefix; this one has the same lengths.
    IMG_DIR = "/\\" + "v" * 48 + "\\"
    IMG_TIFF, IMG_BMP = IMG_DIR + "CBContent.tmp", IMG_DIR + "CBBitmapContent.tmp"

    def test_clipboard_image_packet_matches_mac_size(self):
        self.assertEqual((len(self.IMG_DIR), len(self.IMG_TIFF), len(self.IMG_BMP)), (51, 64, 70))
        cmd = u.encode_clipboard_image(self.IMG_TIFF, self.IMG_BMP)
        self.assertEqual(len(cmd), 1024)
        xml = u.decode_xml_packet(cmd)
        self.assertIn("<OTIMSG><CP_Content_Text></CP_Content_Text><CP_Content_Bitmap_ImageFile>", xml)
        d = u.describe_command(cmd)
        self.assertEqual((d["cb_format"], d["image_file"], d["bitmap_file"]),
                         ("Apple TIFF Format", self.IMG_TIFF, self.IMG_BMP))

    def test_clipboard_image_without_bitmap_omits_the_element(self):
        # An empty CP_Content_Bitmap_ImageFile crashed GoBridgeDemon
        # (ConvertHexStringToPath on ""); without the element it is skipped.
        xml = u.decode_xml_packet(u.encode_clipboard_image("/tmp/a.tiff"))
        self.assertNotIn("CP_Content_Bitmap_ImageFile", xml)
        self.assertIn("<CP_Content_Text></CP_Content_Text><CP_Content_ImageFile>", xml)
        self.assertNotIn("bitmap_file", u.decode_clipboard(xml))

    def test_mac_temp_path_to_posix(self):
        self.assertEqual(u.posix_path("/\\var\\folders\\pD\\x+++TI\\-Tmp-\\CBContent.tmp"),
                         "/var/folders/pD/x+++TI/-Tmp-/CBContent.tmp")
        self.assertEqual(u.posix_path("/home/user/a.png"), "/home/user/a.png")

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


class TestWindowsPeer(unittest.TestCase):
    """A Windows peer writes its fields little-endian (first Windows <-> Mac
    session, 2026-11-11, #50); the Mac writes them big-endian."""

    def test_xml_packet_little_endian_length(self):
        xml = "<NP_Cmd>Cmd_Delete_Src_Temp_File</NP_Cmd>"
        cmd = bytes([u.CMD_XML]) + struct.pack("<I", len(xml)) + xml.encode()
        self.assertEqual(u.decode_xml_packet(cmd, "<"), xml)
        for endian in ("<", ">"):  # ">" falls back to the other byte order
            d = u.describe_command(cmd, endian)
            self.assertNotIn("decode_error", d)
            self.assertEqual(d["np_cmd"], "Cmd_Delete_Src_Temp_File")

    def test_xml_packet_big_endian_still_default(self):
        cmd = u.encode_xml_packet("<NP_Cmd>x</NP_Cmd>")
        self.assertEqual(u.decode_xml_packet(cmd), "<NP_Cmd>x</NP_Cmd>")

    def test_get_directory_info_little_endian(self):
        cmd = u.encode_get_directory_info("/Users/someone/Desktop", "<")
        self.assertEqual(u.describe_command(cmd, "<")["path"], "/Users/someone/Desktop")
        d = u.describe_command(cmd, ">")
        self.assertNotIn("decode_error", d)
        self.assertEqual(d["path"], "/Users/someone/Desktop")

    def test_change_file_attribute_layout(self):
        # 37 <attributes u32> <ctime> <atime> <mtime> (FILETIME u64 each)
        #    <path length u32, bytes> <path, UTF-16, no NUL>
        cmd = u.encode_change_file_attribute("/var/folders/x/T/f", 0x20,
                                             1700000000, 1700000001, 1700000002, "<")
        path = "/var/folders/x/T/f".encode("utf-16-le")
        self.assertEqual(cmd[0], 0x37)
        self.assertEqual(cmd[1:5], struct.pack("<I", 0x20))
        self.assertEqual(struct.unpack("<Q", cmd[5:13])[0], u.filetime_from_unix(1700000000))
        self.assertEqual(cmd[29:33], struct.pack("<I", len(path)))
        self.assertEqual(cmd[33:], path)
        d = u.describe_command(cmd, "<")
        self.assertEqual(d["command_name"], "ChangeFileAttribute")
        self.assertEqual((d["attributes"], d["path"]), (0x20, "/var/folders/x/T/f"))
        self.assertEqual((d["ctime"], d["atime"], d["mtime"]),
                         (1700000000, 1700000001, 1700000002))

    def test_change_file_attribute_truncated(self):
        cmd = u.encode_change_file_attribute("/a", 0x20, 0, 0, 0, "<")
        with self.assertRaises(ValueError):
            u.decode_change_file_attribute(cmd[:-1], "<")

    def test_windows_package_with_attribute_command(self):
        # Windows fills the 11 reserved bytes with stale buffer contents and
        # follows each file's 0xa3 with a 0x37 for the destination path.
        a3 = u.encode_file_data(115, 1, 1, b"Version:0.9", "<")
        attr = u.encode_change_file_attribute("/var/folders/x/T/CBAx", 0x20, 1, 2, 3, "<")
        pkg = (bytes([u.CMD_PACKAGE]) + struct.pack("<I", 2)
               + bytes.fromhex("037d02ae0900003c4f5449") + a3 + attr)
        self.assertEqual(u.decode_multiple_file_package(pkg, "<"), [a3, attr])
        for endian in ("<", ">"):
            d = u.describe_command(pkg, endian)
            self.assertNotIn("decode_error", d)
            self.assertEqual([c["command_name"] for c in d["commands"]],
                             ["DownloadFileData", "ChangeFileAttribute"])
            self.assertEqual(d["commands"][0]["file_id"], 115)
            self.assertEqual(d["commands"][1]["path"], "/var/folders/x/T/CBAx")

    def test_package_rejects_unknown_subcommand(self):
        pkg = u.encode_multiple_file_package([bytes([0x39]) + bytes(20)])
        with self.assertRaises(ValueError):
            u.decode_multiple_file_package(pkg, "<")


class TestImageFetcher(unittest.TestCase):
    """--save-clipboard-images: fetch each image the Mac copies."""

    def test_requests_the_image_file_as_posix_path(self):
        f = u.ClipboardImageFetcher()
        cmd = f.request("/\\var\\folders\\x\\CBContent.tmp")
        req = u.decode_download_request(cmd, "<")
        self.assertEqual(req["multi_session_id"], 1001)
        self.assertEqual(req["files"], [{"file_id": 1001, "path": "/var/folders/x/CBContent.tmp"}])
        self.assertEqual(f.filename(1001), "clipboard_1.tiff")

    def test_ids_and_names_count_up(self):
        f = u.ClipboardImageFetcher()
        f.request("/a")
        req = u.decode_download_request(f.request("/b"), "<")
        self.assertEqual(req["files"][0]["file_id"], 1002)
        self.assertEqual(f.filename(1002), "clipboard_2.tiff")
        self.assertIsNone(f.filename(1))


class TestAfterLogin(unittest.TestCase):
    """What the peer queues once the Mac accepts our Login."""

    def test_nothing_by_default(self):
        self.assertEqual(u.after_login_commands(), [])

    def test_image_offered_by_absolute_path(self):
        cmds = u.after_login_commands(image="pic.tiff")
        self.assertEqual([why for _, why in cmds], ["image"])
        d = u.describe_command(cmds[0][0])
        self.assertEqual((d["cb_format"], d["image_file"]),
                         ("Apple TIFF Format", os.path.abspath("pic.tiff")))
        self.assertNotIn("bitmap_file", d)

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


class TestMultipleFilePackage(unittest.TestCase):
    """MultipleFilePackage (0x3a): several 0xa3 in one command (pkg run)."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.offered = {}

    def tearDown(self):
        self.tmp.cleanup()

    def file(self, name, data):
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as f:
            f.write(data)
        self.offered[path] = path
        return path

    def test_layout(self):
        a = u.encode_file_data(1, 1, 1, b"ab")
        b = u.encode_file_data(2, 1, 1, b"cde")
        pkg = u.encode_multiple_file_package([a, b])
        # 3a <count u32, little-endian: the Mac reads it unswapped> <11 bytes> <commands>
        self.assertEqual(pkg[:16], bytes([0x3A, 2, 0, 0, 0]) + bytes(11))
        self.assertEqual(pkg[16:], a + b)
        self.assertEqual(u.decode_multiple_file_package(pkg, "<"), [a, b])
        d = u.describe_command(pkg, "<")
        self.assertEqual((d["command_name"], d["count"]), ("MultipleFilePackage", 2))
        self.assertEqual([c["file_id"] for c in d["commands"]], [1, 2])

    def test_decode_truncated(self):
        pkg = u.encode_multiple_file_package([u.encode_file_data(1, 1, 1, b"abc")])
        with self.assertRaises(ValueError):
            u.decode_multiple_file_package(pkg[:-1], "<")

    def test_small_files_go_in_one_package(self):
        a, b = self.file("a", b"x" * 3000), self.file("b", b"y" * 5000)
        cmds = u.serve_download(mac_download_request(102, [(102, a), (103, b)]), self.offered)
        self.assertEqual([c[0] for c in cmds], [0xA1, 0x3A, 0xA7])
        subs = [u.decode_file_data(c, "<") for c in
                u.decode_multiple_file_package(cmds[1], "<")]
        self.assertEqual([(s["file_id"], s["data"]) for s in subs],
                         [(102, b"x" * 3000), (103, b"y" * 5000)])

    def test_one_small_file_or_a_split_file_stays_bare(self):
        a = self.file("a", b"x" * 10)
        cmds = u.serve_download(mac_download_request(1, [(1, a)]), self.offered)
        self.assertEqual([c[0] for c in cmds], [0xA1, 0xA3, 0xA7])
        big, small = self.file("big", b"z" * 9000), self.file("s", b"s")
        cmds = u.serve_download(mac_download_request(2, [(2, big), (3, small)]),
                                self.offered, piece=4096)
        self.assertEqual([c[0] for c in cmds], [0xA1, 0xA3, 0xA3, 0xA3, 0xA3, 0xA7])

    def test_packages_stay_under_the_piece_limit(self):
        paths = [self.file(n, b"q" * 3000) for n in "abcde"]
        req = mac_download_request(1, [(i, p) for i, p in enumerate(paths, 1)])
        cmds = u.serve_download(req, self.offered, piece=7000)
        self.assertEqual([c[0] for c in cmds], [0xA1, 0x3A, 0x3A, 0xA3, 0xA7])
        self.assertEqual([len(u.decode_multiple_file_package(c, "<")) for c in cmds[1:3]], [2, 2])

    def test_package_off(self):
        a, b = self.file("a", b"1"), self.file("b", b"2")
        cmds = u.serve_download(mac_download_request(1, [(1, a), (2, b)]), self.offered,
                                package=False)
        self.assertEqual([c[0] for c in cmds], [0xA1, 0xA3, 0xA3, 0xA7])


class TestCommandTable(unittest.TestCase):
    def test_ids_from_decompiled_init_methods(self):
        # -[<Class> init] setCommandID: values in GoBridgeDemon 152311cb.
        self.assertEqual(u.COMMANDS[0x0C], "UploadFileData")
        self.assertEqual(u.COMMANDS[0x34], "SyncDynamic")
        self.assertEqual(u.COMMANDS[0x37], "ChangeFileAttribute")
        self.assertEqual(u.COMMANDS[0xA2], "DirectoryInfo")
        self.assertEqual(u.COMMANDS[0xA4], "DriveInfo")
        self.assertEqual(u.COMMANDS[0x12], "UploadMultipleFile")


class TestBrowse(unittest.TestCase):
    """Linux as the file server for Wormhole.app's remote browser."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "share")
        os.makedirs(os.path.join(self.root, "sub"))
        with open(os.path.join(self.root, "a.txt"), "wb") as f:
            f.write(b"x" * 1234)
        os.utime(os.path.join(self.root, "a.txt"), (1475782699, 1475782700))

    def tearDown(self):
        self.tmp.cleanup()

    def test_decode_mac_get_directory_info(self):
        # The Mac's 0x04 from the drives run: BE16 length, UTF-16BE, no NUL.
        path = "/home/user/share"
        raw = path.encode("utf-16-be")
        cmd = bytes([0x04]) + struct.pack(">H", len(raw)) + raw
        self.assertEqual(u.decode_get_directory_info(cmd), path)
        self.assertEqual(u.describe_command(cmd)["path"], path)

    def test_drive_list_xml(self):
        cmd = u.encode_drive_list([("/home/user/share", 1000, 400)])
        xml = u.decode_xml_packet(cmd)
        self.assertTrue(xml.startswith("<ExtraXmlCommand>HookAppService</ExtraXmlCommand>"
                                       "<ExtraXmlParam><OTIMSG><NP_Cmd>"
                                       "NP_Cmd_Post_Drive_Update_Info</NP_Cmd>"))
        self.assertIn("<NP_Remote_Request_Info><NP_Misc_Drive_ListMRS><Line>"
                      "<NP_Misc_Drive_Letter>/home/user/share</NP_Misc_Drive_Letter>"
                      "<NP_Misc_Drive_Total_Space_Number>1000</NP_Misc_Drive_Total_Space_Number>"
                      "<NP_Misc_Drive_Free_Space_Number>400</NP_Misc_Drive_Free_Space_Number>"
                      "</Line></NP_Misc_Drive_ListMRS></NP_Remote_Request_Info>", xml)

    def test_drive_list_escapes_xml(self):
        xml = u.decode_xml_packet(u.encode_drive_list([("/a&b<c", 1, 1)]))
        self.assertIn("/a&amp;b&lt;c", xml)

    def test_directory_record_layout(self):
        rec = u.encode_directory_record("a.txt", 0, 1234, 100, 200, 300, "<")
        self.assertEqual(len(rec), 552)
        words = struct.unpack_from("<10I", rec)
        # attrs; ctime, atime, mtime as (low, high) Unix seconds; size low, high; name
        # bytes.  Time word order checked live: (T, 0) showed T in Wormhole.app,
        # (0, T) showed the year 5828963 (dates run, 2026-11-11).
        self.assertEqual(words, (0, 100, 0, 200, 0, 300, 0, 1234, 0, 10))
        self.assertEqual(rec[40:50].decode("utf-16-le"), "a.txt")
        self.assertEqual(rec[50:], bytes(552 - 50))

    def test_directory_record_large_size_and_long_name(self):
        rec = u.encode_directory_record("n" * 300, 0x10, (3 << 32) + 5, 0, 0, 0, "<")
        self.assertEqual(struct.unpack_from("<I", rec, 0)[0], 0x10)
        self.assertEqual(struct.unpack_from("<II", rec, 28), (5, 3))
        self.assertEqual(struct.unpack_from("<I", rec, 36)[0], 512)   # truncated to fit

    def test_directory_record_time_beyond_32_bits(self):
        rec = u.encode_directory_record("a", 0, 0, (1 << 32) + 2, 0, 0, "<")
        self.assertEqual(struct.unpack_from("<II", rec, 4), (2, 1))

    def test_directory_info_roundtrip(self):
        cmd = u.encode_directory_info([("a", 0, 1, 2, 3, 4), ("b", 0x10, 0, 2, 3, 4)],
                                      free_space=(7 << 32) + 9)
        self.assertEqual(cmd[0], 0xA2)
        d = u.decode_directory_info(cmd, "<")
        self.assertEqual([(e["name"], e["directory"], e["size"], e["mtime"]) for e in d["entries"]],
                         [("a", False, 1, 4), ("b", True, 0, 4)])
        self.assertEqual(d["free_space"], (7 << 32) + 9)
        # One pad byte: the Mac reads the free space only when more follows it.
        self.assertEqual(len(cmd), 1 + 2 + 2 * 552 + 8 + 1)

    def test_free_space_without_pad_is_ignored_like_the_mac(self):
        cmd = u.encode_directory_info([("a", 0, 1, 2, 3, 4)], free_space=5)[:-1]
        self.assertNotIn("free_space", u.decode_directory_info(cmd, "<"))

    def test_list_directory_reads_shared_tree(self):
        entries = u.list_directory(self.root)
        by_name = {e[0]: e for e in entries}
        self.assertEqual(sorted(by_name), ["a.txt", "sub"])
        self.assertEqual(by_name["a.txt"][1:3], (0, 1234))
        self.assertEqual(by_name["a.txt"][5], 1475782700)          # mtime
        self.assertEqual(by_name["sub"][1], 0x10)

    def test_list_directory_marks_dotfiles_hidden(self):
        open(os.path.join(self.root, ".hidden"), "w").close()
        by_name = {e[0]: e for e in u.list_directory(self.root)}
        self.assertEqual(by_name[".hidden"][1], 0x02)

    def test_serve_directory_inside_share(self):
        cmd = u.encode_get_directory_info(os.path.join(self.root, "sub"), ">")
        replies = u.serve_get_directory_info(cmd, [self.root])
        self.assertEqual([r[0] for r in replies], [0xA1, 0xA2])
        self.assertEqual(replies[0][1:3], bytes([0x04, 0]))
        self.assertEqual(u.decode_directory_info(replies[1], "<")["entries"], [])

    def test_serve_refuses_path_outside_share(self):
        for path in (self.tmp.name, os.path.join(self.root, "..", "x"), "/etc"):
            replies = u.serve_get_directory_info(u.encode_get_directory_info(path, ">"),
                                                 [self.root])
            self.assertEqual([r[0] for r in replies], [0xA1], path)
            # requestResult 1 and errorCode 3, as THMGBServer answers an unreadable path
            self.assertEqual(replies[0][1:3], bytes([0x04, 1]))
            self.assertEqual(struct.unpack_from("<I", replies[0], 7)[0], 3)

    def test_after_login_posts_drive_list(self):
        cmds = u.after_login_commands(share=[self.root])
        self.assertEqual([why for _c, why in cmds], ["drives"])
        self.assertIn("<NP_Misc_Drive_Letter>%s</NP_Misc_Drive_Letter>" % self.root,
                      u.decode_xml_packet(cmds[0][0]))

    def test_resolver_serves_shared_files_and_offers_only(self):
        offered = os.path.join(self.tmp.name, "offered.bin")
        open(offered, "w").close()
        r = u.FileResolver({offered: offered}, [self.root])
        self.assertEqual(r.get(offered), offered)
        self.assertEqual(r.get(os.path.join(self.root, "a.txt")),
                         os.path.realpath(os.path.join(self.root, "a.txt")))
        self.assertIsNone(r.get(os.path.join(self.root, "sub")))       # not a file
        self.assertIsNone(r.get(os.path.join(self.tmp.name, "other")))
        req = mac_download_request(9, [(9, os.path.join(self.root, "a.txt"))])
        self.assertEqual([c[0] for c in u.serve_download(req, r)], [0xA1, 0xA3, 0xA7])

    def test_decode_mac_make_new_directory(self):
        # The Mac's 0x07 before an upload (share run): session BE32, BE16
        # length, UTF-16BE path with a NUL.
        raw = (self.root + "\0").encode("utf-16-be")
        cmd = bytes([0x07]) + struct.pack(">IH", 105, len(raw)) + raw
        self.assertEqual(u.decode_make_new_directory(cmd), {"session_id": 105, "path": self.root})
        self.assertEqual(u.describe_command(cmd)["path"], self.root)

    def test_make_directory_inside_share(self):
        new = os.path.join(self.root, "sub", "new")
        replies = u.serve_make_new_directory(u.encode_make_new_directory(1, new), [self.root])
        self.assertTrue(os.path.isdir(new))
        self.assertEqual([r[:3] for r in replies], [bytes([0xA1, 0x07, 0])])

    def test_make_existing_directory_succeeds(self):
        replies = u.serve_make_new_directory(u.encode_make_new_directory(1, self.root), [self.root])
        self.assertEqual(replies[0][2], 0)

    def test_make_directory_outside_share_refused(self):
        outside = os.path.join(self.tmp.name, "outside")
        replies = u.serve_make_new_directory(u.encode_make_new_directory(1, outside), [self.root])
        self.assertFalse(os.path.exists(outside))
        self.assertEqual(replies[0][2], 1)

    def test_server_replies_dispatch(self):
        r = u.FileResolver({}, [self.root])
        listing = u.server_replies(u.encode_get_directory_info(self.root), [self.root], r)
        self.assertEqual([(c[0], why) for c, why in listing], [(0xA1, "browse"), (0xA2, "browse")])
        mkdir = u.server_replies(u.encode_make_new_directory(1, self.root), [self.root], r)
        self.assertEqual([(c[0], why) for c, why in mkdir], [(0xA1, "mkdir")])
        self.assertEqual(u.server_replies(bytes([0x02]), [self.root], r), [])
        # Nothing shared or offered: browsing and mkdir are not answered at all.
        self.assertEqual(u.server_replies(u.encode_get_directory_info(self.root), [],
                                          u.FileResolver({}, [])), [])

    def test_serve_refuses_symlink_escape(self):
        os.symlink("/etc", os.path.join(self.root, "link"))
        replies = u.serve_get_directory_info(
            u.encode_get_directory_info(os.path.join(self.root, "link"), ">"), [self.root])
        self.assertEqual(replies[0][2], 1)


def mac_upload_files(command, multi, files, total_size, large=0):
    """0x13 / 0x12 as the Mac sends them (upload run): BE fields, UTF-16BE
    paths with a NUL.  files: (fileID, path)."""
    out = bytes([command]) + struct.pack(">IQHH", multi, total_size, large, len(files))
    for fid, path in files:
        raw = (path + "\0").encode("utf-16-be")
        out += struct.pack(">IH", fid, len(raw)) + raw
    return out


def mac_upload_multi(multi, files, command=0x12):
    """0x12 as the Mac sent it (upload run, 101 bytes for one file): no size
    or large-file count, unlike 0x13.  0x15 (empty files) has the same shape."""
    out = bytes([command]) + struct.pack(">IH", multi, len(files))
    for fid, path in files:
        raw = (path + "\0").encode("utf-16-be")
        out += struct.pack(">IH", fid, len(raw)) + raw
    return out


def mac_file_data(file_id, total, index, data):
    return bytes([0x0C]) + struct.pack(">IIII", file_id, total, index, len(data)) + data


class TestUpload(unittest.TestCase):
    """Linux as the server for uploads pasted into Wormhole.app's browser."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "share")
        os.makedirs(self.root)
        self.rx = u.UploadReceiver([self.root])
        self.dest = os.path.join(self.root, "up.bin")

    def tearDown(self):
        self.tmp.cleanup()

    def test_zero_length_upload_creates_empty_files(self):
        # The Mac's 101-byte 0x15 (empty run): session 105, file 111.
        cmd = mac_upload_multi(105, [(111, self.dest)], command=0x15)
        self.assertEqual(len(cmd), 7 + 6 + 2 * (len(self.dest) + 1))
        self.assertEqual(u.describe_command(cmd)["files"], [{"file_id": 111, "path": self.dest}])
        # THMGBServer createZeroLengthFiles: answers only on failure.
        self.assertEqual(self.rx.handle(cmd), [])
        self.assertEqual(os.path.getsize(self.dest), 0)

    def test_zero_length_upload_replaces_existing_file(self):
        with open(self.dest, "wb") as f:
            f.write(b"old")
        self.rx.handle(mac_upload_multi(1, [(1, self.dest)], command=0x15))
        self.assertEqual(os.path.getsize(self.dest), 0)

    def test_zero_length_upload_outside_share_errors(self):
        outside = os.path.join(self.tmp.name, "out.txt")
        replies = self.rx.handle(mac_upload_multi(7, [(8, outside)], command=0x15))
        self.assertEqual(len(replies), 1)
        err = u.decode_upload_error(replies[0], "<")
        self.assertEqual((err["session_id"], err["error_code"], err["file_id"]),
                         (7, u.REMOTE_OPERATION_ERROR, 8))
        self.assertFalse(os.path.exists(outside))

    def test_zero_length_upload_routed(self):
        r = u.FileResolver({}, [self.root])
        replies = u.server_replies(mac_upload_multi(1, [(1, self.dest)], command=0x15),
                                   [self.root], r, self.rx)
        self.assertEqual(replies, [])
        self.assertTrue(os.path.exists(self.dest))

    def test_decode_mac_confirm(self):
        # Shape of the Mac's 111-byte 0x13 (upload run): session 105, 100 000 bytes, 1 file.
        cmd = mac_upload_files(0x13, 105, [(106, self.dest)], 100000)
        self.assertEqual(u.decode_upload_files(cmd), {
            "multi_session_id": 105, "total_size": 100000, "large_files": 0,
            "files": [{"file_id": 106, "path": self.dest}]})
        self.assertEqual(u.describe_command(cmd)["multi_session_id"], 105)

    def test_confirmation_layout(self):
        cmd = u.encode_upload_confirmation(105, [7, 9])
        self.assertEqual(cmd.hex(), "a8" "00010000" "69000000" "02000000" "07000000" "09000000")

    def test_confirm_reports_existing_files_and_space(self):
        open(self.dest, "w").close()
        other = os.path.join(self.root, "new.bin")
        replies = self.rx.handle(mac_upload_files(0x13, 105, [(1, self.dest), (2, other)], 10))
        self.assertEqual(replies, [u.encode_upload_confirmation(105, [1])])

    def test_confirm_outside_share_is_read_only(self):
        outside = os.path.join(self.tmp.name, "x.bin")
        (reply,) = self.rx.handle(mac_upload_files(0x13, 5, [(1, outside)], 10))
        self.assertEqual(reply[4], 1)                                # destRootPathReadOnlyFlag

    def test_confirm_without_space(self):
        (reply,) = self.rx.handle(mac_upload_files(0x13, 5, [(1, self.dest)], 1 << 62))
        self.assertEqual(reply[2], 0)                                # freeSpaceFlag

    def test_upload_one_file_in_pieces(self):
        self.assertEqual(self.rx.handle(mac_upload_multi(105, [(106, self.dest)])), [])
        self.assertEqual(self.rx.handle(mac_file_data(106, 2, 1, b"abc")), [])
        self.assertEqual(self.rx.handle(mac_file_data(106, 2, 2, b"def")),
                         [u.encode_download_finished(105, "<")])
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), b"abcdef")

    def test_finished_only_after_every_file(self):
        second = os.path.join(self.root, "sub", "two.bin")          # parent created on demand
        self.rx.handle(mac_upload_multi(8, [(8, self.dest), (9, second)]))
        self.assertEqual(self.rx.handle(mac_file_data(8, 1, 1, b"a")), [])
        self.assertEqual(self.rx.handle(mac_file_data(9, 1, 1, b"b")),
                         [u.encode_download_finished(8, "<")])
        with open(second, "rb") as f:
            self.assertEqual(f.read(), b"b")

    def test_empty_file(self):
        self.rx.handle(mac_upload_multi(3, [(3, self.dest)]))
        self.assertEqual(self.rx.handle(mac_file_data(3, 1, 1, b"")),
                         [u.encode_download_finished(3, "<")])
        self.assertEqual(os.path.getsize(self.dest), 0)

    def test_upload_outside_share_refused(self):
        outside = os.path.join(self.tmp.name, "x.bin")
        replies = self.rx.handle(mac_upload_multi(4, [(4, outside)]))
        self.assertEqual([r[:3] for r in replies], [bytes([0xA1, 0x12, 1])])
        self.assertEqual(self.rx.handle(mac_file_data(4, 1, 1, b"x")),
                         [u.encode_upload_error(4, 3, 4, "Remote operation error", "<")])
        self.assertFalse(os.path.exists(outside))

    def test_data_for_unknown_file_is_an_error(self):
        self.assertEqual(self.rx.handle(mac_file_data(77, 1, 1, b"x")),
                         [u.encode_upload_error(77, 3, 77, "Remote operation error", "<")])

    def test_abort_drops_the_session(self):
        self.rx.handle(mac_upload_multi(5, [(5, self.dest)]))
        self.rx.handle(mac_file_data(5, 2, 1, b"a"))
        self.assertEqual(self.rx.handle(bytes([0x14]) + struct.pack(">I", 5)), [])
        self.assertEqual(self.rx.handle(mac_file_data(5, 2, 2, b"b"))[0][0], 0xA9)

    def test_decode_mac_upload_multi(self):
        # The Mac's 101-byte 0x12 (upload run): session 105, one file, ID 106.
        cmd = mac_upload_multi(105, [(106, "/home/user/share/wh_ok.bin")])
        self.assertEqual(len(cmd), 7 + 6 + 2 * 27)
        self.assertEqual(u.decode_upload_multi(cmd), {
            "multi_session_id": 105,
            "files": [{"file_id": 106, "path": "/home/user/share/wh_ok.bin"}]})
        self.assertEqual(u.describe_command(cmd)["files"][0]["file_id"], 106)

    def test_malformed_request_does_not_raise(self):
        r = u.FileResolver({}, [self.root])
        bad = mac_upload_multi(1, [(1, self.dest)])[:-5]
        replies = u.server_replies(bad, [self.root], r, self.rx)
        self.assertEqual([(c[:3], why) for c, why in replies],
                         [(bytes([0xA1, 0x12, 1]), "error")])

    def test_describe_malformed_request_does_not_raise(self):
        bad = mac_upload_multi(1, [(1, self.dest)])[:-5]
        desc = u.describe_command(bad)
        self.assertEqual(desc["command_name"], "UploadMultipleFile")
        self.assertIn("truncated", desc["decode_error"])

    def test_server_replies_routes_uploads(self):
        r = u.FileResolver({}, [self.root])
        replies = u.server_replies(mac_upload_files(0x13, 1, [(1, self.dest)], 1), [self.root],
                                   r, self.rx)
        self.assertEqual([(c[0], why) for c, why in replies], [(0xA8, "upload")])


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


class TestFileOps(unittest.TestCase):
    """Move to Trash, rename and remove from Wormhole.app's remote browser."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "share")
        self.trash = os.path.join(self.tmp.name, "Trash")
        os.makedirs(os.path.join(self.root, "dir", "deeper"))
        for name in ("a.txt", "b.txt", os.path.join("dir", "inner.txt")):
            with open(os.path.join(self.root, name), "w") as f:
                f.write(name)
        self.outside = os.path.join(self.tmp.name, "outside.txt")
        with open(self.outside, "w") as f:
            f.write("keep")

    def tearDown(self):
        self.tmp.cleanup()

    def p(self, *parts):
        return os.path.join(self.root, *parts)

    def replies(self, cmd):
        return u.server_replies(cmd, [self.root], u.FileResolver({}, [self.root]),
                                trash=self.trash)

    def test_delete_file_roundtrip(self):
        cmd = u.encode_delete(0x08, 7, "/home/user/x.txt")
        self.assertEqual(cmd[:7], bytes([0x08, 0, 0, 0, 7, 0, 34]))   # 16 chars + NUL, UTF-16BE
        self.assertEqual(u.decode_delete(cmd), {"session_id": 7, "path": "/home/user/x.txt"})
        self.assertEqual(u.describe_command(cmd)["command_name"], "DeleteFile")
        self.assertEqual(u.describe_command(cmd)["path"], "/home/user/x.txt")

    def test_delete_directory_roundtrip(self):
        cmd = u.encode_delete(0x06, 1, "/home/user/d")
        self.assertEqual(u.decode_delete(cmd)["path"], "/home/user/d")
        self.assertEqual(u.describe_command(cmd)["command_name"], "DeleteDirectory")

    def test_rename_roundtrip(self):
        cmd = u.encode_rename(3, "/s/old.txt", "/s/new.txt")
        # <session u32> <oldLen u16> <newLen u16> <old> <new>
        self.assertEqual(cmd[:9], bytes([0x09, 0, 0, 0, 3, 0, 22, 0, 22]))
        self.assertEqual(u.decode_rename(cmd), {"session_id": 3, "path": "/s/old.txt",
                                                "new_path": "/s/new.txt"})
        self.assertEqual(u.describe_command(cmd)["new_path"], "/s/new.txt")

    def test_delete_file_moves_it_to_the_trash(self):
        replies = self.replies(u.encode_delete(0x08, 1, self.p("a.txt")))
        self.assertEqual([(c[:3], why) for c, why in replies],
                         [(bytes([0xA1, 0x08, 0]), "delete")])
        self.assertFalse(os.path.exists(self.p("a.txt")))
        with open(os.path.join(self.trash, "files", "a.txt")) as f:
            self.assertEqual(f.read(), "a.txt")
        with open(os.path.join(self.trash, "info", "a.txt.trashinfo")) as f:
            info = f.read()
        self.assertIn("[Trash Info]\nPath=" + self.p("a.txt").replace(" ", "%20"), info)
        self.assertIn("DeletionDate=", info)

    def test_trash_names_do_not_collide(self):
        self.replies(u.encode_delete(0x08, 1, self.p("a.txt")))
        with open(self.p("a.txt"), "w") as f:
            f.write("second")
        self.replies(u.encode_delete(0x08, 2, self.p("a.txt")))
        self.assertEqual(sorted(os.listdir(os.path.join(self.trash, "files"))),
                         ["a.2.txt", "a.txt"])

    def test_delete_directory_moves_the_tree(self):
        replies = self.replies(u.encode_delete(0x06, 1, self.p("dir")))
        self.assertEqual(replies[0][0][:3], bytes([0xA1, 0x06, 0]))
        self.assertFalse(os.path.exists(self.p("dir")))
        self.assertTrue(os.path.isfile(os.path.join(self.trash, "files", "dir", "inner.txt")))

    def test_delete_refused_outside_share_and_for_the_share_itself(self):
        for target in (self.outside, self.root, self.p("missing.txt")):
            replies = self.replies(u.encode_delete(0x08, 1, target))
            self.assertEqual(replies[0][0][:3], bytes([0xA1, 0x08, 1]), target)
        self.assertTrue(os.path.exists(self.outside))
        self.assertTrue(os.path.isdir(self.root))

    def test_delete_symlink_trashes_the_link_not_its_target(self):
        os.symlink(self.outside, self.p("link"))
        replies = self.replies(u.encode_delete(0x08, 1, self.p("link")))
        self.assertEqual(replies[0][0][:3], bytes([0xA1, 0x08, 0]))
        self.assertFalse(os.path.lexists(self.p("link")))
        self.assertTrue(os.path.islink(os.path.join(self.trash, "files", "link")))
        with open(self.outside) as f:
            self.assertEqual(f.read(), "keep")

    def test_rename_inside_share(self):
        replies = self.replies(u.encode_rename(1, self.p("a.txt"), self.p("c.txt")))
        self.assertEqual([(c[:3], why) for c, why in replies],
                         [(bytes([0xA1, 0x09, 0]), "rename")])
        self.assertFalse(os.path.exists(self.p("a.txt")))
        with open(self.p("c.txt")) as f:
            self.assertEqual(f.read(), "a.txt")

    def test_rename_refusals(self):
        cases = [(self.p("a.txt"), self.p("b.txt")),                    # target exists
                 (self.p("missing.txt"), self.p("c.txt")),              # no source
                 (self.p("a.txt"), os.path.join(self.tmp.name, "c")),   # out of the share
                 (self.outside, self.p("c.txt")),                       # from outside
                 (self.root, self.p("renamed_root"))]                   # the share itself
        for old, new in cases:
            replies = self.replies(u.encode_rename(1, old, new))
            self.assertEqual(replies[0][0][:3], bytes([0xA1, 0x09, 1]), (old, new))
            err = u.decode_response(replies[0][0], "<")
            self.assertEqual(err["error_code"], u.REMOTE_OPERATION_ERROR)
        with open(self.p("b.txt")) as f:
            self.assertEqual(f.read(), "b.txt")
        self.assertTrue(os.path.exists(self.p("a.txt")))

    def test_not_served_without_share(self):
        cmd = u.encode_delete(0x08, 1, self.p("a.txt"))
        self.assertEqual(u.server_replies(cmd, [], u.FileResolver({}, []), trash=self.trash), [])
        self.assertTrue(os.path.exists(self.p("a.txt")))


if __name__ == "__main__":
    unittest.main()
