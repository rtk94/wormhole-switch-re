import ctypes
import os
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


class TestHeader(unittest.TestCase):
    def test_sg_io_hdr_size(self):
        self.assertEqual(ctypes.sizeof(u.SgIoHdr), 88)


if __name__ == "__main__":
    unittest.main()
