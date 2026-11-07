#!/usr/bin/env python3
"""Tests for tools/wormhole_parse.py.

Run from the repo root, stdlib only:

    python3 -m unittest tools.test_wormhole_parse -v
    # or
    python3 tools/test_wormhole_parse.py

The integration tests run against the committed capture and assert
the counts/decodings documented in docs/capture-log.md.  If a count
changes, either the capture changed (update capinfos + docs) or the
parser regressed -- do not just update the expected value.
"""

from __future__ import annotations

import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wormhole_parse as wp  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
PCAP = REPO / "captures" / "wormhole_bus3_2026-11-06.pcap"


class TestCommittedCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap = wp.read_pcap(PCAP)
        cls.summary = wp.summarise(cls.pcap)
        cls.txns = wp.parse_transactions(cls.pcap.packets)
        cls.wormhole = [t for t in cls.txns if t.bus == 3 and t.dev == 15]

    def test_packet_count_and_hash(self):
        self.assertEqual(len(self.pcap.packets), 2298)
        self.assertEqual(
            self.pcap.sha256,
            "fff7d587ab317d5fb2cb40c194347ba40ffb6aa4b7847fd4cba02e0eb3d1c97f")
        self.assertEqual(self.pcap.linktype, 220)
        self.assertAlmostEqual(self.pcap.duration, 29.032344, places=3)

    def test_wormhole_discovery_by_vid_pid(self):
        self.assertEqual(self.summary["wormhole_devices"], ["3:15"])
        info = self.summary["devices"]["3:15"]
        self.assertEqual(info["vid"], "0x0711")
        self.assertEqual(info["pid"], "0x2211")
        self.assertEqual(info["packets"], 250)
        self.assertEqual(info["by_xfer"].get("bulk"), 244)
        # HID interfaces idle: no interrupt packets for the Wormhole.
        self.assertEqual(info["by_xfer"].get("interrupt", 0), 0)

    def test_wormhole_enumeration_interfaces(self):
        devices = wp.discover_devices(self.pcap.packets)
        ifaces = devices[(3, 15)].interfaces
        self.assertEqual(len(ifaces), 3)
        self.assertEqual((ifaces[0]["class"], ifaces[0]["subclass"]), (0x08, 0x06))
        eps = [ep["address"] for iface in ifaces for ep in iface["endpoints"]]
        # Order in the descriptor: bulk IN/OUT, mouse EP3, keyboard EP4.
        self.assertEqual(eps, ["0x81", "0x02", "0x83", "0x84"])

    def test_wormhole_transaction_count_and_opcodes(self):
        self.assertEqual(len(self.wormhole), 42)
        hist = self.summary["devices"]["3:15"]["opcode_histogram"]
        self.assertEqual(hist, {
            "LOG SENSE": 16,
            "REQUEST SENSE": 16,
            "TEST UNIT READY": 4,
            "INQUIRY": 2,
            "READ CAPACITY(10)": 1,
            "READ TOC/PMA/ATIP": 2,
            "GET CONFIGURATION": 1,
        })
        csw = self.summary["devices"]["3:15"]["csw_status_histogram"]
        # Only the LOG SENSE probes fail.
        self.assertEqual(csw.get("CHECK CONDITION"), 16)

    def test_inquiry_decode(self):
        inq = [t for t in self.wormhole if t.opcode == 0x12]
        self.assertEqual(len(inq), 2)
        data = wp.decode_data(inq[0])
        self.assertEqual(data["pdt"], 5)
        self.assertEqual(data["vendor"], "j5create")
        self.assertEqual(data["product"], "WormholeSwitch")
        self.assertEqual(data["revision"], "2.00")
        self.assertEqual(data["version"], 0)

    def test_read_capacity_decode(self):
        rc = [t for t in self.wormhole if t.opcode == 0x25]
        self.assertEqual(len(rc), 1)
        data = wp.decode_data(rc[0])
        self.assertEqual(data["last_lba"], 1592)
        self.assertEqual(data["block_len"], 2048)
        self.assertEqual(data["capacity_bytes"], 1593 * 2048)

    def test_request_sense_decode(self):
        rs = [t for t in self.wormhole if t.opcode == 0x03]
        self.assertEqual(len(rs), 16)
        for t in rs:
            data = wp.decode_data(t)
            self.assertEqual(data["sense_key"], 5)
            self.assertEqual(data["sense_key_name"], "Illegal Request")
            self.assertEqual(data["asc"], "0x20")
            self.assertEqual(data["asc_name"],
                             "Invalid command operation code")

    def test_read_toc_and_get_config_are_cdrom_probes(self):
        # 0x43/0x46 are CD/DVD probes issued by the kernel after the
        # manual sg_inq/sg_readcap/dd, not READ(10) variants.
        toc = [t for t in self.wormhole if t.opcode == 0x43]
        cfg = [t for t in self.wormhole if t.opcode == 0x46]
        self.assertEqual(len(toc), 2)
        self.assertEqual(len(cfg), 1)
        self.assertEqual(toc[0].opcode_name, "READ TOC/PMA/ATIP")
        self.assertEqual(cfg[0].opcode_name, "GET CONFIGURATION")

    def test_interrupt_traffic_belongs_to_logitech_not_wormhole(self):
        summary = self.summary
        for key, dev in summary["devices"].items():
            if dev["is_wormhole"]:
                self.assertEqual(dev["by_xfer"].get("interrupt", 0), 0)
        # Bus 3 device 7 (Logitech 046d:c548) carries all interrupt traffic.
        logi = summary["devices"]["3:7"]
        self.assertGreater(logi["by_xfer"].get("interrupt", 0), 1000)

    def test_json_is_serialisable(self):
        first = self.pcap.first_ts or 0.0
        dicts = [wp.transaction_to_dict(t, first) for t in self.wormhole]
        blob = json.dumps(dicts, sort_keys=True)
        self.assertIn("WormholeSwitch", blob)
        self.assertEqual(len(dicts), 42)

    def test_no_orphan_csw_for_wormhole(self):
        for t in self.wormhole:
            self.assertIsNotNone(t.csw, "transaction %s missing CSW" % t.cbw.tag)


class TestUnitDecoders(unittest.TestCase):
    def test_parse_cbw(self):
        cdb = bytes.fromhex("120000002400")
        payload = b"USBC" + struct.pack("<II", 0x201, 36) + bytes([0x80, 0, 6]) + cdb
        payload = payload.ljust(31, b"\x00")
        cbw = wp.parse_cbw(payload)
        self.assertIsNotNone(cbw)
        assert cbw is not None
        self.assertEqual(cbw.tag, 0x201)
        self.assertEqual(cbw.cdb, cdb)
        self.assertEqual(cbw.flags, 0x80)

    def test_parse_csw(self):
        payload = b"USBS" + struct.pack("<II", 0x1F1, 0) + bytes([1])
        csw = wp.parse_csw(payload)
        self.assertIsNotNone(csw)
        assert csw is not None
        self.assertEqual(csw.status, 1)

    def test_parse_cbw_rejects_short_and_bad_sig(self):
        self.assertIsNone(wp.parse_cbw(b"USBC" + b"\x00" * 4))  # truncated echo
        self.assertIsNone(wp.parse_cbw(b"XXXX" + b"\x00" * 27))

    def test_decode_cdb_read10(self):
        cdb = bytes.fromhex("28000000000100000100")
        out = wp.decode_cdb(cdb)
        self.assertEqual(out["name"], "READ(10)")
        self.assertEqual(out["lba"], 1)
        self.assertEqual(out["transfer_len_blocks"], 1)

    def test_decode_cdb_log_sense(self):
        out = wp.decode_cdb(bytes.fromhex("4a010000100000000800"))
        self.assertEqual(out["name"], "LOG SENSE")
        self.assertEqual(out["alloc_len"], 8)

    def test_decode_cdb_unknown_opcode(self):
        # 0x0B is an obsolete SEEK opcode not in SCSI_OPCODES and
        # outside the 0xC0-0xFF vendor range, so it stays UNKNOWN.
        # (0xFF is in the vendor range and is now decoded as vendor.)
        out = wp.decode_cdb(bytes([0x0B, 0, 0, 0, 0, 0]))
        self.assertEqual(out["name"], "UNKNOWN 0x0B")

    def test_parse_device_descriptor(self):
        payload = bytes.fromhex("120100020000004011071122000101020301")
        out = wp.parse_device_descriptor(payload)
        self.assertIsNotNone(out)
        assert out is not None
        self.assertEqual(out["vid"], 0x0711)
        self.assertEqual(out["pid"], 0x2211)

    def test_parse_config_descriptor_endpoints(self):
        # Full Wormhole config descriptor from the capture (82 bytes).
        payload = bytes.fromhex(
            "0902520003010060050904000002080650000705810200020007050202000200"
            "09040100010301020009210001000122340007058303080001090402000103"
            "01010009210001000122430007058403080004")
        out = wp.parse_config_descriptor(payload)
        self.assertIsNotNone(out)
        assert out is not None
        self.assertEqual(out["total_length"], 0x52)
        self.assertEqual(out["num_interfaces"], 3)
        eps = [ep["address"] for i in out["interfaces"] for ep in i["endpoints"]]
        self.assertEqual(eps, ["0x81", "0x02", "0x83", "0x84"])

    def test_read_pcap_rejects_non_pcap(self):
        with self.assertRaises(ValueError):
            wp.read_pcap(REPO / "README.md")

    def test_read_pcap_missing_file(self):
        with self.assertRaises(OSError):
            wp.read_pcap(REPO / "captures" / "does-not-exist.pcap")


class TestSyntheticCapture(unittest.TestCase):
    SYNTH = REPO / "captures" / "wormhole_bus3_synth_2026-11-06.pcap"

    def test_synthetic_capture_vendor_hid(self):
        pcap = wp.read_pcap(self.SYNTH)
        summary = wp.summarise(pcap)
        self.assertEqual(summary["total_vendor_hid_packets"], 1)
        self.assertEqual(summary["wormhole_devices"], ["3:15"])
        info = summary["devices"]["3:15"]
        self.assertEqual(info["vendor_hid_packets"], 1)
        self.assertEqual(info["vendor_hid_types"], {"mouse": 1})
        # The synthetic packet must decode as mouse / OT footer / valid framing.
        txns = wp.parse_transactions(pcap.packets)
        vendor = [t for t in txns if t.is_vendor_hid]
        self.assertEqual(len(vendor), 1)
        d = wp.transaction_to_dict(vendor[0], pcap.first_ts or 0.0)
        self.assertEqual(d["cdb_hex"], "d933010a000000000000000000004f54")
        self.assertEqual(d["hid_type"], "mouse")
        self.assertTrue(d["footer_ok"])
        self.assertTrue(d["valid_hid_framing"])
        self.assertEqual(d["csw_status_name"], "good")

    def test_synthetic_capture_hid_idle_for_wormhole(self):
        pcap = wp.read_pcap(self.SYNTH)
        summary = wp.summarise(pcap)
        # Logitech traffic exists, but Wormhole inbound HID stays idle
        # on single-host injection (peer replay needs a real session).
        self.assertEqual(summary["devices"]["3:15"]["hid_reports"], 0)


class TestVendorHidCdb(unittest.TestCase):
    def test_decode_vendor_hid_mouse(self):
        # D9 '3' + 12-byte payload + 'OT' -- the mouse HID packet.
        cdb = bytes([0xD9, 0x33]) + bytes.fromhex("0123456789abcdef01234567") + b"OT"
        out = wp.decode_cdb(cdb)
        self.assertEqual(out["name"], "WORMHOLE VENDOR HID (0xD9)")
        self.assertEqual(out["opcode"], "0xD9")
        self.assertTrue(out["is_vendor"])
        self.assertTrue(out["is_vendor_hid"])
        self.assertEqual(out["hid_type"], "mouse")
        self.assertEqual(out["type_char"], "3")
        self.assertEqual(out["payload_hex"], "0123456789abcdef01234567")
        self.assertEqual(out["payload"], list(bytes.fromhex("0123456789abcdef01234567")))
        self.assertEqual(out["footer_hex"], "4f54")
        self.assertEqual(out["footer_ascii"], "OT")
        self.assertTrue(out["footer_ok"])
        self.assertTrue(out["valid_hid_framing"])
        self.assertEqual(out["cdb_len"], 16)

    def test_decode_vendor_hid_keyboard_and_multimedia(self):
        for char, name in ((0x34, "keyboard"), (0x36, "multimedia")):
            cdb = bytes([0xD9, char]) + bytes(12) + b"OT"
            out = wp.decode_vendor_cdb(cdb)
            self.assertEqual(out["hid_type"], name)
            self.assertTrue(out["valid_hid_framing"])

    def test_decode_vendor_hid_bad_footer(self):
        cdb = bytes([0xD9, 0x33]) + bytes(12) + b"XX"
        out = wp.decode_vendor_cdb(cdb)
        self.assertEqual(out["footer_ok"], False)
        self.assertEqual(out["valid_hid_framing"], False)

    def test_decode_vendor_hid_unknown_type(self):
        cdb = bytes([0xD9, 0x39]) + bytes(12) + b"OT"  # '9'
        out = wp.decode_vendor_cdb(cdb)
        self.assertEqual(out["hid_type"], "unknown")
        self.assertEqual(out["valid_hid_framing"], False)

    def test_decode_generic_vendor_upipe_candidate(self):
        # Non-D9 vendor opcode with a data phase -- possible UPipe.
        cdb = bytes([0xC2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 1, 0, 0])
        out = wp.decode_cdb(cdb)
        self.assertTrue(out["is_vendor"])
        self.assertFalse(out["is_vendor_hid"])
        self.assertTrue(out["candidate_upipe"])
        self.assertIn("UPipe", out["name"])

    def test_decode_vendor_non_vendor_is_empty(self):
        self.assertEqual(wp.decode_vendor_cdb(bytes.fromhex("120000002400")), {})
        self.assertEqual(wp.decode_vendor_cdb(b""), {})

    def test_build_vendor_hid_cdb_roundtrip(self):
        payload = bytes.fromhex("00112233445566778899aabb")
        cdb = wp.build_vendor_hid_cdb("4", payload)
        self.assertEqual(len(cdb), 16)
        self.assertEqual(cdb[0], 0xD9)
        self.assertEqual(cdb[1], 0x34)
        self.assertEqual(cdb[2:14], payload)
        self.assertEqual(cdb[14:16], b"OT")
        out = wp.decode_cdb(cdb)
        self.assertEqual(out["payload_hex"], payload.hex())

    def test_build_vendor_hid_cdb_multimedia_roundtrip(self):
        # '6' multimedia uses the same 16-byte framing and the payload
        # passes through raw -- its byte layout is undetermined (no
        # captured '6' frame yet), so nothing is assumed here.
        payload = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaab")
        cdb = wp.build_vendor_hid_cdb("6", payload)
        self.assertEqual(len(cdb), 16)
        self.assertEqual(cdb[0], 0xD9)
        self.assertEqual(cdb[1], 0x36)
        self.assertEqual(cdb[2:14], payload)
        self.assertEqual(cdb[14:16], b"OT")
        out = wp.decode_cdb(cdb)
        self.assertEqual(out["hid_type"], "multimedia")
        self.assertEqual(out["type_char"], "6")
        self.assertEqual(out["payload_hex"], payload.hex())
        self.assertTrue(out["valid_hid_framing"])

    def test_build_vendor_hid_cdb_multimedia_all_zero_probe(self):
        # The framing-only probe from docs/reproduction.md 6.5: an
        # all-zero multimedia frame must be built and decode cleanly.
        cdb = wp.build_vendor_hid_cdb("6", bytes(12))
        self.assertEqual(cdb.hex(), "d936" + "00" * 12 + "4f54")
        out = wp.decode_cdb(cdb)
        self.assertEqual(out["hid_type"], "multimedia")
        self.assertEqual(out["payload_hex"], "00" * 12)
        self.assertTrue(out["valid_hid_framing"])

    def test_build_vendor_hid_cdb_pads_short_payload(self):
        cdb = wp.build_vendor_hid_cdb("3", bytes([0x01]))
        self.assertEqual(cdb[2], 0x01)
        self.assertEqual(cdb[3:14], bytes(11))

    def test_build_vendor_hid_cdb_rejects_bad_type(self):
        with self.assertRaises(ValueError):
            wp.build_vendor_hid_cdb("9", b"")

    def test_transaction_vendor_flags(self):
        cbw = wp.CbW(tag=0x301, data_len=0, flags=0, lun=0,
                     cdb=wp.build_vendor_hid_cdb("3", bytes(12)),
                     frame=1, ts=0.0)
        txn = wp.Transaction(bus=3, dev=15, cbw=cbw)
        self.assertTrue(txn.is_vendor)
        self.assertTrue(txn.is_vendor_hid)
        self.assertEqual(txn.opcode_name, "WORMHOLE VENDOR HID (0xD9)")


class TestHidReports(unittest.TestCase):
    def test_decode_mouse_report(self):
        # Buttons 0x01 (left), X=+10, Y=-5, Wheel=0
        payload = bytes([0x01, 10, 251, 0])
        out = wp.decode_hid_mouse_report(payload)
        self.assertTrue(out["decoded"])
        self.assertEqual(out["kind"], "mouse")
        self.assertEqual(out["buttons"], 0x01)
        self.assertTrue(out["left"])
        self.assertFalse(out["right"])
        self.assertEqual(out["x"], 10)
        self.assertEqual(out["y"], -5)
        self.assertEqual(out["wheel"], 0)

    def test_decode_mouse_report_signed_and_buttons(self):
        payload = bytes([0x07, 0x7F, 0x80, 0xFF])  # all buttons, X=+127 Y=-128 wheel=-1
        out = wp.decode_hid_mouse_report(payload)
        self.assertTrue(out["left"] and out["right"] and out["middle"])
        self.assertEqual(out["x"], 127)
        self.assertEqual(out["y"], -128)
        self.assertEqual(out["wheel"], -1)

    def test_decode_mouse_report_short(self):
        out = wp.decode_hid_mouse_report(bytes([0x00, 0x00]))
        self.assertFalse(out["decoded"])
        self.assertIn("error", out)

    def test_decode_keyboard_report(self):
        # Modifier LShift (0x02), constant 0, keys 0x04 (A) 0x05 (B)
        payload = bytes([0x02, 0x00, 0x04, 0x05, 0, 0, 0, 0])
        out = wp.decode_hid_keyboard_report(payload)
        self.assertTrue(out["decoded"])
        self.assertEqual(out["kind"], "keyboard")
        self.assertEqual(out["modifiers"], 0x02)
        self.assertEqual(out["modifier_names"], ["LShift"])
        self.assertEqual(out["keys"], [0x04, 0x05])
        self.assertEqual(out["key_hex"], ["0x4", "0x5"])
        self.assertFalse(out["idle"])

    def test_decode_keyboard_idle(self):
        payload = bytes(8)
        out = wp.decode_hid_keyboard_report(payload)
        self.assertTrue(out["idle"])
        self.assertEqual(out["keys"], [])

    def test_decode_hid_report_dispatch(self):
        mouse = wp.decode_hid_report(3, bytes([0, 1, 2, 3]))
        kbd = wp.decode_hid_report(4, bytes(8))
        unknown = wp.decode_hid_report(9, bytes(4))
        self.assertEqual(mouse["kind"], "mouse")
        self.assertEqual(kbd["kind"], "keyboard")
        self.assertFalse(unknown["decoded"])

    def test_parse_hid_reports_filters(self):
        # Only xfer==1, kind=='C', IN direction counts.
        def pkt(kind, xfer, ep, payload, frame=1):
            return wp.UrbPacket(
                frame=frame, ts=1000.0 + frame, urb_id=frame, kind=kind,
                xfer=xfer, endpoint=ep, dev=15, bus=3,
                flag_setup=0, flag_data=0, status=0, length=len(payload),
                data_len=len(payload), setup=None, interval=0,
                transfer_flags=0, payload=payload)

        packets = [
            pkt("S", 1, 0x83, bytes(4), 1),      # submit -- ignore
            pkt("C", 1, 0x83, bytes([1, 10, 0, 0]), 2),  # mouse report
            pkt("C", 1, 0x84, bytes([0, 0, 4, 0, 0, 0, 0, 0]), 3),  # kbd
            pkt("C", 3, 0x81, b"USBC", 4),       # bulk -- ignore
            pkt("C", 1, 0x04, bytes(8), 5),      # OUT -- ignore
        ]
        reports = wp.parse_hid_reports(packets)
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0]["kind"], "mouse")
        self.assertEqual(reports[1]["kind"], "keyboard")

    def test_idle_capture_has_zero_hid_and_zero_vendor(self):
        pcap = wp.read_pcap(PCAP)
        summary = wp.summarise(pcap)
        info = summary["devices"]["3:15"]
        # Total HID reports are non-zero (Logitech 3:7 floods the bus),
        # but the Wormhole device itself must have 0 reports / 0 vendor HID.
        self.assertGreater(summary["total_hid_reports"], 0)
        self.assertEqual(info["hid_reports"], 0)
        self.assertEqual(info["vendor_hid_packets"], 0)
        self.assertEqual(info["vendor_cdb_packets"], 0)
        self.assertEqual(info["candidate_upipe_packets"], 0)

    def test_synthetic_peer_active_summary(self):
        # Build a minimal pcap-like packet list with a vendor HID CBW
        # transaction and an inbound mouse report, then summarise.
        import io
        # Construct usbmon headers manually is heavy; instead test the
        # transaction + HID integration via parse functions directly.
        cbw_payload = b"USBC" + struct.pack("<II", 0x999, 0) + bytes([0, 0, 16]) + wp.build_vendor_hid_cdb("3", bytes(12))
        cbw_payload = cbw_payload.ljust(31, b"\x00")
        cbw = wp.parse_cbw(cbw_payload)
        assert cbw is not None
        txn = wp.Transaction(bus=3, dev=15, cbw=cbw,
                             csw=wp.CsW(tag=0x999, residue=0, status=0, frame=2, ts=1.0))
        d = wp.transaction_to_dict(txn, 0.0)
        self.assertTrue(d["is_vendor_hid"])
        self.assertEqual(d["hid_type"], "mouse")
        self.assertEqual(d["vendor_hid_type"], "mouse")


if __name__ == "__main__":
    unittest.main(verbosity=2)
