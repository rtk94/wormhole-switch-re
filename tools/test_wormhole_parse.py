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
        # #17: committed capture is now the Wormhole-only (3:15) filtered
        # subset (250 packets); the original mixed-bus 2,298-packet file
        # remains in git history until a history rewrite is approved.
        self.assertEqual(len(self.pcap.packets), 250)
        self.assertEqual(
            self.pcap.sha256,
            "5a135f4dc9df9cd69bcd4f3829a48a5232e6d2e1523bafb4a592905c2962b25b")
        self.assertEqual(self.pcap.linktype, 220)
        self.assertAlmostEqual(self.pcap.duration, 28.370474, places=3)

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
        # #17: the committed capture is now Wormhole-only — the Logitech
        # device (3:7, 1,682 interrupt completions in the original mixed
        # capture) is gone, so the Wormhole must have zero interrupt traffic
        # and no other device may be present.
        summary = self.summary
        for key, dev in summary["devices"].items():
            if dev["is_wormhole"]:
                self.assertEqual(dev["by_xfer"].get("interrupt", 0), 0)
        self.assertEqual(set(summary["devices"].keys()), {"3:15"})

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
        # Wormhole inbound HID stays idle
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
        # #17: the sanitised capture is Wormhole-only, so total HID reports
        # for the file are zero; the Wormhole device itself must have 0
        # reports / 0 vendor HID. (In the original mixed capture the
        # 841 total HID reports were all Logitech 3:7.)
        self.assertEqual(summary["total_hid_reports"], 0)
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


class TestHidSendPairing(unittest.TestCase):
    """Unit tests for pair_hid_reports_to_sends (issue #15).

    A Wormhole HID report at one cable end is caused by an accepted
    16-byte 0xD9 send submitted at the other end, so the pairing walk
    matches sends to reports FIFO on (HID type, payload bytes) across
    devices and flags unmatched reports as orphans.
    """

    def _hid(self, ep, payload, frame, ts, bus=3, dev=15):
        return wp.UrbPacket(
            frame=frame, ts=ts, urb_id=frame, kind="C", xfer=1,
            endpoint=0x80 | ep, dev=dev, bus=bus, flag_setup=0,
            flag_data=0, status=0, length=len(payload),
            data_len=len(payload), setup=None, interval=0,
            transfer_flags=0, payload=payload)

    def _cbw(self, tag, cdb, frame, ts, bus=3, dev=15):
        payload = (b"USBC" + struct.pack("<II", tag, 0)
                   + bytes([0, 0, len(cdb)]) + cdb).ljust(31, b"\x00")
        return wp.UrbPacket(
            frame=frame, ts=ts, urb_id=frame, kind="S", xfer=3,
            endpoint=0x02, dev=dev, bus=bus, flag_setup=0, flag_data=0,
            status=-115, length=31, data_len=len(payload), setup=None,
            interval=0, transfer_flags=0, payload=payload)

    def _csw(self, tag, status, frame, ts, bus=3, dev=15):
        payload = b"USBS" + struct.pack("<II", tag, 0) + bytes([status])
        return wp.UrbPacket(
            frame=frame, ts=ts, urb_id=frame, kind="C", xfer=3,
            endpoint=0x81, dev=dev, bus=bus, flag_setup=0, flag_data=0,
            status=0, length=13, data_len=len(payload), setup=None,
            interval=0, transfer_flags=0, payload=payload)

    def _send(self, hid_type, payload, frame, ts, tag=0x100, status=0,
              bus=3, dev=15):
        """One 0xD9 send as a CBW/CSW pair; status 0 = accepted."""
        cdb = wp.build_vendor_hid_cdb(hid_type, payload)
        return [self._cbw(tag, cdb, frame, ts, bus, dev),
                self._csw(tag, status, frame + 2, ts + 0.001, bus, dev)]

    def _mouse_report(self, x, frame, ts, bus=3, dev=15):
        return self._hid(3, bytes([0, x & 0xFF, 0, 0]), frame, ts, bus, dev)

    def test_accepted_send_pairs_with_report(self):
        # The send is at the other cable end (bus 1); a host's own send
        # on the same device never echoes back as a report.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.0,
                              bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.002)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(out["accepted_sends"], 1)
        self.assertEqual(out["reports"], 1)
        self.assertEqual(len(out["pairs"]), 1)
        self.assertEqual(len(out["orphans"]), 0)
        self.assertEqual(len(out["unpaired_sends"]), 0)
        pair = out["pairs"][0]
        self.assertEqual(pair["report"]["hex"], "003c0000")
        self.assertEqual(pair["send_frame"], 10)
        self.assertEqual(pair["send_payload_hex"],
                         "003c00000000000000000000")
        self.assertAlmostEqual(pair["gap_s"], 0.002, places=6)

    def test_rejected_send_never_pairs(self):
        # Re-run P4: a CHECK CONDITION (15-byte) send is rejected and
        # forwards nothing, so the following report has no sender here.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.0,
                              status=1, bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.002)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(out["accepted_sends"], 0)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(out["orphans"][0]["hex"], "003c0000")

    def test_orphan_report_without_any_send(self):
        # The bus3_live2 shape (#15): one EP3 x=+60 report, no 0xD9
        # anywhere in the capture -- an orphan, i.e. peer-side input.
        packets = [self._mouse_report(0x3C, 849, 100.0)]
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(out["device_keys"], ["main 3:15"])
        self.assertEqual(out["accepted_sends"], 0)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(out["orphans"][0]["frame"], 849)
        self.assertEqual(out["orphans"][0]["x"], 60)

    def test_value_mismatch_is_orphan(self):
        packets = (self._send("3", bytes([0x00, 0x0A]), 10, 100.0,
                              bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.002)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(len(out["unpaired_sends"]), 1)

    def test_type_mismatch_is_orphan(self):
        # A keyboard send cannot cause a mouse report (type byte '3' vs
        # '4' and EP3 vs EP4 must agree).
        packets = (self._send("4", bytes([0x00, 0x00, 0x04]), 10, 100.0,
                              bus=1, dev=6)
                   + [self._mouse_report(0x00, 20, 100.002)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(out["orphans"][0]["kind"], "mouse")

    def test_report_before_send_stays_orphan(self):
        # The reviewer's repro: a matching send AFTER the report cannot
        # have caused it -- pairing stays off regardless of FIFO order.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.100,
                              bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.0)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(len(out["unpaired_sends"]), 1)

    def test_stale_send_outside_window_stays_orphan(self):
        # A matching send far older than the window (here 1 s; observed
        # merged pairs span -0.56 to +2.02 ms) is not a plausible cause:
        # orphan.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 99.0,
                              bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.0)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(len(out["unpaired_sends"]), 1)

    def test_send_within_window_pairs_and_gap_is_positive(self):
        # 40 ms is inside the 50 ms forward window: it pairs.  Gaps are
        # signed (the negative-gap case below pairs at -8 ms); this one
        # happens to be positive.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 99.960,
                              bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.0)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 1)
        self.assertAlmostEqual(out["pairs"][0]["gap_s"], 0.040, places=6)

    def test_peer_offset_corrects_report_clock(self):
        # The report host's clock runs ahead: the report is stamped
        # 60 ms after its send, outside the 50 ms window.  A known
        # +60 ms correction (subtracted from report timestamps) pairs
        # it, and the reported gap is the corrected one.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.0,
                              bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.060)])
        self.assertEqual(len(wp.pair_hid_reports_to_sends(packets)["pairs"]), 0)
        out = wp.pair_hid_reports_to_sends(packets, peer_offset=0.060)
        self.assertEqual(len(out["pairs"]), 1)
        self.assertAlmostEqual(out["pairs"][0]["gap_s"], 0.0, places=6)
        self.assertEqual(out["peer_offset_source"], "flag")
        self.assertAlmostEqual(out["peer_offset_s"], 0.060, places=9)

    def test_offset_estimate_recovers_synthetic_skew(self):
        # All sends on one host, all reports on the other; the report
        # host's clock runs ~70 ms ahead, so every raw gap leaves the
        # window.  Zero-offset pairing finds nothing; auto-estimation
        # finds a correcting offset in the grid and pairs 10/10.  (The
        # estimator returns the least correction consistent with the
        # data -- the pairing window is 60 ms wide, so the recovered
        # value need not equal the planted skew exactly.)
        sends = []
        reports = []
        for i in range(10):
            x = 0x10 + i
            sends += self._send("3", bytes([0x00, x]), 10 + i * 10,
                                100.0 + i * 0.05, bus=1, dev=6)
            reports.append(self._mouse_report(
                x, 20 + i * 10, 100.0 + i * 0.05 + 0.0013 + 0.070,
                bus=3, dev=15))
        merged = sorted(sends + reports, key=lambda p: p.ts)
        zero = wp.pair_hid_reports_to_sends(merged)
        self.assertEqual(len(zero["pairs"]), 0)
        est = wp.pair_hid_reports_to_sends(merged, estimate_offset=True)
        self.assertEqual(est["peer_offset_source"], "estimated")
        self.assertGreaterEqual(est["peer_offset_s"], -0.100)
        self.assertLessEqual(est["peer_offset_s"], 0.100)
        self.assertEqual(len(est["pairs"]), 10)

    def test_in_window_negative_gap_pairs(self):
        # An 8 ms early report is within the clock-skew allowance: it
        # pairs, and the gap is reported negative.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.008,
                              bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.0)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 1)
        self.assertAlmostEqual(out["pairs"][0]["gap_s"], -0.008, places=6)

    def test_gap_just_outside_forward_bound_stays_orphan(self):
        # +60 ms is just outside the 50 ms forward bound: orphan, so
        # widening PAIR_WINDOW_S to 0.9 no longer passes the suite.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 99.940,
                              bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.0)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(len(out["unpaired_sends"]), 1)

    def test_gap_just_outside_backward_bound_stays_orphan(self):
        # -20 ms is just outside the 10 ms skew bound: orphan, so
        # widening PAIR_SKEW_S to 0.09 no longer passes the suite.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.020,
                              bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.0)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(len(out["unpaired_sends"]), 1)

    def test_same_device_send_never_pairs(self):
        # The reviewer's repro: a local accepted send followed 2 ms
        # later by a matching report on the same device is not a pair --
        # a host's own send never echoes back, so the report stays an
        # orphan (genuine peer-side input keeps its orphan status).
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.0)
                   + [self._mouse_report(0x3C, 20, 100.002)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(len(out["unpaired_sends"]), 1)

    def test_send_is_consumed_one_to_one(self):
        # Two identical reports but one send: the second report stays
        # unmatched instead of reusing the consumed send.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.0,
                              bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.002),
                      self._mouse_report(0x3C, 30, 100.004)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 1)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(len(out["unpaired_sends"]), 0)

    def test_fifo_consumes_earliest_send(self):
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.0,
                              tag=0x101, bus=1, dev=6)
                   + self._send("3", bytes([0x00, 0x3C]), 14, 100.1,
                                tag=0x102, bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.002)])
        out = wp.pair_hid_reports_to_sends(packets)
        self.assertEqual(len(out["pairs"]), 1)
        self.assertEqual(out["pairs"][0]["send_frame"], 10)
        self.assertEqual(out["unpaired_sends"][0]["frame"], 14)

    def test_cross_device_pairing_for_merged_ends(self):
        # The two cable ends enumerate as different bus:dev numbers;
        # on merged both-ends packets a report pairs across devices.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.0, bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.002)])
        out = wp.pair_hid_reports_to_sends(
            packets,
            device_keys={("main", 1, 6), ("main", 3, 15)})
        self.assertEqual(out["device_keys"],
                         ["main 1:6", "main 3:15"])
        self.assertEqual(len(out["pairs"]), 1)
        self.assertEqual(out["pairs"][0]["send_bus"], 1)
        self.assertEqual(out["pairs"][0]["report"]["bus"], 3)

    def test_fallback_scoping_without_enumeration(self):
        # No control enumeration in the packets: scoping falls back to
        # the devices the accepted 0xD9 sends and EP3/EP4 reports point
        # at, so the pairing still works.
        packets = (self._send("3", bytes([0x00, 0x3C]), 10, 100.0, bus=1, dev=6)
                   + [self._mouse_report(0x3C, 20, 100.002)])
        out = wp.pair_hid_reports_to_sends(packets, device_keys=None)
        self.assertEqual(out["device_keys"],
                         ["main 1:6", "main 3:15"])
        self.assertEqual(len(out["pairs"]), 1)


class TestHidSendPairingCaptures(unittest.TestCase):
    """Issue #15 against the committed peer-active captures.

    live3 (local end) and bus1_live (peer end) are the two halves of the
    same session; the re-run is the local half of a later peer-side
    sequence whose sends tools/peer_rerun_send.py logged on the peer.
    """

    LIVE3 = REPO / "captures" / "wormhole_bus3_live3_2026-11-06.pcap"
    BUS1 = REPO / "captures" / "wormhole_bus1_live_2026-11-06.pcap"
    RERUN = REPO / "captures" / "wormhole_bus3_rerun_2026-11-06.pcap"

    @classmethod
    def setUpClass(cls):
        cls.live3 = wp.read_pcap(cls.LIVE3)
        cls.bus1 = wp.read_pcap(cls.BUS1, capture_id="peer")
        cls.rerun = wp.read_pcap(cls.RERUN)
        cls.live3_pairing = wp.pair_hid_reports_to_sends(cls.live3.packets)
        cls.bus1_pairing = wp.pair_hid_reports_to_sends(cls.bus1.packets)
        merged = sorted(cls.live3.packets + cls.bus1.packets,
                        key=lambda p: p.ts)
        cls.merged_pairing = wp.pair_hid_reports_to_sends(merged)
        cls.rerun_pairing = wp.pair_hid_reports_to_sends(cls.rerun.packets)

    def test_live3_x60_report_is_an_orphan_locally(self):
        # 9 local accepted sends (x=+10/+20/+30, click, keyboard) plus
        # one EP3 x=+60 report whose sender is not in this capture.
        out = self.live3_pairing
        self.assertEqual(out["device_keys"], ["main 3:15"])
        self.assertEqual(out["accepted_sends"], 9)
        self.assertEqual(out["reports"], 1)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 1)
        self.assertEqual(len(out["unpaired_sends"]), 9)
        orphan = out["orphans"][0]
        self.assertEqual(orphan["frame"], 131)
        self.assertEqual(orphan["hex"], "003c0000")
        self.assertEqual(orphan["x"], 60)

    def test_bus1_only_accepted_send_is_mouse60(self):
        # The peer end sent 8 CDBs, 7 arrived 15-byte and were rejected;
        # the one accepted send is mouse x=+60 (16-byte framing).
        out = self.bus1_pairing
        self.assertEqual(out["device_keys"], ["peer 1:6"])
        self.assertEqual(out["accepted_sends"], 1)
        self.assertEqual(out["reports"], 9)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 9)
        unpaired = out["unpaired_sends"][0]
        self.assertEqual(unpaired["frame"], 131)
        self.assertEqual(unpaired["hid_type"], "mouse")
        self.assertEqual(unpaired["payload_hex"],
                         "003c00000000000000000000")

    def test_merged_ends_pair_one_to_one(self):
        # Merging both cable ends: 10/10 reports pair with accepted
        # sends across devices, in order, gaps within a few ms of clock
        # skew.  The x=+60 report's sender is the peer's frame-131 send.
        out = self.merged_pairing
        self.assertEqual(out["device_keys"], ["main 3:15", "peer 1:6"])
        self.assertEqual(out["accepted_sends"], 10)
        self.assertEqual(out["reports"], 10)
        self.assertEqual(len(out["pairs"]), 10)
        self.assertEqual(len(out["orphans"]), 0)
        self.assertEqual(len(out["unpaired_sends"]), 0)
        x60 = [p for p in out["pairs"] if p["report"]["hex"] == "003c0000"]
        self.assertEqual(len(x60), 1)
        self.assertEqual((x60[0]["send_bus"], x60[0]["send_dev"]), (1, 6))
        self.assertEqual(x60[0]["send_frame"], 131)
        self.assertLess(abs(x60[0]["gap_s"]), 0.005)
        for p in out["pairs"]:
            self.assertLess(abs(p["gap_s"]), 0.005)

    def test_rerun_orphans_match_the_peer_send_log(self):
        # Single-sided local capture: all 12 reports are orphans here;
        # their senders are the 12 accepted P1-P3 sends the peer logged
        # via tools/peer_rerun_send.py (M+1, M-1, MZ, KZ per phase).
        out = self.rerun_pairing
        self.assertEqual(out["device_keys"], ["main 3:15"])
        self.assertEqual(out["accepted_sends"], 0)
        self.assertEqual(out["reports"], 12)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 12)
        want = [("mouse", "00010000"), ("mouse", "00ff0000"),
                ("mouse", "00000000"), ("keyboard", "0000000000000000")] * 3
        got = [(r["kind"], r["hex"]) for r in out["orphans"]]
        self.assertEqual(got, want)

    def test_idle_capture_wormhole_has_no_orphans(self):
        # VID:PID scoping keeps the Logitech receiver's 841 EP2 reports
        # out: the Wormhole had no reports and no 0xD9 sends at all.
        pcap = wp.read_pcap(PCAP)
        out = wp.pair_hid_reports_to_sends(pcap.packets)
        self.assertEqual(out["device_keys"], ["main 3:15"])
        self.assertEqual(out["accepted_sends"], 0)
        self.assertEqual(out["reports"], 0)
        self.assertEqual(len(out["pairs"]), 0)
        self.assertEqual(len(out["orphans"]), 0)

    def test_same_bus_dev_across_captures_still_pairs(self):
        # rtk94's remap repro: the peer capture enumerates the SAME
        # bus:dev numbers as live3.  Device identity is per capture
        # ((capture_id, bus, dev)), so this still pairs 10/10; a
        # bus:dev-only identity silently dropped it to 0.
        from dataclasses import replace
        remapped = [replace(p, bus=3, dev=15) for p in self.bus1.packets]
        merged = sorted(self.live3.packets + remapped, key=lambda p: p.ts)
        out = wp.pair_hid_reports_to_sends(merged)
        self.assertEqual(len(out["pairs"]), 10)
        self.assertEqual(len(out["orphans"]), 0)

    def test_one_capture_without_enumeration_still_pairs(self):
        # rtk94's 2026-11-11 review, fallback table: if one end's capture
        # has no control transfers, the old all-or-nothing fallback
        # dropped that end's device and every report became an orphan.
        # The fallback is per capture now: stripping bus1_live's
        # enumeration still pairs 10/10.
        stripped = [p for p in self.bus1.packets if p.xfer != 2]
        merged = sorted(self.live3.packets + stripped, key=lambda p: p.ts)
        out = wp.pair_hid_reports_to_sends(merged)
        self.assertEqual(out["device_keys"],
                         ["main 3:15", "peer 1:6"])
        self.assertEqual(len(out["pairs"]), 10)
        self.assertEqual(len(out["orphans"]), 0)

    def test_main_host_device_at_peer_bus_dev_is_excluded(self):
        # rtk94's 2026-11-11 review, cross-capture ambiguity: another
        # HID device sitting at the peer cable's bus:dev on the MAIN
        # host must stay out of the pairing.  Its reports decode fine,
        # so only the per-capture key scoping keeps it out.
        impostor = wp.UrbPacket(
            frame=500, ts=100.5, urb_id=500, kind="C", xfer=1,
            endpoint=0x83, dev=6, bus=1, flag_setup=0, flag_data=0,
            status=0, length=4, data_len=4, setup=None, interval=0,
            transfer_flags=0, payload=bytes([0, 0x7F, 0, 0]))
        merged = sorted(
            self.live3.packets + self.bus1.packets + [impostor],
            key=lambda p: p.ts)
        out = wp.pair_hid_reports_to_sends(merged)
        self.assertEqual(out["reports"], 10)  # impostor not analysed
        self.assertEqual(len(out["pairs"]), 10)
        self.assertEqual(len(out["orphans"]), 0)
        self.assertEqual(out["device_keys"],
                         ["main 3:15", "peer 1:6"])

    def test_report_clock_shift_table(self):
        # rtk94's shift table, reproduced on the committed captures:
        # shifting bus1_live (the report end) by Delta and pairing at
        # offset 0 is exactly "pairing failing in a way that looks like
        # skew".  Measured: 10 / 9 / 1 / 0 pairs at 0 / +12 / -20 /
        # +100 ms.
        from dataclasses import replace
        measured = {0.0: 10, 0.012: 9, -0.020: 1, 0.100: 0}
        for delta, expected in sorted(measured.items()):
            shifted = [replace(p, ts=p.ts + delta) for p in self.bus1.packets]
            merged = sorted(self.live3.packets + shifted,
                            key=lambda p: p.ts)
            out = wp.pair_hid_reports_to_sends(merged)
            self.assertEqual(len(out["pairs"]), expected,
                             "shift %r ms" % (delta * 1000.0))
            # and the failure is recoverable: correcting the peer
            # capture's clock re-pairs 10/10 for every shift in the table
            est = wp.pair_hid_reports_to_sends(
                merged, estimate_offset=True, peer_capture_id="peer")
            self.assertEqual(len(est["pairs"]), 10,
                             "recovery at shift %r ms" % (delta * 1000.0))

    def test_cli_peer_flag_pairs_two_captures(self):
        # --peer replaces the external mergecap step: the two halves of
        # the 2026-11-08 session pair directly from the CLI.
        import contextlib
        import io as _io
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = wp.main([str(self.LIVE3), "--orphans", "--peer",
                          str(self.BUS1), "--json"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(len(out["hid_send_pairing"]["pairs"]), 10)

    def test_orphan_wording_is_neutral(self):
        # rtk94: a single-sided orphan must not claim the sender is at
        # the other cable end -- state the absence, not an origin.
        blob = "\n".join(wp._fmt_pairing(self.live3_pairing))
        self.assertIn(
            "no matching accepted 0xD9 send in the analysed packets", blob)
        self.assertNotIn("other cable end", blob)

    def test_pairing_output_is_json_serialisable(self):
        blob = json.dumps(self.merged_pairing, sort_keys=True)
        self.assertIn("003c0000", blob)
        self.assertIn("send_payload_hex", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
