#!/usr/bin/env python3
"""Tests for tools/capacity_anomaly.py (issue #13 capacity anomaly).

Run from the repo root, stdlib only:

    python3 -m unittest tools.test_capacity_anomaly -v
    # or
    python3 tools/test_capacity_anomaly.py

The expected values are the recorded evidence in docs/transport.md,
docs/capture-log.md, docs/reproduction.md and docs/iso-payload.md.  If one
changes, either the docs are wrong or the firmware changed -- do not just
update the expected value.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capacity_anomaly as ca  # noqa: E402


class TestRecordedDeviceView(unittest.TestCase):
    def test_steady_state_read_capacity_decode(self):
        rc = ca.parse_read_capacity(ca.RC10_RESPONSE)
        self.assertEqual(rc["last_lba"], 1592)
        self.assertEqual(rc["block_len"], 2048)
        self.assertEqual(rc["blocks"], 1593)
        self.assertEqual(rc["device_bytes"], 3262464)

    def test_read_capacity_short_data_phase_rejected(self):
        with self.assertRaises(ValueError):
            ca.parse_read_capacity(b"\x00" * 7)


class TestKernelMath(unittest.TestCase):
    def test_kernel_path_on_recorded_response(self):
        # sr.c: capacity = (1 + 1592) * 4 = 6372 sectors of 512 B.
        self.assertEqual(ca.sr_capacity_512b(1592, 2048), 6372)

    def test_kernel_path_disagrees_with_observed_sysfs(self):
        # The recorded response cannot be the source of the cached size.
        self.assertNotEqual(ca.sr_capacity_512b(1592, 2048),
                            ca.SYSFS_SIZE_512B)

    def test_kernel_conversion_preserves_device_bytes(self):
        # (1 + last_lba) * 2048 == capacity_512b * 512 for 2048 B sectors.
        self.assertEqual(ca.sr_capacity_512b(1592, 2048) * 512, 3262464)

    def test_512_byte_sectors_pass_through(self):
        self.assertEqual(ca.sr_capacity_512b(3, 512), 4)

    def test_quirk_block_sizes_remapped_to_2048(self):
        # sr.c remaps 0/2340/2352 to 2048 before the *4 conversion.
        for block_len in (0, 2340, 2352):
            self.assertEqual(ca.sr_capacity_512b(1592, block_len), 6372)

    def test_unsupported_block_size_zeroes_capacity(self):
        self.assertIsNone(ca.sr_capacity_512b(1592, 4096))
        self.assertIsNone(ca.sr_capacity_512b(1592, 1024))

    def test_fallback_capacity_is_not_the_observed_size(self):
        # sr.c failure path: 0x1fffff blocks x 2048 B -> *4.
        self.assertEqual(ca.sr_fallback_capacity_512b(), 0x1FFFFF * 4)
        self.assertNotEqual(ca.sr_fallback_capacity_512b(),
                            ca.SYSFS_SIZE_512B)


class TestCandidateEnumerationResponses(unittest.TestCase):
    def test_iso_size_consistency(self):
        # 15.5 MiB three ways: sysfs sectors, ISO bytes, 7936 x 2048 B.
        self.assertEqual(ca.ISO_BYTES, ca.SYSFS_SIZE_512B * 512)
        self.assertEqual(ca.ISO_BYTES, 7936 * 2048)

    def test_candidates_reproduce_sysfs_size_through_kernel_path(self):
        for c in ca.responses_producing_sysfs_size():
            self.assertEqual(
                ca.sr_capacity_512b(c["last_lba"], c["block_len"]),
                ca.SYSFS_SIZE_512B)
            self.assertEqual(c["device_bytes"], ca.ISO_BYTES)

    def test_candidates_raw_bytes(self):
        raws = {c["raw"] for c in ca.responses_producing_sysfs_size()}
        self.assertIn("00001eff00000800", raws)  # last LBA 7935 / 2048 B
        self.assertIn("00007bff00000200", raws)  # last LBA 31743 / 512 B
        self.assertNotIn(ca.RC10_RESPONSE.hex(), raws)

    def test_predicted_cold_plug_response_evaluates_to_sysfs_size(self):
        rc = ca.parse_read_capacity(bytes.fromhex("00001eff00000800"))
        self.assertEqual(rc["device_bytes"], ca.ISO_BYTES)
        self.assertEqual(ca.sr_capacity_512b(rc["last_lba"],
                                             rc["block_len"]),
                         ca.SYSFS_SIZE_512B)

    def test_no_candidate_matches_the_steady_state_response(self):
        rc = ca.parse_read_capacity(ca.RC10_RESPONSE)
        steady = {"last_lba": rc["last_lba"], "block_len": rc["block_len"]}
        for c in ca.responses_producing_sysfs_size():
            self.assertNotEqual(
                (c["last_lba"], c["block_len"]),
                (steady["last_lba"], steady["block_len"]))


class TestCannedResponseQuirks(unittest.TestCase):
    def test_toc_identical_for_lba_and_msf_formats(self):
        self.assertEqual(ca.decode_toc(ca.TOC_FMT0),
                         ca.decode_toc(ca.TOC_FMT2))

    def test_toc_decode(self):
        toc = ca.decode_toc(ca.TOC_FMT0)
        self.assertEqual(toc["toc_length"], 0x0012)
        self.assertEqual(toc["first_track"], 1)
        self.assertEqual(toc["last_track"], 1)
        self.assertEqual(toc["track_desc"]["track"], 1)
        self.assertEqual(toc["track_desc"]["adr_control"], 0x14)
        self.assertEqual(toc["track_desc"]["start_lba"], 0x200)

    def test_get_configuration_current_profile_is_cd_rom(self):
        gc = ca.decode_get_configuration(ca.GET_CONFIG)
        self.assertEqual(gc["current_profile"], 0x000A)
        self.assertEqual(gc["profile_list_feature"], 0x0000)
        profiles = {p["profile"] for p in gc["profiles"]}
        self.assertIn(0x000A, profiles)  # CD-ROM
        self.assertIn(0x0008, profiles)
        self.assertIn(0x0009, profiles)

    def test_read_capacity_16_unsupported(self):
        self.assertEqual(ca.RC16_SENSE_KEY, 0x05)
        self.assertEqual(ca.RC16_ASC, 0x20)


class TestAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = ca.analyse()

    def test_views(self):
        self.assertEqual(self.a["device_view"]["bytes"], 3262464)
        self.assertEqual(self.a["kernel_view"]["sysfs_512b_sectors"], 31744)
        self.assertEqual(self.a["kernel_view"]["bytes"], ca.ISO_BYTES)
        self.assertTrue(self.a["kernel_view"]["matches_iso_bytes"])

    def test_kernel_derivation_and_fallback_ruled_out(self):
        self.assertEqual(
            self.a["kernel_from_recorded_response"]["sectors_512b"], 6372)
        self.assertFalse(
            self.a["kernel_from_recorded_response"]["matches_sysfs"])
        self.assertFalse(self.a["fallback"]["matches_sysfs"])

    def test_candidates_and_verdict(self):
        self.assertEqual(len(self.a["candidate_enumeration_responses"]), 2)
        self.assertTrue(self.a["quirk_evidence"]
                        ["toc_format0_equals_format2"])
        self.assertIn("firmware", self.a["verdict"])


class TestRc10Override(unittest.TestCase):
    def test_override_matches_sysfs(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = ca.main(["--rc10", "00001eff00000800"])
        self.assertEqual(code, 0)
        self.assertIn("MATCHES", buf.getvalue())

    def test_override_json(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = ca.main(["--rc10", "0000063800000800", "--json"])
        self.assertEqual(code, 0)
        data = __import__("json").loads(buf.getvalue())
        self.assertEqual(data["parse"]["last_lba"], 1592)
        self.assertEqual(data["kernel_sectors_512b"], 6372)
        self.assertFalse(data["matches_sysfs_31744"])

    def test_override_invalid_hex_fails(self):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ca.main(["--rc10", "zz"])
        self.assertEqual(code, 2)
        self.assertIn("invalid --rc10 hex", err.getvalue())


if __name__ == "__main__":
    unittest.main()
