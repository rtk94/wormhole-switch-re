#!/usr/bin/env python3
"""Capacity anomaly analysis for the WormholeSwitch fake CD-ROM (issue #13).

Why does ``READ CAPACITY(10)`` advertise 1593 x 2048 B (3.1 MiB) while Linux
exposes ``/sys/block/srX/size`` = 31744 x 512 B (15.5 MiB) and mounts a
15.5 MiB ISO9660 volume?

This tool replays the Linux ``drivers/scsi/sr.c`` ``get_sectorsize()`` math
against the recorded evidence (docs/transport.md, docs/capture-log.md,
docs/iso-payload.md) and shows:

  * the recorded steady-state ``READ CAPACITY(10)`` response produces a
    gendisk capacity of 6372 (512 B units) -- not the observed 31744;
  * the kernel's failure fallback (``0x1fffff`` blocks, sector_size 2048)
    produces 8388604 -- also not 31744;
  * the only enumeration-time responses that the kernel path maps to
    exactly 31744 are ``last LBA 7935 / 2048 B`` and ``last LBA 31743 /
    512 B`` -- both a 16,252,928 B device view, i.e. exactly the ISO
    volume size.

Verdict: firmware state-dependent capacity (quirk).  The kernel cached the
15.5 MiB size from the cold-plug enumeration response; the firmware then
reports a truncated 3.1 MiB capacity in steady state.  The predicted
cold-plug data phase is ``00 00 1e ff 00 00 08 00`` (or ``00 00 7b ff 00
00 02 00``) -- hardware-gated byte-level confirmation pending.

Run from the repo root (stdlib only):

    python3 tools/capacity_anomaly.py            # human-readable analysis
    python3 tools/capacity_anomaly.py --json     # machine-readable
    python3 tools/capacity_anomaly.py --rc10 00001eff00000800
                                                 # evaluate any captured
                                                 # READ CAPACITY(10) data
                                                 # phase through the kernel
                                                 # path
"""

from __future__ import annotations

import argparse
import json
import sys

# ---------------------------------------------------------------------------
# Recorded evidence (all values appear verbatim in docs/)
# ---------------------------------------------------------------------------

# Steady-state READ CAPACITY(10) data phase (docs/transport.md,
# docs/capture-log.md: live sg_raw == sg_readcap == capture f1355).
RC10_RESPONSE = bytes.fromhex("0000063800000800")

# /sys/block/srX/size as observed on the capture host (docs/transport.md,
# docs/reproduction.md): 31744 sectors of 512 B = 16,252,928 B = 15.5 MiB.
SYSFS_SIZE_512B = 31744

# WORMHOLE ISO9660 volume / block-device size (docs/iso-payload.md).
ISO_BYTES = 16252928

# READ CAPACITY(16) (0x9E sa 0x10) sense: Illegal Request / Invalid opcode.
RC16_SENSE_KEY = 0x05
RC16_ASC = 0x20

# READ TOC/PMA/ATIP payload -- identical bytes returned for format 0 (LBA)
# and format 2 (MSF), a canned firmware response (capture f1385/f1391).
TOC_FMT0 = bytes.fromhex("001201010014010000000200")
TOC_FMT2 = bytes.fromhex("001201010014010000000200")
TOC_ALLOCATION_LENGTH = 12

# GET CONFIGURATION/Feature List payload, 32-byte allocation (capture f1399).
GET_CONFIG = bytes.fromhex(
    "000000840000000a0000030c0008000000090000000a01000001030400000002")

# drivers/scsi/sr.c get_sectorsize() failure path: READ CAPACITY error ->
# cd->capacity = 0x1fffff, sector_size = 2048 (Linux master, 2026).
SR_FALLBACK_CAPACITY_BLOCKS = 0x1FFFFF

VERDICT = "firmware state-dependent capacity (quirk)"


# ---------------------------------------------------------------------------
# READ CAPACITY(10) decode + Linux sr.c replay
# ---------------------------------------------------------------------------

def parse_read_capacity(raw: bytes) -> dict:
    """Decode the 8-byte READ CAPACITY(10) data phase."""
    if len(raw) < 8:
        raise ValueError(
            "READ CAPACITY(10) data phase must be 8 bytes, got %d" % len(raw))
    last_lba = int.from_bytes(raw[0:4], "big")
    block_len = int.from_bytes(raw[4:8], "big")
    return {
        "last_lba": last_lba,
        "block_len": block_len,
        "blocks": last_lba + 1,
        "device_bytes": (last_lba + 1) * block_len,
    }


def sr_capacity_512b(last_lba: int, block_len: int) -> int | None:
    """Replay drivers/scsi/sr.c get_sectorsize() for a successful READ
    CAPACITY(10) and return the gendisk capacity in 512 B units (what
    /sys/block/srX/size shows), or None for an unsupported sector size.

    Kernel logic (Linux master):

        cd->capacity = 1 + get_unaligned_be32(&buffer[0]);
        switch (sector_size) {          # buffer[4..7] big-endian
        case 0: case 2340: case 2352:
            sector_size = 2048;         # fallthrough
        case 2048:
            cd->capacity *= 4;
            fallthrough;
        case 512:
            break;
        default:
            "unsupported sector size"; cd->capacity = 0;
        }
        set_capacity(cd->disk, cd->capacity);

    The cdrom_get_last_written() UDF correction is not applied here; it can
    only raise the capacity to the leadout address, and the recorded TOC
    payload cannot supply >= 31744 (see decode_toc()).
    """
    capacity = 1 + last_lba
    if block_len in (0, 2340, 2352):
        block_len = 2048
    if block_len == 2048:
        capacity *= 4
    elif block_len != 512:
        return None
    return capacity


def sr_fallback_capacity_512b() -> int:
    """Capacity the kernel caches when READ CAPACITY(10) fails outright."""
    return SR_FALLBACK_CAPACITY_BLOCKS * 4  # sector_size 2048 -> *4


def responses_producing_sysfs_size(
        sysfs_size: int = SYSFS_SIZE_512B) -> list[dict]:
    """Every supported (last_lba, block_len) READ CAPACITY(10) answer whose
    kernel path yields exactly ``sysfs_size`` /sys/size sectors, with the
    raw data-phase bytes it would appear as on the wire."""
    candidates = []
    for block_len, per_512 in ((512, 1), (2048, 4)):
        if sysfs_size % per_512:
            continue
        blocks = sysfs_size // per_512
        last_lba = blocks - 1
        raw = (last_lba.to_bytes(4, "big") + block_len.to_bytes(4, "big"))
        candidates.append({
            "last_lba": last_lba,
            "block_len": block_len,
            "blocks": blocks,
            "device_bytes": blocks * block_len,
            "raw": raw.hex(),
        })
    return candidates


# ---------------------------------------------------------------------------
# Supporting canned-response decodes (quirk evidence)
# ---------------------------------------------------------------------------

def decode_toc(raw: bytes = TOC_FMT0) -> dict:
    """Decode the truncated READ TOC/PMA/ATIP response (12-byte allocation).

    Header: TOC data length (2 B), first track, last track; then the first
    8-byte track descriptor (session, ADR/control, track, reserved,
    4-byte start address).
    """
    desc = raw[4:12]
    return {
        "toc_length": int.from_bytes(raw[0:2], "big"),
        "first_track": raw[2],
        "last_track": raw[3],
        "track_desc": {
            "session": desc[0],
            "adr_control": desc[1],
            "track": desc[2],
            "start_lba": int.from_bytes(desc[4:8], "big"),
        },
    }


def decode_get_configuration(raw: bytes = GET_CONFIG) -> dict:
    """Decode the truncated GET CONFIGURATION/Feature List response.

    Header: list length (4 B), reserved (2 B), current profile (2 B);
    then the Profile List feature (0x0000) with its profile descriptors.
    """
    profiles = []
    pos = 12  # 8-byte header + 4-byte Profile List feature header
    while pos + 4 <= len(raw):
        profiles.append({
            "profile": int.from_bytes(raw[pos:pos + 2], "big"),
            "current": raw[pos + 2],
        })
        pos += 4
    return {
        "list_length": int.from_bytes(raw[0:4], "big"),
        "current_profile": int.from_bytes(raw[6:8], "big"),
        "profile_list_feature": int.from_bytes(raw[8:10], "big"),
        "profiles": profiles,
    }


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyse() -> dict:
    """Full anomaly analysis over the recorded evidence."""
    rc = parse_read_capacity(RC10_RESPONSE)
    kernel_sectors = sr_capacity_512b(rc["last_lba"], rc["block_len"])
    kernel_matches = kernel_sectors == SYSFS_SIZE_512B
    fallback_sectors = sr_fallback_capacity_512b()
    candidates = responses_producing_sysfs_size()
    toc = decode_toc()
    gc = decode_get_configuration()

    return {
        "device_view": {
            "source": "READ CAPACITY(10) response "
                      + RC10_RESPONSE.hex() + " (steady state)",
            "last_lba": rc["last_lba"],
            "block_len": rc["block_len"],
            "blocks": rc["blocks"],
            "bytes": rc["device_bytes"],
            "mib": round(rc["device_bytes"] / (1024 * 1024), 2),
        },
        "kernel_view": {
            "source": "/sys/block/srX/size (cached from cold-plug probe)",
            "sysfs_512b_sectors": SYSFS_SIZE_512B,
            "bytes": SYSFS_SIZE_512B * 512,
            "mib": round(SYSFS_SIZE_512B * 512 / (1024 * 1024), 2),
            "matches_iso_bytes": SYSFS_SIZE_512B * 512 == ISO_BYTES,
        },
        "kernel_from_recorded_response": {
            "sectors_512b": kernel_sectors,
            "bytes": kernel_sectors * 512,
            "matches_sysfs": kernel_matches,
            "note": "sr.c get_sectorsize(): capacity = (1 + last_lba) "
                    "* 4 for 2048 B sectors",
        },
        "fallback": {
            "sectors_512b": fallback_sectors,
            "bytes": fallback_sectors * 512,
            "matches_sysfs": fallback_sectors == SYSFS_SIZE_512B,
            "note": "sr.c failure path: 0x%x blocks x 2048 B (~4 GiB)"
                    % SR_FALLBACK_CAPACITY_BLOCKS,
        },
        "read_capacity_16": {
            "supported": False,
            "sense_key": RC16_SENSE_KEY,
            "asc": RC16_ASC,
            "note": "Illegal Request / Invalid command operation code",
        },
        "quirk_evidence": {
            "toc_format0_equals_format2": TOC_FMT0 == TOC_FMT2,
            "toc": toc,
            "get_configuration": gc,
        },
        "candidate_enumeration_responses": candidates,
        "verdict": VERDICT,
        "remaining_hardware_steps": [
            "cold-plug usbmon/dmesg capture: predicted enumeration "
            "READ CAPACITY(10) data phase 00001eff00000800 (7935 x 2048 B, "
            "the ISO size) or 00007bff00000200 (31743 x 512 B)",
            "READ(10) beyond LBA 1592: expect readable data up to the "
            "enumeration capacity if the full ISO is exposed",
        ],
    }


def print_report(a: dict) -> None:
    """Human-readable summary of analyse()."""
    print("Capacity anomaly: 3.1 MiB device view vs 15.5 MiB kernel view")
    print()
    print("Device (steady state): %s" % a["device_view"]["source"])
    print("  last LBA %d, %d B blocks -> %d blocks = %d B (%s MiB)" % (
        a["device_view"]["last_lba"], a["device_view"]["block_len"],
        a["device_view"]["blocks"], a["device_view"]["bytes"],
        a["device_view"]["mib"]))
    print("Kernel: %s" % a["kernel_view"]["source"])
    print("  /sys/block/srX/size = %d x 512 B = %d B (%s MiB)" % (
        a["kernel_view"]["sysfs_512b_sectors"],
        a["kernel_view"]["bytes"], a["kernel_view"]["mib"]))
    print("  matches ISO volume size: %s" % (
        a["kernel_view"]["matches_iso_bytes"],))
    print()
    print("Kernel math on the recorded response (sr.c get_sectorsize()):")
    print("  capacity = (1 + %d) * 4 = %d sectors of 512 B = %d B -> %s"
          % (a["device_view"]["last_lba"],
             a["kernel_from_recorded_response"]["sectors_512b"],
             a["kernel_from_recorded_response"]["bytes"],
             "MATCHES sysfs" if a["kernel_from_recorded_response"]
             ["matches_sysfs"] else "does NOT match sysfs 31744"))
    print("Failure fallback (READ CAPACITY error path):")
    print("  0x%x blocks x 2048 B -> %d sectors of 512 B -> %s"
          % (SR_FALLBACK_CAPACITY_BLOCKS, a["fallback"]["sectors_512b"],
             "MATCHES sysfs" if a["fallback"]["matches_sysfs"]
             else "does NOT match sysfs 31744"))
    print("READ CAPACITY(16): unsupported (%s)" %
          a["read_capacity_16"]["note"])
    print()
    print("Responses that WOULD produce sysfs 31744 through the kernel path:")
    for c in a["candidate_enumeration_responses"]:
        print("  last LBA %d / %d B blocks -> raw %s (%d B device view)" % (
            c["last_lba"], c["block_len"], c["raw"], c["device_bytes"]))
    print()
    print("Canned-response quirk evidence:")
    print("  READ TOC format 0 == format 2 bytes: %s (track start LBA %d)"
          % (a["quirk_evidence"]["toc_format0_equals_format2"],
             a["quirk_evidence"]["toc"]["track_desc"]["start_lba"]))
    print("  GET CONFIGURATION current profile: 0x%04X (CD-ROM)" %
          a["quirk_evidence"]["get_configuration"]["current_profile"])
    print()
    print("Verdict: %s" % a["verdict"])
    print("Remaining hardware steps:")
    for step in a["remaining_hardware_steps"]:
        print("  - %s" % step)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WormholeSwitch capacity anomaly analysis (issue #13)")
    parser.add_argument(
        "--rc10", metavar="HEX",
        help="evaluate a captured 8-byte READ CAPACITY(10) data phase "
             "through the sr.c kernel path")
    parser.add_argument(
        "--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    if args.rc10:
        try:
            raw = bytes.fromhex(args.rc10.replace(" ", ""))
        except ValueError as exc:
            print("invalid --rc10 hex: %s" % exc, file=sys.stderr)
            return 2
        rc = parse_read_capacity(raw)
        sectors = sr_capacity_512b(rc["last_lba"], rc["block_len"])
        if args.json:
            json.dump({
                "response_hex": raw.hex(),
                "parse": rc,
                "kernel_sectors_512b": sectors,
                "kernel_bytes": None if sectors is None else sectors * 512,
                "matches_sysfs_31744": sectors == SYSFS_SIZE_512B,
            }, sys.stdout, indent=2)
            print()
        else:
            print("READ CAPACITY(10) data phase: %s" % raw.hex())
            print("  last LBA %d / %d B blocks -> %d B device view" % (
                rc["last_lba"], rc["block_len"], rc["device_bytes"]))
            if sectors is None:
                print("  kernel: unsupported sector size (capacity zeroed)")
            else:
                print("  kernel sr.c path -> %d sectors of 512 B (%s sysfs "
                      "31744)" % (sectors,
                                  "MATCHES" if sectors == SYSFS_SIZE_512B
                                  else "does not match"))
        return 0

    a = analyse()
    if args.json:
        json.dump(a, sys.stdout, indent=2)
        print()
    else:
        print_report(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
