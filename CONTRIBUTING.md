# Contributing to wormhole-switch-re

This is a **documentation and reverse-engineering research** repository. There is no firmware to build, no binary to ship, and no service to deploy. Contributions are welcome in the form of:

- Corrections to existing analysis (descriptors, protocol logic, decompiler traces)
- New captures from different hosts / OS versions / hub topologies
- Tooling improvements in `tools/` (parser coverage, sanitiser robustness, test cases)
- Additional host-software analysis (Windows SKLoader, macOS GoBridge, other OEM builds)
- Documentation clarity, cross-references, or reproduction steps

## Ground rules

- **No copyrighted blobs.** Original firmware, host installers, ISO images, or extracted PE/Mach-O binaries are **not** accepted in this repo. Hashes, descriptors, and analysis output are fine — see `docs/iso-payload.md` and `docs/pe-analysis.md` for the established format.
- **Sanitise captures.** Raw `usbmon` pcaps contain every device on the bus. Before committing, filter to the Wormhole VID:PID (`0711:2211`) with `tools/filter_usbmon.py`. See `docs/reproduction.md` §6.
- **Reproducibility.** Any new capture or analysis should include the exact commands used to produce it so others can verify. The repo already provides `tools/wormhole_parse.py` (stdlib-only) and `tools/filter_usbmon.py` — extend them rather than introducing new external dependencies.
- **Tone.** Technical, concise, evidence-backed. No marketing language, no speculation presented as fact. "Observed" / "decoded" / "decompiler shows" / "unknown" — use the right verb.

## How to contribute

1. Fork the repo and create a topic branch (`git checkout -b topic/short-name`).
2. Make your change. Run the test suites:
   ```sh
   python3 -m unittest tools.test_wormhole_parse
   python3 -m unittest tools.test_filter_usbmon
   python3 -m unittest tools.test_peer_rerun_send
   python3 -m unittest tools.test_upipe_peer
   ```
3. If you add parser support for a new packet type, add a test case in `tools/test_wormhole_parse.py`.
4. Update relevant docs in `docs/` (cross-link with `[link](path.md)`).
5. Open a PR against `main`. CI (`.github/workflows/tests.yml`) runs the unit tests.

## Adding a new capture

1. Capture on your bus: `sudo tcpdump -i usbmonN -w raw.pcap`
2. Identify the Wormhole `Bus:Dev` with `lsusb -d 0711:2211`
3. Filter: `python3 tools/filter_usbmon.py raw.pcap --device B:D -o captures/wormhole_busN_YYYY-MM-DD.pcap`
4. Parse and verify: `python3 tools/wormhole_parse.py captures/wormhole_busN_YYYY-MM-DD.pcap --hid`
5. Add a markdown note in `docs/` (or extend `capture-log.md` / `live-capture-YYYY-MM-DD.md`) with the command log, `capinfos` output, and parser summary.
6. Commit the filtered pcap (pcaps ≤ ~200 kB are fine; larger ones stay in private storage with only the filtered copy published).

## Tooling contributions

- `tools/wormhole_parse.py` — single-file, stdlib-only parser. New features should preserve zero-dependency property.
- `tools/filter_usbmon.py` — keeps only one device's transactions from a raw usbmon pcap.
- `tools/peer_rerun_send.py` — logged send driver for peer→local re-run tests (uses `sg_raw` + direct `SG_IO`).
- `tools/upipe_peer.py` — Linux GoBridge peer over UPipe (SG_IO); its decoders are shared with the parser.
- `tools/gobridge_scsi.d` — dtrace tracer for GoBridgeDemon's SCSI tasks on macOS.
- All Python tools have unittest suites. New code needs tests.

## License

By contributing, you agree that your documentation and script contributions are licensed under the **MIT License** (same as `LICENSE` in this repo). Original J5Create / KaiJet / Magic Control Technology firmware and host binaries remain copyrighted by their respective owners and are not part of this project.