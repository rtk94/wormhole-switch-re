# Issue #17 — Sanitise `captures/wormhole_bus3_2026-11-06.pcap`

## Finding (verified 2026-11-08, pre-rewrite)

- **Tracked in git history:** YES — `git log --all -- captures/wormhole_bus3_2026-11-06.pcap`
  shows exactly one commit: `e15d291 Add WormholeSwitch RE docs + initial usbmon capture`
  (2026-11-06, blob 199,490 bytes). `git ls-files` confirms it is tracked in the working tree.
- **The committed file was NOT sanitised** even though `e15d291` / `docs/capture-log.md`
  describe it as "sanitized". `capinfos`: 2,298 packets / 199 kB. It contains the
  whole Bus 3:
  - `3:15` WormholeSwitch (`0711:2211`) — 250 packets (the intended device)
  - `3:14` IronKey (`1953:0202`) — 342 packets (other-device traffic → the #17 leak)
  - `3:7` Logitech receiver (`046d:c548`) — 1,688 packets, 841 HID reports, 1,682 interrupt completions
  - `3:1`, `3:3`, `3:5` hubs/control — 18 packets

## Sanitised replacement

- Filter: `tshark -r <original> -Y "usb.bus_id==3 && usb.device_address==15" -F pcap -w captures/wormhole_bus3_2026-11-06.pcap`
- Result: **250 packets, 22 kB**, `3:15`-only (`tshark | sort | uniq -c` → `250  3  15`),
  same window (2026-11-06 10:58:43.901301 → 10:59:12.271775, 28.37 s),
  SHA-256 `5a135f4dc9df9cd69bcd4f3829a48a5232e6d2e1523bafb4a592905c2962b25b`
  (original `fff7d587…`). `captures/wormhole_bus3_capinfos.txt` regenerated.
- Verified with `tools/wormhole_parse.py`: all **42 Wormhole SCSI transactions preserved**
  (GET EVENT STATUS NOTIFICATION 16, REQUEST SENSE 16, TEST UNIT READY 4, INQUIRY 2, READ CAPACITY(10) 1,
  READ TOC/PMA/ATIP 2, GET CONFIGURATION 1), 0 interrupt packets for `3:15` — identical
  Wormhole rows to the unfiltered parse. Only the non-Wormhole devices were dropped.
- Impact: frame numbers shift (e.g. first Wormhole CBW `f97 → f7`); `docs/capture-log.md`
  frame references (e.g. 1385–1402, "98 total CBWs", "841 HID reports") now describe the
  original mixed capture. Wormhole transaction counts are unchanged.

## What a history rewrite would change (requires user confirmation — do NOT force-push yet)

The sanitised pcap above only fixes the working tree. The **unfiltered blob remains in
`e15d291` and every descendant commit** (`main`, `origin/main`, all open PR branches
that descend from it). To fully sanitise history, replace the blob in place:

```sh
# 1. fresh clone (filter-repo refuses dirty repos), install git-filter-repo
pip install git-filter-repo
# 2. from a clean clone of rtk94/wormhole-switch-re:
git filter-repo --blob-callback '
  if blob.original_id == "<OID of the 199490-byte pcap blob>":
      blob.data = <filtered pcap bytes>
'
# (or: replace the path wholesale with --path captures/wormhole_bus3_2026-11-06.pcap --invert-paths
#  and re-add the filtered file in a follow-up commit — blob replacement keeps history cleaner)
# 3. git push --force origin main   # rewrites EVERY commit after e15d291; collaborators must re-clone
```

Effects: all commit hashes from `e15d291` onward change; open PRs #24–#35 become
unmergeable without rebase; anyone who cloned before must re-clone (no `git pull` is
safe). Alternative if the leak is judged non-sensitive (Logitech/IronKey descriptors
and HID reports, to be reviewed): leave history, keep the working-tree fix, and
record the decision here.

**Decision:** history rewrite deferred by the owner (recorded on issue #17). The working-tree fix stands.

## `.gitignore` (this change)

Default-ignore `captures/*.pcap`, allowlist `!captures/wormhole_*.pcap`, with the
filter command inline. All currently tracked pcaps already match `wormhole_*`
(`git ls-files captures/` clean). Oversize/raw dumps are ignored by default; contributors
must filter before adding.

## Follow-up

`captures/wormhole_bus3_synth_2026-11-06.pcap` (140 packets) was also mixed-bus
(`3:7` 70 / `3:14` 30 / `3:15` 22, plus hub traffic). The working-tree copy is now
filtered to `3:15` (22 packets). As with the file above, the original blob remains
in git history.
