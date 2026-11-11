# GSDD container format (issue #10)

`GSDD.zz` / `GSDD.lst` — the OTiArchive database + encrypted list for the
Wormhole Windows payload under `\ImageRoot\Deployment\`. The archive
library is the UPX-packed `ArchiveTreeLib.dll` embedded as resource
`DLL/129` in `SKLoader.exe` (see [`pe-analysis.md`](pe-analysis.md)).
Original blobs are **not** in this repo; hashes and analysis only.

## Files and hashes

```
GSDD.zz  1407767 B  sha256 897f80733e41fb2d89d32a671ed3ea5a821d95739a7ab0784b0fd4c5d7b1b259
GSDD.lst   12663 B  sha256 0ba5766dea8b66f8f49c42df2246144f9110d7e2c9e3f58e35c85812aed7cf93
SKLoader.exe 200392 B sha256 db88b211c78e28eab1561baf2af3e4a2592299be326c6af2f557107d68630af8
embedded DLL (packed)  104488 B sha256 acc30445201b26e86cb1f8c8bce85914edb907020e70d91bfb31824563d1e2d5
ArchiveTreeLib.dll (UPX 4.2.4 -d) 310312 B sha256 718508547dd3d3e15d69dee7d0c53f316818b2f65b543e2e9621db92ff803543
```

REA evidence (this session; re-run to consume):

- `inspect_pe_resources` → `ev_225e48b03a382f707bc4164f7568f591b27cbf19cc899709e20118c4425ec08d` (DLL/129 @ offset 70520, sha256 `acc30445…`)
- `open_binary` + `binary_overview` → `ev_67d6a9ef30eb6d1b21e28bce70e6fb1d73e115d8a98f2619ea7ab8f0b130fe2e` (1849 procedures, 2059 strings, image base `0x10000000`)
- `inspect_pe_imports` (unpacked DLL) → `ev_37f758a7f1f9f8ad0e752b1373a12c85e6bebf0a35a02c7500d7107d96c5332f` (**380 imports, 9 DLLs, imphash `40512788355c2bae0d1e78cdb2a8c2ad`**; incl. `GetTempPathA`, `LoadLibraryA`, `GetProcAddress`)
- `search_strings` (DecryptBuffer/PINCode/EncryptedList) → `ev_4500918c5a05a53d1100fcf680e6a64d0e9a3becf1e411e4afbf72cf8fd6c8df`
- `xrefs 0x1002a050` → `0x100187cf` (`ev_5669ca45c7a60af4f85c4b2ff833b5855c7b45fcf6ad6f5a10a60e00aeff9a5c`), `xrefs 0x1002ad6c` → `0x1001ddbd` (`ev_3bd53849c70df2f508e4ec624db55da54684b3dd1d9e74c3f81749a6d91fe2c4`), `xrefs 0x1002ab84` → `0x1001638d` (`ev_474bb496eef2f70e7ea9c46bbda5cf6f1bd5ad5fd50643934f0fcc7bf8207732`)
- `procedure_pseudo_code 0x10018730` (LoadLibrary/GetProcAddress loader) → `ev_413dd811db2d2c319c5d03ee05109d0d950a1246ce7a3138de032acb739231a5`
- `procedure_pseudo_code 0x1001da20` (`CFileTreeXML::OpenEncryptedListFile`) → `ev_ccabd35d3443db728f8941279a60c57302fdc0f1725b4e88c6f3ab3321e95096`
- `procedure_pseudo_code 0x1001d100` (repeating-XOR, full key, period 33) → `ev_bdca5c4e1960f8970eaf29f3bf2d8065a3d95ba8b2a7c0bcc748fffa3a049c42`

## TL;DR

- `GSDD.zz` = OTiArchive database: 128-byte header (`OT`, version `02`, count `0x1d` = 29),
  followed by **29 contiguous records tiling the file to EOF** (128 + 1,407,639 = 1,407,767 ✓).
- Each record = fixed 28-byte table + encrypted-name block (`EN`, verbatim copy in the XML list) +
  30-byte size trailer + `CS` bytes of (compressed + encrypted) file data.
- `GSDD.lst` = **the encrypted XML file-tree list** (`CFileTreeXML::OpenEncryptedListFile`).
  Decryption is a **repeating XOR with the 33-digit key** found as a string in the DLL
  (`FUN_1001d100` @ `0x1001d100`, `ev_bdca5c4e…`).
- Plaintext of `.lst` is the XML tree: `<OTIMSG ET=… PT=…><D1 …><N1 …>` with per-file
  `CS` (compressed size), `OS` (original size), `ON` (plaintext name), `EN` (encrypted name), `LW`, `NT=F/D`.
- Inside `.zz`, records are 1:1 with the 29 `<N>` entries. Payload blocks are encrypted with
  **OTiEncrypt.dll** (`EncryptBuffer`/`DecryptBuffer` + `GetHashTable`), which is **not present**
  in the source bundle — payload decompression is blocked until it is obtained.
- There is no file literally named `GoLink.exe` or `ImageRoot.exe` in the archive.
  `ImageRoot` is the archive root *folder*. The executable payloads are `Wormhole.exe`,
  `SKLoader.exe`, `LinkEngKM.exe`, etc. (see file table). The old "ImageRoot.exe/GoLink"
  names in the task came from the SKLoader strings (`ImageRoot.exe`, `GoLink`); the real
  entries are documented below.

## 1. `GSDD.lst` — decryption

In `ArchiveTreeLib.dll`, `CFileTreeXML::OpenEncryptedListFile` (`FUN_1001da20`,
read `GSDD.lst`, `FUN_1001d100(key, buffer, size)`, parse XML) passes the
string at `0x1002add8` as the key:

```
"621249016792505949038205623835511"   (33 ASCII digits; ends with two 1s)
```

`FUN_1001d100` (`0x1001d100`; `ev_bdca5c4e…`) is a **repeating XOR**:
read the full key, then for each payload byte `buf[i] ^= key[i mod keylen]`
(full 33 bytes — the assembly confirms period == `strlen(key)`, not 32).
First 12 decoded bytes are `<OTIMSG ET="`, confirming the key phase;
decoding the whole file gives a well-formed single-line XML tree
(`EN="\ImageRoot"`, `LW` timestamps, `NT="D"` directories, `NT="F"` files).
Every other cipher tried on this "substitution-cipher-like" data was noise:
`.lst` has exactly the byte set `{0x00..0x1F} ∪ {0x40..0x7F}` (96 values, bit 5 always
cleared) but no semantic match besides this key — digit-XOR explains it:
ASCII plaintext (0x20-0x7E) XOR digits (0x30-0x39) yields exactly that set.

## 2. `GSDD.zz` — byte layout

```
0x00  4B   magic: 4F 54 02 1D  ("OT" + 02 + 1D)  — 0x1D == 29 == record count
0x04  76   zero-padded / obfuscated header (mostly 0x00, then encrypted-name-like data)
0x80  records, contiguous, to EOF (29 records)
```

The 29 record starts (verified table prefix `12 00 00 00 F6 00 00 00 66 00 00 00 93 00 00 00`
occurs at exactly these offsets):

| idx | offset range | len | file (after XML decode) | CS | OS |
|----|--------------|-----|--------------------------|----|----|
|0|0x000080–0x000706|1670|FunctModuleManifest.xml|1404|3945|
|1|0x000706–0x002B99|9363|GOCommon.ini|9141|56212|
|2|0x002B99–0x0032CC|1843|GOSuiteLang.ini|1609|7628|
|3|0x0032CC–0x0039ED|1825|LoaderMenifest.xml|1579|5199|
|4|0x0039ED–0x026B8E|143777|Splash_GOSync.png|143515|148013|
|5|0x026B8E–0x02F90A|36220|2208KM_HID.dll|35822|39760|
|6|0x02F90A–0x036B7C|29298|CBAgentLang.ini|28896|160410|
|7|0x036B7C–0x036E6D|753|FunctModuleManifest.xml (Functions\)|319|498|
|8|0x036E6D–0x039063|8694|GOCommon.ini (Functions\)|8304|51192|
|9|0x039063–0x045C6D|52234|LEWD.exe|51860|68296|
|10|0x045C6D–0x048C0E|12193|LinkEngineLang.ini|11779|89316|
|11|0x048C0E–0x099A71|331363|LinkEngKM.exe|330969|345760|
|12|0x099A71–0x09DA8E|16413|OnLineUpdate.dll|16007|17920|
|13|0x09DA8E–0x0A4F3D|29871|OnlineUpdate.exe|29465|37712|
|14|0x0A4F3D–0x0A6A54|6935|OnlineUpdateLang.ini|6513|44414|
|15|0x0A6A54–0x0AF29E|34890|OSW08.dll|34512|38440|
|16|0x0AF29E–0x0B502B|23949|ProdLic.DLL|23563|25600|
|17|0x0B502B–0x0B7A47|10780|CBLink.ico|10358|14846|
|18|0x0B7A47–0x0B8326|2271|DropEftCopy.cur|1829|3262|
|19|0x0B8326–0x0B8BCD|2215|DropEftNone.cur|1773|3262|
|20|0x0B8BCD–0x0B94D7|2314|Offline.ico|1888|2862|
|21|0x0B94D7–0x0B9DB0|2265|ReceiveData.ico|1823|2862|
|22|0x0B9DB0–0x0BA677|2247|TempHalfOff.ico|1805|2862|
|23|0x0BA677–0x0BAF51|2266|TempOff.ico|1840|2862|
|24|0x0BAF51–0x0BB6E6|1941|UnderControl.ico|1495|2862|
|25|0x0BB6E6–0x0BCA67|4993|SuccessControl.wav|4535|6742|
|26|0x0BCA67–0x0BDE9D|5174|SuccessReceive.wav|4716|8932|
|27|0x0BDE9D–0x0EE142|197285|Wormhole.exe|196895|211984|
|28|0x0EE142–0x157B17|432597|SKLoader.exe (stored, larger than the on-disk one)|432446|445640|

Summed `CS` = 1,396,660 (total `CS`+29 headers+ENs+trailers + 128 header = file size ✓).

The 7 DWORD table at each record start was previously read at `0x80` as
`0x1200, 0xF600, 0x6600, 0x9300, 0x7700, 0x200, 0xD000`, but that is the
LE-encoding of 7 small WORD-shifted values. The stable interpretation, verified
against all 29 records:

- DW[0]: `0x12xx` — near-constant version/fragment field (low byte varies slightly per record)
- DW[1..5]: `0xF600, 0x6600, 0x9300, 0x7700, 0x0200` — identical for all 29 records
- DW[6]: **`EN-length << 8`** (`>C<…` block length): e.g. record0 `0x0000D000>>8 = 0xD0 = 208` = `len(EN[0])` ✓, record1 `0xA400>>8=164` ✓, …, record5 `0x15400>>8=340` ✓

### Names (`EN`)

The `EN` bytes in `.zz` equal the `EN="…"` values of the decoded XML **verbatim**
(encrypted names; not digit-XORed). They are OTiEncrypt ciphertexts
(see the `Before OTI_AddFile` debug string: `Before OTI_AddFile, szARZipFile: %s, szSrcFilePath: %s, szEncryName: %s, szArcPassword: %s`).
Plaintext words never occur (no `Wormhole.exe`, no `.exe`, no `MZ`). All `EN` lengths
are ≡ 0 mod 4 (e.g. 208, 164, 176, …, 92; each is an `OTiEncrypt`-encrypted directory
entry — a fixed-template ciphertext whose 70+ byte common suffix is the encrypted
shared path; its variable prefix encodes the filename).

### Trailer (30 bytes after `EN`)

Immediately after `EN`, a 30-byte trailer, then `CS` (actually `CS-1`) payload bytes
before the next table (the last record simply runs to EOF):

- bytes 0–5: 6-byte tag: `[4 varied bytes][byte4][0x81]` — byte5 is always `0x81`
  (e.g. `78 FF 30 4E B6 81`, `0E 9D 66 4F B6 81`, rec8 `99 E8 C7 4C 24 81`)
- bytes 6–13: **u64 LE `CS`** (verified for all 29 records)
- bytes 14–21: **u64 LE `OS`** (verified for all 29)
- bytes 22–29: **u64 LE `1`** (all records — likely compression/encryption *flags*)

Base layout: `28 (table) + EN + 30 (trailer) + CS (data)`, etc. — for record0:
28+208+30+1404 = 1670 ✓ equals the observed gap. (There is also a leading `0x00`
byte before `EN`; equivalently, the header is 29 bytes with `EN` starting at `tbl+29`.)

### Payload data (`CS` bytes)

Starts with a mini block header, then opaque high-entropy data
(overall file entropy 7.999 bits/byte, 256 distinct bytes). The first ~28 bytes contain
several small-LE-int fields (e.g. record0: `8B 0F 00 00 29 5A 9D 6E 00 00 69 0F 00 00 B5 04
00 00 68 0F 00 00 EF 55 03 00 00 84 C3…`; record1: `B4 DB 00 00 …` = OS again). The
fourth dword (`0x6E9D5A29`, rec0) is a CRC32-shaped value — the DLL checks
`rcd` vs `cal` per block (`UncompressBlock(): CRC_ERROR: rcd: %X, cal: %X`,
string @ `0x1002ab84`). After the mini header the stream is encrypted with
**OTiEncrypt** (see §3). Entropy analysis (1 KiB windows, 7.8–7.99 after the first
~0x1B0; `MZ` hits = 20 ≈ random expectation 21.5, `PK`/`ELF` = 0) is consistent with
a strong cipher on compressed data, not with plain compression.

## 3. `ArchiveTreeLib.dll` (OTiArchive) — the crypto dependency

Exports (12, `objdump -p`): `AddTree`, `ExtractTree`, `OTI_AddFile`, `OTI_AddFileW`,
`OTI_CheckArchiveFile`, `OTI_CheckFileExisted`, `OTI_CompressArchive`, `OTI_DeleteFile`,
`OTI_ExtractFile`, `OTI_GetCumulatedDeletedSize`, `OTI_ListFile`, `OTI_UpdatePassword`.

- `FUN_10018730` (`0x10018730`, `ev_413dd811…`): on first use,
  `GetTempPathA` + `"%s%s"` + `OTiEncrypt.dll` → `LoadLibraryA`, then
  `GetProcAddress("GetHashTable")`, `GetProcAddress("EncryptBuffer")`,
  `GetProcAddress("DecryptBuffer")`.
- Internal wrappers (`0x100187f0`/`0x10018830`) call those with a key buffer
  built by `FUN_10018870` — a 17-byte buffer filled with ASCII `'0'` (`0x30`) —
  plus mode `5`, block params `0x10, 1`. The **actual cipher is in `OTiEncrypt.dll`,
  which is absent from the source bundle** (not in SKLoader resources — only `DLL/129`
  is embedded; no `OTiEncrypt` string in `/SKLoader.exe` bytes; nothing named
  `*encrypt*`/`OTiEncrypt*` exists on the media dir). Payload extraction is therefore
  blocked at the encryption layer, before compression.
- `CFileTreeXML::OpenEncryptedListFile` (`FUN_1001da20`, `ev_ccabd35d…`) only uses the
  *simple XOR* (`FUN_1001d100` key = the 33-digit string above) for the `.lst` list —
  the payload / `EN` blocks use the full OTiEncrypt cipher.
- Named-but-unknown password-ish strings: `ArchiveTreePINCode` @ `0x1002a120` and,
  right after `OTiEncrypt.dll` @ `0x1002a084`, the ASCII blob `tY23WgLLsPam`
  (noted as the leading bytes after `OTiEncrypt.dll\0\0`; plausible default password,
  unconfirmed). No `SZ` password buffer was resolved to the real `szArcPassword`
  value — static analysis stopped at the inter-DLL boundary.

## 4. Extraction attempts (all failed → documented)

On the **first-record payload slice** (`0x000190–0x000706`-ish, CS=1404) and the whole
`.zz`, tried:

1. `zlib`/`gzip`/raw-deflate, `lzma`, `bz2` at every alignment offset (0–2000), with
   and without digit-XOR / `0x30`-key XOR → no stream decodes.
2. Repeating-XOR (digit key) then inflate; single-byte XOR magic scan (`PK\x03\x04`)
   over the file → nothing beyond noise (k=59 `78 01` count 487 is structurally
   interesting but does not inflate).
3. ZipCrypto (`password ∈ {"tY23WgLLsPam","000…0","621…,","OTiArchive","Wormhole"}`,
   implemented in-line) + inflate → produces tiny false-positive outputs only (len 3/8),
   no `MZ`.
4. RC4 KSA of the digit key / 17-zero key (drops 0/256/768/3072) + inflate → nothing.
5. `7z l` on both files → "Cannot open the file as archive" (expected; custom format).

The blocker is the OTiEncrypt cipher (16-byte blocks, `GetHashTable` key derivation
from the 17-`0x30` buffer, mode 5) — a proprietary external DLL. Compression
algorithm cannot even be identified until the cipher is recovered
(strings only confirm per-block `CompressBlock`/`UncompressBlock` with CRC check).

### What remains to extract `Wormhole.exe` / `LinkEngKM.exe`

Route 3 is being taken in a Windows KVM guest with the cable passed through
(`docs/reproduction.md` §6.6), tracked in #48.

1. Obtain `OTiEncrypt.dll` (from a live Wormhole install / vendor media) and reuse
   its exported `DecryptBuffer` via Wine/Frida on the extracted record buffers,
   or
2. reverse `GetHashTable`/`DecryptBuffer` once that DLL is in hand; the cipher
   operates on 16-byte blocks, so known-plaintext (PE headers) + the fixed key
   buffer ("17× 0x30", mode 5) should be enough to confirm an implementation, or
3. run `ExtractTree` under Wine with `OTiEncrypt.dll` present in `%TEMP%` and let the
   DLL decrypt `GSDD.zz` directly (run SKLoader → `ArchiveTreeExtractRootFolder`
   writes `\ImageRoot\Deployment\…`).

The block boundaries and per-record `CS`/`OS` above are everything needed to feed
decrypted records to a future extractor.

## References

- `docs/pe-analysis.md` — SKLoader resource/DLL extraction context (unchanged facts;
  DLL hash & imphash double-checked in this session).
- `LoaderMenifest.xml` (Deployment/Config) — `KaiJet / Wormhole1107` OEM / loader
  manifest, read directly from media.
