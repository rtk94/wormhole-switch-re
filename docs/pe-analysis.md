# PE analysis: SKLoader.exe + embedded DLL

Tooling: `reverse-engineer-anything` skill v49.

- `inspect_pe_imports` on `SKLoader.exe` → `ev_07329fb9b606a2dffe0bf64dab8fc5e1a053b0393bddbd24d479a14241626fca`
- `inspect_pe_resources` on `SKLoader.exe` → `ev_6a73d90a3edee6195a19b687c0eb84a5be2b0ddec17c3b961c38fa8706e9e90a`
- `inspect_pe_certificates` on `SKLoader.exe` → `ev_442fc03a72f711ac630f37683084e8b506f83545b1309075e7464dac0f95c191`
- `inspect_pe_imports` on extracted embedded DLL → `ev_579fef7e2940f9aaa3ad2727ac9fcb3df7cdfa5b48a0beb5ef125777d48ea077`
- Ghidra 12.1.4 deep analysis (see below):
  - SKLoader `binary_overview` → `ev_4a42fde15615c5813fe1de2bd9dfd2d9c49d1145de69e2b183bf61bda866ca98`
  - SKLoader `list_strings` → `ev_f258d4f50e103ec80fb3622a6338e7c57185cbc756c4fbd79ad84d1a759b6cdb`
  - `CreateAppProcess` wrapper `FUN_00402beb` pseudocode → `ev_24ea697bf58c324c2e5f7e2c54487c1026317080d371974fef8541db20ec6e66`
  - Resource-extract wrapper `FUN_00401a2e` pseudocode → `ev_62ad88ff18a3bdfa0ad60dd9c5e5cdf5ebfbda251a9990e4119604a5dcc10749`
  - `ShellExecuteA("open")` wrapper `FUN_00403504` pseudocode → `ev_28ec44481cb8a745929c144638d7860459c9b12e05293d35fb2b68ec6f73810c`
  - Unpacked DLL `inspect_pe_imports` → `ev_67f2cc05438d99ae2b6d6dee63293b32b92dbf5ae8f9c8f7193d16aa8df29eb9`
  - Unpacked DLL `binary_overview` → `ev_67d6a9ef30eb6d1b21e28bce70e6fb1d73e115d8a98f2619ea7ab8f0b130fe2e`
  - GoBridgeDemon `binary_overview` → `ev_26ed15872d2e8057e62b56f5b5aa5f30087694ab0948d13ec10b987d18ce79a8`

Hashes (original blobs are not in this repo):

```
SKLoader.exe            db88b211c78e28eab1561baf2af3e4a2592299be326c6af2f557107d68630af8
Embedded DLL resource   acc30445201b26e86cb1f8c8bce85914edb907020e70d91bfb31824563d1e2d5 (104488 B, offset 70520 in SKLoader)
Embedded DLL unpacked   718508547dd3d3e15d69dee7d0c53f316818b2f65b543e2e9621db92ff803543 (310312 B, UPX 4.2.4 -d)
GSDD.lst                0ba5766dea8b66f8f49c42df2246144f9110d7e2c9e3f58e35c85812aed7cf93
GSDD.zz                 897f80733e41fb2d89d32a671ed3ea5a821d95739a7ab0784b0fd4c5d7b1b259
WormholeShell           179be25a0f11a16def7b9612ea5c3981dfb59616446dbdd8705eafb1fb28b5ce
GoBridgeDemon           152311cb5592e49bc9ac2cefd8145e22ee32d83582e3bf457145bfda84c96f68
```

## SKLoader.exe

- PE32 i386, 200392 B, 4 sections (`file`).
- Imphash (pefile) `be27a3513dcc60a4715f8432543394cf`, import directory RVA 62432 size 120, **no delay imports**.
- Coverage: 5 DLLs, 225 imports.

| DLL | Functions (sample) |
|-----|-------------------|
| `MFC42.DLL` | 150+ ordinal imports (MFC app) |
| `MSVCRT.dll` | `memset`, `malloc`, `strlen`, `_mbs*`, `atoi`, `atol` |
| `KERNEL32.dll` | `CloseHandle`, `CreateFileA`, `CreateProcessA`, `GetModuleFileNameA`, `GetLogicalDrives`, `GetDriveTypeA`, `MoveFileA`, `FindResourceA`/`LoadResource`, `Sleep` |
| `USER32.dll` | `EnableWindow`, `GetSystemMetrics`, `SendMessageA` |
| `SHELL32.dll` | `SHGetSpecialFolderPathA`, `ShellExecuteA` |

No `DeviceIoControl`, no `SetupDi*`, no `CreateFile` on `\\.\`-style device paths (beyond generic `CreateFileA`), no WinUSB. This is not a USB protocol driver — it is a deployment loader that enumerates drives, extracts resources, and spawns processes via `CreateProcessA`/`ShellExecuteA`.

### Deep analysis (Ghidra 12.1.4)

- `binary_overview`: 988 procedures, 193 strings, image base `0x400000`,
  sections `.text` / `.rdata` / `.data` / `.rsrc` (+ a `tdb` segment at
  `0xffdff000`). Entry point RVA `0xa674` (`0x40a674`) is CRT startup
  (`__set_app_type(2)` = GUI), not loader logic.
- Version info (UTF-16, `.rsrc`): Company `KaiJet`, FileDescription
  `Wormhole Switch Loader`, InternalName `LoaderShell`,
  OriginalFilename `LoaderShell.EXE`, version `1, 0, 1007, 8`,
  copyright 2011. Also a Chinese dialog string `關於 LoaderShell(&A)...`.
- Strings confirm the orchestration (addresses in `.data`):
  - Archive helper: `OTiArchive.dll`, `ArchiveTreeSilentProcess`,
    `ArchiveTreeExtractRootFolder`, `ArchiveTreeExtractTargetFolder`,
    `ArchiveTreeListFileName`, `ArchiveTreeDBFileName`, `ExtractTree`, `ExImg`
  - Payloads: `GSDD.lst`, `GSDD.zz`, `GSDDTS.xml`, `Deployment`, `ImageRoot.exe`, `GoLink`
  - Manifest: `LoaderMenifest.xml` (spelled *Menifest* in the binary),
    `GetLoaderManifestFilePath()`, `gsmanifest/loader/options/OEMInfo`,
    `.../UseCmnAppData`, `.../UseRAR`, plus `HardWareID`, `ProductName`, `CompanyID`, `Filename`
  - Args: `CumulateAppParameters(): calling second loader with parameters: '%s'`,
    `-GS:CleanOut`, `-GS:FailUninstallMsg:`, `-GS:SuccessUninstallMsg:`,
    `CLoaderShellApp(): ParseCallingParams(): %s`
  - Logging at `C:\XMLErrorLog`, format `TIMSG`, `%d, %d, %s --> `
  - Misc: base64 alphabet blob at `0x40d64f`, `621249016792505949038205623835511` at `0x410084`
- Decompiled wrappers (all single-caller, Ghidra function = call site):
  - **`FUN_00402beb` — `CreateAppProcess`** (caller site `0x40513d`):
    `CreateProcessA(app, cmdline, NULL, NULL, FALSE, 0x20, NULL, cwd, &startup, &pi)`
    with creation flag `0x20` (`CREATE_NEW_PROCESS_GROUP`), 5000 ms default
    wait timeout. On failure: `CString::Format` + `OutputDebugStringA`
    (`CreateAppProcess(): Fail!!! reason: %s, strApp: %s`). If wait flag set:
    `WaitForSingleObject(hProcess, timeout)` + `GetExitCodeProcess`,
    returns `exit == 0`; otherwise closes handles and returns 1.
  - **`FUN_00401a2e` — resource extract** (caller site `0x4016a2`):
    `FindResourceA(module, MAKEINTRESOURCE(id), type)` → `SizeofResource` →
    `LoadResource` → `LockResource`, creates the output's parent directory
    (truncate at last `\`, tolerates `ERROR_ALREADY_EXISTS` `0xb7`),
    then `CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL)`
    + `WriteFile(resource, size)`. On write failure the partial file is
    deleted (`DeleteFileA`). Returns bool.
  - **`FUN_00403504` — `ShellExecuteA("open")`** (caller site `0x404456`):
    `ShellExecuteA(NULL, "open" @ 0x410224, file, params, dir, SW_SHOW=5)`,
    returns `hInstance > 32`.
- No `DeviceIoControl` string in the defined-string inventory either —
  consistent with the import table: USB traffic is handled by the kernel
  `usb-storage` driver for the emulated CD-ROM; the loader only needs
  files/processes.

## Resources (15 entries)

- Type **`DLL`** name **129** lang 1028, payload RVA 70520, offset 70520, size 104488, SHA-256 `acc3044520...` — MZ blob.
- 9 `RT_ICON` images (IDs 1-9), `RT_DIALOG` IDs 100/102, `RT_STRING` ID 7, `RT_GROUP_ICON`, `RT_VERSION` ID 1. Icons match J5Create branding visually.

The DLL resource is the payload: SKLoader extracts it at runtime (typical for KaiJet loaders). It was carved to `embedded_DLL_129.bin` for analysis (not tracked).

## Embedded DLL (UPX)

- `file`: `PE32 executable for MS Windows 4.00 (DLL), Intel i386, UPX compressed, 3 sections`
- Sections: `UPX0` (vsize 0x83000), `UPX1` (vsize 0x17000, raw 0x16400), `.rsrc` (0x02000). `UPX!` signature at offset ~992.
- REA imports: 9 DLLs, 13 functions total — UPX stub only:

```
KERNEL32: LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree
ADVAPI32: RegCloseKey
COMCTL32: _TrackMouseEvent
GDI32: BitBlt
MFC42 ordinal 4407
MSVCRT: atoi
RPCRT4: UuidCreate
SHELL32: ShellExecuteA
USER32: GetDC
```

Imphash `59908120d5bcb424b73bcd6a2bf054b1` reflects the stub, not the real code.

### Unpacked (UPX 4.2.4, now installed)

`upx -d` on a scratch copy: 104,488 → 310,312 B, 5 sections, SHA-256
`718508547dd3d3e15d69dee7d0c53f316818b2f65b543e2e9621db92ff803543`.
Unpacked `inspect_pe_imports` (`ev_67f2cc05438d99ae2b6d6dee63293b32b92dbf5ae8f9c8f7193d16aa8df29eb9`):
**9 DLLs, 380 imports**, imphash `40512788355c2bae0d1e78cdb2a8c2ad`.

| DLL | Notable imports |
|-----|-----------------|
| `KERNEL32.dll` | `CreateFileA/W`, `ReadFile`/`WriteFile`, `FindFirstFileW`/`FindNextFileW`, `CreateDirectoryA`, `GetLogicalDrives`, `GetDriveTypeA`, `GetTempPathA`, `FindResourceA`/`LoadResource`/`SizeofResource`/`LockResource`, `CreateMutexA`, `LoadLibraryA`/`GetProcAddress`, `GetVersionExA` |
| `ADVAPI32.dll` | `RegCreateKeyExA`, `RegOpenKeyExA`, `RegQueryValueExA`, `RegSetValueExA`, `RegDeleteValueA`, `RegCloseKey` |
| `GDI32.dll` / `USER32.dll` | GUI: `BitBlt`, `CreateFontIndirectA`, `MessageBoxA`, `SetTimer`, `FindWindowExA`, … |
| `MFC42.DLL` | ~200 ordinal imports (MFC app) |
| `MSVCRT.dll` | `fopen`/`fprintf`/`fclose`, `_stat`/`_wstat`, `_mkdir`, `_chmod`, `_utime`, `remove`, … |
| `RPCRT4.dll` | `UuidCreate`, `UuidToStringA`, `RpcStringFreeA` |
| `SHELL32.dll` | `ShellExecuteA` |

Still **no `DeviceIoControl`, no `CreateProcessA`, no `SetupDi*`, no WinUSB**,
and no `DeviceIoControl` string in the Ghidra string inventory either.
This DLL is file/archive/GUI/registry code, not a USB driver.

Exports (12, via `objdump -p`): `AddTree`, `ExtractTree`, `OTI_AddFile`,
`OTI_AddFileW`, `OTI_CheckArchiveFile`, `OTI_CheckFileExisted`,
`OTI_CompressArchive`, `OTI_DeleteFile`, `OTI_ExtractFile`,
`OTI_GetCumulatedDeletedSize`, `OTI_ListFile`, `OTI_UpdatePassword`.
Internal name `ArchiveTreeLib.dll`; strings include `ArchiveTreeSilentProcess`,
`ArchiveTreeCompress`, `ArchiveTreePINCode`, `ArchiveTreeAddSourceFolder`, …
This is the **OTiArchive** helper SKLoader references by name and resolves
with `LoadLibraryA`/`GetProcAddress` — which is why those `ArchiveTree*`
functions do not appear in SKLoader's import table.

Ghidra 12.1.4 `binary_overview` on the unpacked DLL:
1,849 procedures, 2,059 strings, image base `0x10000000`, 7 segments
(`.text` / `.rdata` / `.data` / `.rsrc` / `.reloc` + `tdb`).

Chain, end to end: SKLoader extracts this OTiArchive DLL resource
(`FUN_00401a2e`) → loads it dynamically → `ArchiveTree*` extracts the
`GSDD` / `Deployment` payloads → `CreateAppProcess` / `ShellExecuteA("open")`
launches the extracted app (the strings say `ImageRoot.exe` and `GoLink`;
`docs/gsdd.md` shows `ImageRoot` is the archive's root folder and the
executables are `Wormhole.exe`, `LinkEngKM.exe`, …). The actual
peer-to-peer transfer logic remains in the encrypted `GSDD` payloads and the
cable-internal link — still **unknown** from static analysis of the shipped
files, but neither host binary talks USB directly.  Recovering those payloads
from a VM install is #48; their analysis is #49.

## Authenticode (SKLoader.exe)

- One `WIN_CERTIFICATE` at file offset 192512, length 7880, type 2 (PKCS#7), payload SHA-256 `9b92dc2b...`.
- Digest OID `1.3.14.3.2.26` (SHA1), signer RSA.
- Leaf subject:
  ```
  countryName=TW, organizationName=Magic Control Technology Corp.,
  organizationalUnitName=Digital ID Class 3 - Microsoft Software Validation v2,
  organizationalUnitName=GM' Secretary, commonName=Magic Control Technology Corp.
  serial_hex=1af6a29f359edb48a50633d3dae59d75
  not_before 120724000000Z / not_after 150725235959Z
  ```
- Chain: VeriSign Class 3 Code Signing 2010 CA (2010-2020) → VeriSign Class 3 Public Primary G5 (2006-2036) → Symantec timestamping G2/G4 (2022).
- REA does not verify signatures or chain validity — fields are structural only.

## Mac GoBridgeDemon (Ghidra 12.1.4 deep analysis)

`open_binary` on `GoBridgeDemon` returned:

```
format: mach-o-universal, kind: executable,
sha256: 152311cb5592e49bc9ac2cefd8145e22ee32d83582e3bf457145bfda84c96f68,
architecture: x86
```

With Ghidra 12.1.4 aligned (see *Tooling* below), `binary_overview`
now succeeds — previously this failed with `unsupported_version`:
**1,204 procedures, 4,423 strings, 39 segments**, image base `0x1000`,
ObjC sections present (`__class`, `__inst_meth`, `__message_refs`,
`__category`, …) plus `__text` / `__cstring` / `__cfstring`.
The universal binary is i386 + ppc_7400; Ghidra analyzed the x86 slice.

String spot-checks:
- `CGEvent` — 18 hits: consistent with keyboard/mouse input injection
  via CoreGraphics event taps (the HID-injection side of the cable).
- `IOUSB` — 0 hits; `0711` — 0 hits: no USB VID/PID lookup strings in
  the defined-string inventory. The daemon does not enumerate USB by
  VID in strings (any VID check would be a numeric constant, not a
  string — **unknown** without deeper function analysis).

Function-level analysis of GoBridgeDemon (`_main`, CGEvent tap
callbacks, `THMFileManager_handleSystemEvent`, HID forwarding) and of
`OTiTransfer.framework` (`OTi_SendHIDPacket`,
`OTiTransporter::sendHIDPacket`, `SendSCSICommandSendData`,
`FindAllDevices`) is in [`docs/mac-gobridge.md`](mac-gobridge.md) —
including the 16-byte vendor-CDB HID packet format
(`D9 '3'/'4'/'6' <12 payload> O T`) that carries host→cable traffic.

`inspect_macho` remains macOS-only (`unsupported_host`); Mach-O deep
analysis on Linux goes through `open_binary` + Ghidra, which now works.

Sessions were closed with `close_binary`.

## Tooling: Ghidra 12.1.4 side-by-side

REA 6.8.0 requires Ghidra 12.1.x (verified 12.1.4); this host had
12.2 at `/opt/ghidra_12.2_PUBLIC`, which REA rejected as
`unsupported_version`. Fixed side-by-side, 12.2 untouched:

- Downloaded official release
  `ghidra_12.1.4_PUBLIC_20260921.zip` (543 MiB) from
  `NationalSecurityAgency/ghidra` `Ghidra_12.1.4_build`,
  SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`
  (matches the release asset digest).
- Unzipped to `/opt/ghidra_12.1.4_PUBLIC` (`application.version=12.1.4`).
  JDK 25 (`/usr/lib/jvm/java-25-openjdk-amd64`, 25.0.5) already present.
- REA discovers Ghidra via a `ghidra` launcher on `PATH`
  (`/usr/local/bin/ghidra` symlink), not by scanning `/opt`. Repointed:
  `sudo ln -sfn /opt/ghidra_12.1.4_PUBLIC/ghidraRun /usr/local/bin/ghidra`
  (was `.../ghidra_12.2_PUBLIC/ghidraRun`). To switch back, point it
  at 12.2 again. Alternatively set `GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.4_PUBLIC`
  for a single `rea` CLI invocation.
- Verified: `rea doctor --provider ghidra` → healthy, version 12.1.4;
  REA `binary_session` → `provider_version: 12.1.4`,
  `install_dir: /opt/ghidra_12.1.4_PUBLIC`, no MCP restart needed
  (discovery is per-call). `inspect_pcap_client` also now passes
  (tshark/capinfos 4.4.19 at `/usr/bin/{tshark,capinfos}`).
