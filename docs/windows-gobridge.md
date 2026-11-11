# Windows GoBridge (Wormhole1107)

Windows counterpart of [`mac-gobridge.md`](mac-gobridge.md). This first
version covers the install and the recovered binaries (#48); the
function-level analysis is #49 and the wire comparison with the Mac is #50.

## How the binaries were recovered

`GSDD.zz` keeps every Windows binary encrypted, and the cipher DLL
(`OTiEncrypt.dll`) is in no shipped file ([`gsdd.md`](gsdd.md) § What
remains).  Running the loader on Windows decrypts them instead:

- Windows 11 (build 26300) KVM guest with the cable passed through by
  vendor/product ID ([`reproduction.md`](reproduction.md) §6.6), 2026-11-11.
- `SKLoader.exe` started by hand from the `WORMHOLE` CD drive (`E:`); no
  autorun.  SmartScreen/UAC prompts were not recorded.
- The installed tree was packed with `tar` in the guest and copied to the
  host.  Binaries stay in private storage; only hashes are published.

## Install footprint

Everything lands in the user profile.  Whether the loader needs
administrator rights was not checked.

| Item | Detail |
|---|---|
| Install root | `%APPDATA%\KaiJet\Wormhole1107\` |
| `ExImg\ImageRoot\` | The decrypted archive, laid out as the `GSDD` file table: `SKLoader.exe`, `Deployment\Config\*`, `Deployment\Functions\{92EEDB7D-755A-4a90-A79D-C0BD0ACF1A7F}\*` |
| `ExImg\GSDDTS.xml` | `<GSDDSize>1407767</GSDDSize><MirrorSize>1849293</MirrorSize><GSDDLWT>10/23/2013 6:21:32 AM</GSDDLWT>`: the loader's record of which `GSDD.zz` it unpacked (size matches the shipped file) |
| `FunctModules\{92EEDB7D-…}\` | The installed function module: the same binaries as `ImageRoot\Deployment\Functions\{…}`, plus `ECN001.DLL` |
| `Common\OTiOSW08.dll` | Device library, not in the `GSDD` table (see below) |
| `MainExe\` | `GOCommon.ini`, `GOSuiteLang.ini` |
| Autostart | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `CS Dispatch` = `…\FunctModules\{92EEDB7D-…}\Wormhole.exe -GN:RunFromRegistry` |
| Registry | No `HKCU`/`HKLM\Software\KaiJet` key.  `ECN001.DLL` names `Software\OTi\2108\%s\AdvanceFunctionModules\` (not yet checked) |
| Services, drivers | None in the install tree; not checked system-wide |
| Processes after install | `Wormhole.exe`, `LinkEngKM.exe`, `LEWD.exe` (from `FunctModules`), `SKLoader.exe` (from `ExImg\ImageRoot`) |

`FunctModuleManifest.xml` names the module "Wormhole Switch"
(`IDS_CLIPBOARDSHARE_NAME`) and "GO! Bridge" (`IDS_GOBRIDGE_NAME`); its
live-update entry points at the vendor's `www.mct.com.tw`
(`wh88update/download/update_online`).

## Binaries

Every size matches the original size (`OS`) of its `GSDD` record
([`gsdd.md`](gsdd.md) § 2), so these are the archive's plaintext.  The
`FunctModules` copies are byte-identical to the `ImageRoot` ones.  All are
UPX-packed except `ECN001.DLL`; the unpacked size is from `upx -d` on a
copy.

| File | Size (B) | Unpacked (B) | PE timestamp | SHA-256 |
|---|---|---|---|---|
| `Wormhole.exe` | 211,984 | 568,336 | 2013-07-03 | `86e8a299e5db3f3f04ae72299156d4edab896c94289d30c6157510f8fb8dfa00` |
| `LinkEngKM.exe` | 345,760 | 1,138,336 | 2013-01-07 | `330a91657843391342d66c02b21300b0aa6389a4b0b9d194b60c9dd5c0c77c58` |
| `2208KM_HID.dll` | 39,760 | 111,952 | 2011-04-28 | `17abf9ff0cb9928a497eca84a5bd1e858659ba1a6ea4a6b5e9793aad53b322b4` |
| `OSW08.dll` | 38,440 | 97,320 | 2012-04-13 | `e11f1c469bf78da35fe19970f3295e2d651205abb07661692264abdf1366e6a6` |
| `LEWD.exe` | 68,296 | 122,568 | 2011-07-18 | `36019a14491a639ec7a8cfa2a590304ee6ea11e24a7622c0abe002273eeb713a` |
| `ProdLic.DLL` | 25,600 | 73,728 | 2010-03-15 | `a56cdcac0c30f419fb938724885e0a1ad45d82b695f062f4583b08b2ac45281c` |
| `OnLineUpdate.dll` | 17,920 | 57,344 | 2010-12-01 | `111c23aa3ea5c07b3b6726ec8582fb51a3fc542367ae39dc0232880e71a86abc` |
| `OnlineUpdate.exe` | 37,712 | 75,088 | 2011-01-26 | `130021f6efad7a0b92cf71b301987ff71ae6a26667c7eb1beca36aab8add4939` |
| `SKLoader.exe` (`ImageRoot`, record 28) | 445,640 | 1,084,104 | 2011-11-08 | `ee8d2d8288509ef2dea58a6017cdcf7bb96ad230311416db088ffb94b69f4d0f` |
| `ECN001.DLL` (not in `GSDD`) | 32,768 | — | 2005-03-23 | `18a8b834ef24313ec9f8bfc3413173b9488bc07f96c045ef3e9fbd1134df2f1a` |
| `Common\OTiOSW08.dll` (not in `GSDD`) | 36,176 | 95,568 | 2011-04-28 | `1a34640b3a62d8bdfba237e4dde8ef8ad3cd9411f50256a1165917df74783235` |

The two files outside the `GSDD` table come from elsewhere in the loader;
where is open (#49).

`OTiEncrypt.dll` was not found anywhere under `%TEMP%`, `%APPDATA%`,
`%LOCALAPPDATA%`, `%ProgramData%` or Program Files after the install.
Whether it exists briefly during extraction was not watched.  It is no
longer needed: every `GSDD` record is now available decrypted, which closes
[`gsdd.md`](gsdd.md) § What remains.

## First look (for #49)

Imports after unpacking, and strings, give each binary's role:

| Binary | Evidence | Role |
|---|---|---|
| `2208KM_HID.dll` | `SetupDiGetClassDevsA`, `CreateFileA` on `\\.\%c:`, `DeviceIoControl`; log strings `DoScsiCmd_direct` / `DoScsiCmd_no_direct` with a CDB dump; `2208M-Cdrom` | SCSI pass-through to the cable's CD-ROM drive letter, direct and buffered variants: the counterpart of the Mac's `SCSITask` path |
| `OSW08.dll`, `Common\OTiOSW08.dll` | `SetupDi*`, `DeviceIoControl`, `\\.\%c:`, `Enum\SCSI`; an `<otidevice>` XML template (`otivid`, `otipid`, `otisn`, `otichipversion`, `otiusbvid`/`otiusbpid`, `HidSupport`, `fwversion`); exports `OTiDll_ReadDeviceInfo`, `OTiDll_ReadSwAuthInfo`, `OTiDll_SetPasswordLogin`, … | Device discovery, device info and software authorisation |
| `LinkEngKM.exe` | `DeviceIoControl`, `CreateFileW`; pipes `\\.\pipe\OTI_GoSuite`, `OTI_GoSuiteGoInterCopyNotify`, `OTI_KMInterCopy` | Link engine: the UPipe peer (likely; to confirm) |
| `Wormhole.exe` | `SetWindowsHookExA`, `SendInput`, `SetCursorPos`, `OpenClipboard`/`GetClipboardData`/`SetClipboardData`; pipes `OTI_ClipboardAgent`, `OTI_KMLoader`, `OTI_LinkEngineWatchDog`, …; `FindCDROMDrive()` | UI, input capture and injection, clipboard: the counterpart of `KMKeyMouse` / `KMClipboard` |
| `ECN001.DLL` | Exports `OTi_Dynamic_Lib_Authorize` / `_IO` / `_Query`; `<OTIMSG>` XML; `EZCmpInstCaller.dll` | Plug-in loader for "advance function modules" |
| `SKLoader.exe` (`ImageRoot`) | `RegisterDeviceNotificationA` | Loader and device-arrival watcher |
| `LEWD.exe`, `ProdLic.DLL`, `OnLineUpdate.*` | — | Watchdog / licensing / updater (by name; unconfirmed) |

The processes talk over named pipes (`\\.\pipe\OTI_*`), so the Windows
side is split across processes where the Mac's `GoBridgeDemon` is one.

## First Windows ↔ Mac session

The usbmon capture of the install (raw, private) also holds a live session
with Wormhole.app on the Mac: same UPipe framing (`0xD8` poll,
`0xD9 0x28`/`0x2A`), a Windows `Login` (`os_type` windows), folder
browsing, clipboard `XmlPacket`s and a clipboard-file download.  It also
shows CDBs the Mac never sent (`0xF0`, `0xE1`, `0xD8` with data out,
`0xD9 0x3A`).  Findings are tracked in #50.

The deliberate session that followed (`tools/windows_capture.ps1`) is
written up in [`upipe-protocol.md`](upipe-protocol.md) § Windows ↔ Mac
session: clipboard text, RTF, HTML and images, files and folders work both
ways except a Mac → Windows file paste, and cancelling a copy shows the
abort commands.
