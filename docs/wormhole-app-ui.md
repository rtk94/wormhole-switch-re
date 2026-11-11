# Wormhole.app UI (frontend) — function-level analysis (#12)

Tooling: Ghidra 12.1.4 via REA (see `docs/pe-analysis.md` *Tooling*).
Bundle source: `/tmp/wormhole_extract/Wormhole.app/` (the
`/media/$USER/Wormhole/Wormhole.app/` mount was absent in this
environment; the `/tmp/wormhole_extract` copy is the same bundle
extracted from the ISO — all hashes below are for that copy).
Binaries are scratch extracts (not tracked):

```
Wormhole (Contents/MacOS/Wormhole)
              bdb98af157ae8a4e3e2fb1781d4c2aab62736fb38776ece80c2b891d022a4fb5
              mach-o-universal i386+ppc_7400, 599072 B, 628 procedures, 4230 strings
GoBridgeDemon bdb98a… (see docs/mac-gobridge.md) — contents/PlugIns/GoBridgeDemon.app
DownloadUpdateTool
              (contents/PlugIns/DownloadUpdateTool.app, 63316 B)
```

Evidence:
- `binary_overview` → `ev_221d4b0080563318be3e978400278692ca4e2bf37d25c06ad330a90129918664` (image base `0x1000`, 35 segments, ObjC sections `__class`/`__inst_meth`/`__message_refs`/`__category` present)
- `list_strings` summary → `ev_8e832b3f7292554118a4044fca7ec975b5f602081d8687437812372b663b7fdf` (parent `ev_18262efa9565b54bc3201a2a69debd377baa48e9b756f9faf8d839152daa1242`, view `ev_e6628afb72d7e097d0160627a50bbcb6281b14a2516ca6f51ec4aa5bab163b51`)
- `list_procedures` → `ev_189fd2226320c62a269043069bb2a568870820600e59466d2e145b2502f0e090`
- `_main` (0x2684) pseudocode → `ev_ccaf942fdb9f172096a7c826cec4d3b8368aa1087f4e597289bbb47093ca3e7c` (`search_procedures _main` → `ev_8aedb372fdf1f351f91adc60d5e6bce8f6b0aa6e318370d6c44fb0b4f7a7d55d`)

## 1. What the frontend is (and is not)

- **Frontend executable:** `Contents/MacOS/Wormhole` (`CFBundleExecutable=Wormhole`, `com.KaiJet.Wormhole`, `Product Name=Wormhole Switch`, `1.0.0.10`, `LSBackgroundOnly=true`, `NSMainNibFile=MainMenu`, `NSPrincipalClass=NSApplication`). Frameworks linked: Cocoa, Foundation, AppKit, IOKit, DiskArbitration, CoreServices, CoreFoundation, Carbon, ApplicationServices.
- **Not** `WormholeShell` (CLI), **not** `GoBridgeDemon` (daemon, at `Contents/PlugIns/GoBridgeDemon.app/Contents/MacOS/GoBridgeDemon`, `com.KaiJet.GoBridgeDemon`, `LSUIElement=true`), **not** `DownloadUpdateTool` (`com.KaiJet.DownloadUpdateTool`, `Update url=http://www.mct.com.tw/wh88update/download/update_online/APP`).
- The frontend **never touches USB/SCSI/HID directly**: no `OTi_SendHIDPacket`, `OTiTransporter`, `SendSCSICommand*`, `CGEvent`/`CGEventTap`, or `0711`/`2211` strings in its inventory (local `strings` scan: 0 hits each; `IOUSB` 2 hits — IOKit enumeration only, see §4). It speaks to GoBridgeDemon over `NSConnection` + `NSDistributedNotificationCenter`, and GoBridgeDemon → OTiTransfer → `SendSCSICommandSendData` produces the `0xD9` CDB (see `docs/mac-gobridge.md`, `docs/protocol-mouse-upipe.md`).

### 1.1 `Contents/MacOS/Wormhole` entry

`_main` (0x2684, 9 bytes) is a tail-jump to `NSApplicationMain` (`_NSApplicationMain` thunk at 0x28c7a):
```c
void _main(void){ _NSApplicationMain(); return; }
```
Pseudocode → `ev_ccaf942fdb9f172096a7c826cec4d3b8368aa1087f4e597289bbb47093ca3e7c`.
All real startup is nib-driven (`MainMenu.nib` → `MainController_awakeFromNib`).

## 2. Objective-C classes / UI components

`list_procedures` shows 628 procedures, of which ~470 are ObjC methods. Principal classes (addresses are entry points):

| Class | Entry examples | Role |
|---|---|---|
| `MainController` | `+[initialize]` 0x2da4, `-init` 0x31dd, `-awakeFromNib` 0x3b3a, `-applicationDidFinishLaunching:` 0xa57a, `-applicationWillTerminate:` 0x12ede, `-applicationDockMenu:` 0x63a0, `-validateUserInterfaceItem:` 0x63ae | Main window controller, file browser, dock/menu owner, daemon client |
| `GBDockSplitView` | `-awakeFromNib` 0x137b4, `-draggingEntered:` 0x13efe, `-performDragOperation:` 0x14247, `-tableView:namesOfPromisedFilesDroppedAtDestination:forDraggedRowsWithIndexes:` 0x148aa | Dock (staging) split view — local/remote pools |
| `GBPathControl` | `-initWithFrame:` 0x1650c, `-mouseDown:` 0x16f97, `-mouseUp:` 0x16fd9, `-mouseDragged:` (string) | Finder-style path bar in main window |
| `GBOutlineView` | `-awakeFromNib` 0x17da2, `-menuForEvent:` 0x17f15 | Remote file outline view |
| `GBTableView` | `-awakeFromNib` 0x1a44f, `-menuForEvent:` 0x1a574, `-tableView:draggedImage:endedAt:operation:` 0x1a4ae | Dock pool tables |
| `GBDesktopButton` / `GDDesktopButtonCell` | `-awakeFromNib` 0x18c60, `-performDragOperation:` 0x18db1, `+_roundedPathInRect:radius:` 0x17f7e | Mini-panel desktop button (drag target) |
| `CustomWindow` / `CustomView` | `-initWithContentRect:styleMask:backing:defer:` 0x1f6b1, `-mouseDown:` 0x1f758; `CustomView_connectionInfo` 0x1f92b, `_welcomeInfo` 0x1f936 | "Connected Image" window (`_connInfoWnd`) + connection-info view |
| `HotkeyTextField` | `-setApp:` 0x1e376, `-textDidChange:` 0x1e384, `-keyUp:` 0x1e389 | Preferences hotkey capture field |
| `Preference` | `+setKMSwitch:` 0x1d20e, `+setClipboard:` 0x1d2d1, `+setHotkey:` 0x1d292, `+setPCPosition:` 0x1d253, `+getKMSwitch` 0x1d508, `+getClipboard` 0x1d5b0, `+initSettings` 0x1df38 | `NSUserDefaults`/login-item store for KM/clipboard/hotkey/position |
| `WatchDog` | `-initWithObject:` 0x1e5c6, `-launchDemon` 0x1e811, `-daemonIsAlive:` 0x1ea36 | Daemon process watchdog (see §3) |
| `DetectDevice` | `-initWithObject:` 0x1eee8, `-detectDevice:` 0x1eff3, `-checkUpdate` 0x1f31c | Cable/daemon detection (see §4) |
| `THMRemoteFileWrapper` / `THMVolumeInfo` / `WinDriveInfo` | `-initWithPath:` 0x1b001, `-directoryContents` 0x1bd5f; `-initWithVolumePath:displayName:andType:` 0x1cdc7 | Remote file/volume models (`GBPathExtension` category: `_image` 0x269e, `_gbIsDirectory` 0x2708, `_gbFileIcon` 0x27aa, `_gbFileKindString` 0x2a91) |
| `GBFileSizeFormatter` / `GBFileSizeTransformer` | 0x18817 / 0x18b1c | File-size display |
| `THMGBError` / `GBClientErrorHandler` / `THMGBErrorHandler` | 0x1aa6c / 0x1a738 / 0x1a5b9 | Per-file transfer errors (`codeForFile:`, `errorMessageForFile:`) |
| `TCallScript`, `_RunLoopFunction` 0x1e51f, `_FindDevices` 0x1ed79, `_findUsbInterface` 0x1ec06 | — | AppleScript helper + IOKit enumeration used by `DetectDevice` |

`get_objc_classes` with a UI-pattern filter returned 0 rows (that provider reports only imported-class fixups, not defined classes) — class inventory above is from `list_procedures` (`ev_189fd…`), not from that API.

## 3. Startup → daemon handshake

1. `MainController_awakeFromNib` (0x3b3a, pseudocode → `ev_aea219fe5411346192a9b16953d64cd2d563e884d97b952a13b39e2723c96d34`):
   - Single-instance guard: iterates `NSWorkspace launchedApplications`, compares `NSApplicationBundleIdentifier`; on match logs `AnInstanceoftheAPPisalreadyrunning…` and `[NSApp terminate:]`.
   - Reads `DemonBundleIdentifier` (`com.KaiJet.GoBridgeDemon`) from `Info.plist`, `_ProcessIsRunningWithBundleID` → `_KillProcess` if already running (stale daemon).
   - Creates `DetectDevice` (`initWithObject:`), starts toolbar (`GO Bridge` identifier, `toggleToolbarShown:` wired to the standard-window button), registers dragged types (`NSFilenamesPboardType`) on the desktop button, binds `NSTreeController` (`path` KVO) for the sidebar outline view, restores `column_order`/column widths and `shows_*_column` booleans from `NSUserDefaults`, sets `doubleClickInListView:` as the outline-view double action, `setDraggingSourceOperationMask:forLocal:` etc.
2. `MainController_applicationDidFinishLaunching:` (0xa57a, pseudocode → `ev_81ff02f0797124c893bdf0ca618ed4e2f8f37bb11918716e53a2b23d2f45be5a`):
   - `Gestalt('sysv')` → logs `KMSwitchstartsup_OSversion…appversion…`.
   - Registers sleep/wake observers (`receiveSleepNote:` 0x866b / `receiveWakeNote:` 0x86be) and `NSDistributedNotificationCenter` observer `theNotificationHandler:` (0xa3cc) on the executable's last path component.
   - **Conditional menu pruning from `Info.plist`:** `BridgeMenuEnable=false` → removes Bridge/position items from `_mainMenu` (0x128) and dock menu (0x140); `EnableBlockRemoteGOBridge=false` → removes `Block Remote File Shuttle`; `CheckNewUpdateMenuEnable=true` → keeps `Check New Update`; `EZODDMenuEnable=false` → removes EZODD items, else registers `ezoddNotificationHandler:` for `OTi5000DeviceStatus`.
   - Sets collection behaviour on all panels, calls `localizeItems` (0x1171b).
3. `WatchDog_launchDemon` (0x1e811, pseudocode → `ev_ae228dde7b7bff35da529d6f36d0c0d3066044f69c3e8b5bcb5413c67933ef7a`):
   - Splits `DemonBundleIdentifier` on `.`, builds `<last-component>.app`, appends to `[NSBundle builtInPlugInsPath]` → `Contents/PlugIns/<…>.app`. Logs `pathToDemonBundle:%@`.
   - `[NSBundle bundleWithPath:]` → `[NSTask launchedTaskWithLaunchPath:arguments:]` (empty args, retained), logs `demontask:%@`; fallback `[[NSWorkspace sharedWorkspace] launchApplication:]`.
4. Daemon announces liveness via `NSDistributedNotificationCenter` (`GBDaemonisalive` — posted by GoBridgeDemon, see `docs/mac-gobridge.md`). `WatchDog_daemonIsAlive:` (0x1ea36, → `ev_1ca6e6180ece284d913bf7d2d98025da5996779cf4919f35a8d3b39b0517d2a4`) clears its one-shot flag and calls `deferredInitialAfterAwakingFromNib` on the main controller.
5. `MainController_deferredInitialAfterAwakingFromNib` (0x5c16, → `ev_7d20b19e03f8d15f207dee76a89020bfa65539f253bc60f558362bcc74891eed`):
   - `*(self+0x1b4)=0; [self remoteProxy] echo:sender:` with `This is GO Bridge` (CFString `cf_ThisisGO_Bridge`).
   - `[remoteProxy getLicenceNo]` → `<2` ⇒ `[NSApp terminate:]`.
   - `[remoteProxy isDeviceIn]` (with `This is GO Bridge`) ⇒ `NotifySettingDidChange:` codes **6, 0x11 (17), 4, 3, 8, 7**, then if `Preference getEnableAccess` → `enableAccessSetting:` (0x518f), then `sendLoginCommand:` (0x5aef); else `fileManagerDeviceDidRemove:`.
6. `MainController_sendLoginCommand:` (0x5aef, → `ev_6438d04d86d6f0f3fa89c62ab6d9e4eaf26fa8f7312ec824c592ebc73e9cdc7d`):
   - If `[proxy isConnected]==0`: `[proxy isRemoteDevOn]` ? `NotifySettingDidChange:0x13 (19)` : `0`.
   - Else if not `didLoginToRemote`: `[proxy loginToRemoteWithName:0]`; if `remoteDidLogin` → store `remoteIsWindows`/`remoteOSVersion`/`remoteLoginName`, `setRemoteComputerVersion:`.

### 3.1 The proxy: `-[MainController remoteProxy]` (0x3a07)

Pseudocode → `ev_6c5803bcf20de5556fae404872c1bd2a1266d905c3e9bdfdf325d73098887e80` (`search_procedures remoteProxy` → `ev_9bc66c129ba8d373f2be9b9cb37b480b275583c9aa39b85f0395792525dd22fa`). Singleton at `self+0x1b4`:

```c
proxy = [NSConnection rootProxyForConnectionWithRegisteredName:@"GodDamnDaemon" host:0];
[proxy.connectionForProxy addRequestMode:NSModalPanelRunLoopMode];
[proxy.connectionForProxy addRequestMode:NSEventTrackingRunLoopMode];
[proxy.connectionForProxy enableMultipleThreads];
[proxy setProtocolForProxy:<DAT_0002f3fc>];
[proxy setKMLinkHandleDelegate:self];
[proxy setDirHandleDelegate:self];
```

So **every frontend→daemon call is a distributed-object message** to `GodDamnDaemon` (the same name GoBridgeDemon registers — see `docs/mac-gobridge.md`). String evidence: `GodDamnDaemon`, `NSConnection`, `rootProxyForConnectionWithRegisteredName:host:`, `connectionForProxy`, `addRequestMode:`, `enableMultipleThreads`, `setProtocolForProxy:`, `setKMLinkHandleDelegate:`, `setDirHandleDelegate:` (all in `ev_6c5803…` referenced_strings). The daemon's `THMFileManager` implements the receiving side (`handleSystemEvent:`, `postMouseHIDEventToRemote:`, `handleLogin`, …).

## 4. Device detection (frontend side)

`DetectDevice_detectDevice:` (0x1eff3, → `ev_e1d3e3802ded126c45f161c214aa63ba7332dc0908ceea2abd26f74f45606b1d`):
1. `DemonBundleIdentifier` → strip to `<name>.app` → `builtInPlugInsPath` → `bundleWithPath:`; on failure logs `Cannotfinddemonbundle`.
2. `privateFrameworksPath` + `OTiTransfer.framework` → `bundleWithPath:`; on failure `Cannotfindframeworkbundle`.
3. Reads `idVendor` / `idProduct` **integers** from that framework's `Info.plist` (same `0711:2211` as Linux — see `docs/mac-gobridge.md` § *Device matching*; plist integers, not strings, hence `0711` 0 hits).
4. `_FindDevices(idVendor, idProduct, 0)` (0x1ed79, IOKit: `IOMasterPort` → `IOServiceGetMatchingServices` → `IORegistryEntryCreateCFProperties`/`CheckParents`) → 0 ⇒ `noDevice` (0x100f4); else log `Devicein`, `setDevVolumeName:`, `checkUpdate` ⇒ `deviceIn` (0x100f9) or `upateMacKMLink` (0xf965).

`upateMacKMLink` (0xf965, → `ev_7301ce7a1cceb49a97f4f7f6d1c779b7d0e448ba4eb17ea16a05929c206a3c81`): `[Preference removeLoginItem]`, scans `/Volumes/<devVolumeName>` for a `*.app`, `NSTask launchedTaskWithLaunchPath:` with arg `1`, then `[NSApp terminate:]`. Failures log `updateMacKMLinkget…contenterror…`, `UpdateMacKMLink.Findthe.appondevicefailed!!`, `UpdateMacKMLink.Launchappfromdevicefailed`. (This is the self-update that replaces `KMKeyMouse.dylib`/`MacKMLink` from the cable volume — the event engine in `docs/mac-gobridge.md`.)

## 5. Windows, menus, and IB connections

Parsed from `Contents/Resources/MainMenu.nib/designable.nib` (InterfaceBuilder3 XIB, 520 KB) + `keyedobjects.nib`. Object census (243 objects):

```
103× NSMenuItem, 24× NSButton, 19× NSTextField, 16× NSCustomView,
10× NSTableColumn, 9× NSWindowTemplate, 8× NSMenu, 8× NSScroller,
6× NSImageView, 6× NSButtonCell, 5× NSClipView, 4× NSCustomObject,
4× NSScrollView, 3× NSBox, 3× NSView, 3× NSMatrix, 2× NSOutlineView,
2× NSTableView, 2× NSProgressIndicator, 1× each NSSplitView, NSDrawer,
NSComboBox, NSTreeController, NSPopUpButton, NSUserDefaultsController
```

### 5.1 Windows (9 `NSWindowTemplate`)

| id | Class | Title | Frame `{ {x,y}, {w,h} }` | Style |
|---|---|---|---|---|
| 397148372 | `NSPanel` | `FILE SHUTTLE` | `{{196,179},{650,450}}` | 271 (min `420×210`) |
| 719148724 | `NSWindow` | `Confirmation` | `{{361,352},{355,146}}` | 1 |
| 658923283 | `NSWindow` | `About` | `{{316,213},{699,296}}` | 3 |
| 676284497 | `NSWindow` | `Preferences` | `{{300,117},{491,532}}` | 7 |
| 243439784 | `NSPanel` | `View Options` | `{{196,246},{179,258}}` | 147 |
| 410780716 | `NSPanel` | *(mini panel)* | `{{196,441},{86,69}}` | 287 |
| 270149464 | `NSWindow` | `Copy` (overwrite) | `{{196,376},{465,131}}` | 1 |
| 106134548 | `NSWindow` | `Copy` (progress) | `{{196,421},{403,89}}` | 1 |
| 851737193 | `CustomWindow` | `Connected Image` | `{{708,531},{644,340}}` | 15 |

IB outlets (`label` in `IBConnectionRecord`s, 166 connections):
`_MainWindow`→397148372, `_MiniPanel`→410780716, `_PreferenceWindow`→676284497, `_ViewOptionsPanel`→243439784, `_AboutPanel`→658923283, `_OverwritePanel`→270149464, `_ProgressPanel`→106134548, `_exitConfirmationPanel`→719148724, `_connInfoWnd`→851737193 (window) + `_connInfoView`→`CustomView` inside it, `_Drawer`→108627922 (`NSDrawer`, `parentWindow` = main window, `contentView` = `GBDockSplitView`), `_AdvancedView`→`NSSplitView` 482067771, `_SidebarOutlineView`→`GBOutlineView` 77337981, `_ListView`→985683851, `_PathControl`→`GBPathControl` 936077223, `_DesktopButton`→278175340, `_DockSplitView`→831408008 (the `GBDockSplitView` itself holds `_LocalPool`/`_RemotePool` views + `_LocalPoolTable`/`_RemotePoolTable` `NSTableView`s), `_StatusBar`/`_StatusTextField1`/`_StatusTextField2`, `_ToolbarNavView`, `_ToolbarDockModeView`, `_ToolbarNewFolderView`, `_ContentViewHolder`, `_BrowserViewHolder`, `_SimpleView(Hold)`, `_ListViewScollView`, `_ListViewContentsController`→`NSTreeController`, `_MainWndTableHdrView`, `_ColumnModePreviewView`, `_ConfirmFiles`, `_Devices`, `_Places`, `_Toolbar`, `_History`, `_DirectoryContents`, `_RecentPathes`, `_IsDrawerOpened`, `_ListViewColumns`, `_CopyProgressBar`→`NSProgressIndicator`, `_CancelProgressButton`, `_CopyProgressBar`, `_Devices`, `_hotkeyTextField`→`HotkeyTextField`, `_posComboBox`→`NSComboBox` 150761904, `_switchRatioMatrix`→`NSMatrix` 138970066, `_clipboardRatioMatrix`→`NSMatrix` 755331550, `_residentAppButton`, `_useHotkeySwitchOnlyButton`, `_enableAccessButton`, `_showConnInfoButton`, `_mainMenu`, `_mainODDMenu`, `_mainKMMenu`, `_dockMenu`, `_selectDVDMenu`, `_posMenuItem`, `_posDockMenuItem`, `_tmpSwitchCtrlMenuItem`, `_tmpClipboardCtrlMenuItem`, `_blockRemoteFSMenuItem`, `_autoshareMenuItem`, `_checkNewUpdateMenuItem`, …

### 5.2 Menu bar & dock menu

Application menu (`%@` = ProductName):
`Block Remote File Shuttle` (`blockRemoteFSMenuItemSelected:`),
`The Position of Other PC :` ▸ `Left/Up/Down Side of This PC` (`posMenuItemSelected:`),
`Disable Keyboard and Mouse Control temporarily` (`disableSwitchMenuItem:`),
`Disable Clipboard Share temporarily` (`disableClipboardMenuItem:`),
`Preferences` (⌘,), `Check New Update` (`checkNewUpdateMenuItemSelected:`), `About`, `Services`, `Hide`, `Hide Others`, `Show All`, `Quit` (`quitMenuItemSelected:`).
`File`: `Open…` (`openDocument:`), `Close` (`performClose:`), `Move to Trash` (`removeSelectedFiles:`), `New Folder` (`newFolder:`).
`Edit`: `Copy` (`copy:`), `Paste` (`paste:`), `Select All`. `View`: `Show/Hide Path Bar` (`togglePathBar:`), `Show/Hide Status Bar` (`toggleStatusBar:`), `Show/Hide Dock` (`toggleDrawer:`), `Show Toolbar` (`toggleToolbarShown:`), `Customize Toolbar…`, `View Options` (`toggleViewOptions:`).
`Window`: `Zoom` (`performZoom:`), `Show/Hide Dock`. `Help`: `%@ Help`. `EZODD`: `Auto share` (`onClickAutoShareMenuItem:`), `Select DVD` ▸. `FILE SHUTTLE` (order-front), dock menu (`applicationDockMenu:` 0x63a0 → `ev_0ffc29dde9480075b11d4d4c1fbd22075bd4a00c6577d8881ff6c747e27fd151`, returns `self+0x140`) mirrors the app-menu KM items.

Context menus (built in code, not in the nib — see `GBOutlineView_menuForEvent:` 0x17f15, `GBTableView_menuForEvent:` 0x1a574):
sidebar/list: `Open`, `Add to Dock` (`addSelectedItemsToPool:`), `Rename` (`renameSelectedItem:`), `Copy`, `Paste`, `Move to Trash`, `New Folder`, `Select All`; dock-pool tables: `Copy`, `Paste`, `Remove From Dock` (`removeSelectedItemFromPool:`), `Clear` (`clearLocalPool:`/`clearRemotePool:`).

### 5.3 Preferences window controls

`HotkeyTextField` (`updateHotkeySetting:`), `NSComboBox` position (`updatePositionSetting:`), `NSMatrix` KM switch (`updateSwitchSetting:`), `NSMatrix` clipboard (`updateClipboardSetting:`), `NSButton` resident (`updateResidentSetting:`), `Use Hotkey Switch Only` (`updateUseHotkeySwitchOnlySetting:`), `Enable Access` (`updateEnableAccessSetting:`, `enableAccessSetting:` 0x518f), `Show Connection Information` (`updateShowConnInfoSetting:`), `Disable Keyboard Setup`. All persist via `Preference` class methods (0x1d1c9–0x1d8f0) and fan out via `NotifySettingDidChange:` (see §6).

### 5.4 Localizable strings

`Contents/Resources/English.lproj/Localizable.strings` (UTF-16BE, 36 KB, header `Localizable.strings / MacKMLink / Created by Oti on 2011/3/28`) — 201 `key=value` pairs. Notable: `Please Connect the Device`, `Connecting to remote computer...`, `Please remove the cable from the other computer` (update procedure), `Enable Access for assistive devices` / `…requires that the Accessibility be enabled.` (AX permission flow for the daemon's event tap), `Use Hotkey to switch only`, `Show Connection Information`, `Remote computer is off-line!`, `Copy finished with %d errors!`, `There is no enough temporary disk space…`, `Drop files here` (dock split view), `Fail to drop file into here! …`, `Currently copying file…`, `Warning before deleting items`, `Keep mini panel on top of other windows`, column headers `Name`/`Date Modified`/`Date Created`/`Kind`/`Local`/`Remote`/`Remote Computer`, `View Options` (`Show columns:`, `Icon size:`, `Text size:`).

## 6. Mapping user actions → 0xD9 / UPipe

**Core rule:** the frontend emits *no* `0xD9` CDB. Every action below is a
distributed-object message (`NSConnection GodDamnDaemon`) or a
`NSDistributedNotificationCenter` post to GoBridgeDemon; the daemon then
either (a) calls `OTi_SendHIDPacket` → `OTiTransporter::sendHIDPacket` →
`SendSCSICommandSendData(D9 <type> <12 payload> OT)` for HID, or
(b) queues a UPipe/file/clipboard command (`THMGBServer`/`THMGBClient`
handlers, `postUPipeMessageToRemote:`) that rides `SendSCSICommand*`
**with** a bulk data phase (see `docs/mac-gobridge.md` § *HID wire format*,
§ *File-transfer command surface*; `docs/protocol-mouse-upipe.md` §§1–3).

| # | User action (UI) | Frontend entry (address, evidence) | → Daemon (`remoteProxy` selector) | → Wire |
|---|---|---|---|---|
| 1 | Launch app; daemon not running | `WatchDog_launchDemon` 0x1e811 (`ev_ae228dde…`) → `daemonIsAlive:` 0x1ea36 (`ev_1ca6e618…`) | *(process spawn; no protocol msg)* | — |
| 2 | Cable attached / device found | `DetectDevice_detectDevice:` 0x1eff3 (`ev_e1d3e380…`) → `_FindDevices` 0x1ed79 | `noDevice`/`deviceIn`/`upateMacKMLink` (local) | IOKit match on `idVendor:idProduct` (plist ints) |
| 3 | First login (auto) | `deferredInitialAfterAwakingFromNib` 0x5c16 (`ev_7d20b19e…`) | `echo:sender:` (`This is GO Bridge`), `getLicenceNo`, `isDeviceIn`, `NotifySettingDidChange:` 6/17/4/3/8/7 | UPipe settings + login (daemon `handleLogin`) |
| 4 | `sendLoginCommand:` | 0x5aef (`ev_6438d04d…`) | `isConnected`, `isRemoteDevOn` → `NotifySettingDidChange:` 0/19, else `loginToRemoteWithName:0`, `remoteDidLogin` | UPipe login; on success remote OS/name cached |
| 5 | Mouse move / click / scroll **while remote session active** | *(no frontend code — daemon's `CGEventTapCreate(kCGHIDEventTap)`)* → GoBridgeDemon `myCGMOuseEventCallback` 0x2499 → `THMFileManager_handleSystemEvent:` 0x20f7e → `KMLink handleCarbonEvent` → `CKMEvent::SendMouseEvent` | `postMouseHIDEventToRemote:` (daemon) → `OTi_SendHIDPacket(1, packet)` | **`0xD9 '3' <4-byte boot-mouse report + 8×0x00> OT`**, no data phase (see `protocol-mouse-upipe.md` §1) |
| 6 | Key press **while remote** | *(daemon tap)* → `OnKey` → `SendKeyboardEvent` | `postKeyboardHIDEventToRemote:` → `OTi_SendHIDPacket(2, packet)` | **`0xD9 '4' <8-byte boot-keyboard report + 4×0x00> OT`** |
| 7 | Media key (play/next/eject…) **while remote** | *(daemon tap, type 14 subtype 8)* → `SendMultimediaKeyEvent(this,2,usage,0)` | `postMultimediaHIDEventToRemote:` 0x1bccb → `OTi_SendHIDPacket(3, packet)` | **`0xD9 '6' <usage at byte 2> OT`** (see `protocol-mouse-upipe.md` §2.1) |
| 8 | Seamless switch (cursor hits edge) | daemon `BoundaryDetectionIn…` → `SwitchToRemote`/`ProcessSwitchToRemoteCmd` | daemon-internal; frontend only learns via `receiveSwitchToRemoteXML` (0xbe84, `ev_762439fb…`, direction 0–3 remap) and `updateState:` (0xb8ad, `ev_e790c7b6…`, dock-icon switch) | `SendSwitchToRemoteCmd:andX:andY:andW:andH:` — UPipe switch XML, **not** 0xD9 |
| 9 | Hotkey switch (user-configured) | `HotkeyTextField_keyUp:` 0x1e389 sets `Preference setHotkey:`; daemon `OnHotKey`/`RegisterEventHotKey` fires | `onHotkeySwitch:switchDirection:` (frontend stub 0xbe3d → `ev_bd16c713…`, logs `onHotkeySwitch %d %d`, returns 1) | daemon-side `SwitchFromRemote`/`HotKeySwitchBack`; wire = UPipe switch command |
| 10 | Menu: *Disable Keyboard and Mouse Control temporarily* | `disableSwitchMenuItem:` 0x1064a (`ev_2954ff05…`) toggles `self+0x194` | `NotifySettingDidChange:` **0** (disable) / **2** (enable) | UPipe setting; daemon gates `post*HIDEventToRemote` on its enable flag |
| 11 | Menu: *Disable Clipboard Share temporarily* | `disableClipboardMenuItem:` 0x106df (`ev_2562fe4d…`) toggles `self+0x195` | `NotifySettingDidChange:` **1** / **3** | UPipe setting; daemon/KMClipboard gate |
| 12 | Preferences: KM switch / clipboard / position / hotkey-only / resident / AX | `setKMSwitch:` 0xb696 (`ev_67f84798…`) → `Preference setKMSwitch:`; `setClipboard:` 0xb6e8 (`ev_9b85abca…`); `updateKMSetting:andDirection:useHotkeyOnly:` 0xbef4 (`ev_ab960322…`, stub `return;` — real work is in daemon) | `NotifySettingDidChange:` (codes 4/7/8/17 from §3 step 5) | UPipe setting **or** re-login; no 0xD9 |
| 13 | Menu: *The Position of Other PC* (Left/Up/Down) | `posMenuItemSelected:` 0x1027c / `posDockMenuItemSelected:` 0x104da | `Preference setPCPosition:` → `NotifySettingDidChange:` | UPipe setting |
| 14 | Menu: *Block Remote File Shuttle* | `blockRemoteFSMenuItemSelected:` 0x10774 | `NotifySettingDidChange:` (block flag; plist `EnableBlockRemoteGOBridge`) | UPipe setting; daemon gates `THMGBServer` file handlers |
| 15 | Drag file from remote outline view → dock pool / local folder (drop) | `MainController_outlineView:validateDrop:proposedItem:proposedChildIndex:` 0x9777 → `outlineView:acceptDrop:item:childIndex:` 0x98f6 → `deferDownloadPromisedFile:` 0x9a5e; `GBDockSplitView_performDragOperation:` 0x14247; `GBDesktopButton_performDragOperation:` 0x18db1 | `fileManager:startDownloadSession:` 0xde1e / `fileManager:multipleDownloadWillStart:session:` 0xe279 / `fileManager:startDownload:…` → daemon `handleDownloadMultipleFile` | **UPipe file transfer with data phase** (`candidate_upipe`, magic TBD — `protocol-mouse-upipe.md` §3); progress via `fileManager:downloadFile:percentage:session:` 0xe3b3, `…:downloadFile:didFinishSession:` 0xe436; overwrite UI = `Copy` panels (270149464/106134548) |
| 16 | Drag local file → remote (upload) | `GBDockSplitView_tableView:writeRowsWithIndexes:toPasteboard:` 0x1468d / `MainController_tableView:writeRowsWithIndexes:toPasteboard:` 0x9375, `paste:` 0x7ed9, `copy:` 0x11f25 | `fileManager:uploadWillStart:session:` 0xd57f / `fileManager:multipleUploadWillStart:session:` 0xd3d4 → daemon `handleUploadFileData`/`handleUploadMultipleFile` | **UPipe upload with data phase**; progress `fileManager:uploadFile:percentage:session:` 0xd5c6 |
| 17 | Copy in outline view (`⌘C`) / Paste (`⌘V`) | `copy:` 0x11f25, `paste:` 0x7ed9; `outlineView:writeItems:toPasteboard:` 0x9572 | clipboard marshalling **in daemon**: `buildClipboardFileData:` / `handleDownloadClipboardFile:to:` (`THMFileManager`, 0x… — see `mac-gobridge.md` § *File-transfer command surface*) → `KMClipboard.dylib marshallFromUPipeMsg` | **UPipe clipboard message**, *not* HID (see `mac-gobridge.md` § *KMClipboard*) |
| 18 | Text copy between hosts (general pasteboard) | `generalPasteboard` (string), `tableView:writeRowsWithIndexes:toPasteboard:` | same KMClipboard UPipe path (text/RTF/HTML/TIFF/…) | UPipe (see #17) |
| 19 | New Folder / Rename / Move to Trash in remote view | `newFolder:` 0x72af, `renameSelectedItem:` 0x81c4, `removeSelectedFiles:` 0x7587 | `handleMakeNewDirectory` / `handleRenameFile` / `handleDeleteFile` (daemon `THMGBServer`) | UPipe command (XML packet) |
| 20 | Double-click remote file (open) | `doubleClickInListView:` 0x7864 → `openSelectedFiles:` 0x805e | download-to-temp (`tempFolder` 0x7f81) then `openDocument:` 0x81ad | UPipe download, then local `NSWorkspace` open |
| 21 | Menu: *Check New Update* | `checkNewUpdateMenuItemSelected:` 0x11b06 → `startUpdate:` 0x11c3d | launches `DownloadUpdateTool` | HTTP (`Update url` in its plist), not cable |
| 22 | Menu: *Show Connection Information* | `showConnInfo:` 0x126f7 → `CustomWindow` 851737193 (`_connInfoWnd`) | reads `remoteComputerName`/`remoteComputerVersion` (set in §3 step 6) | — (local display of cached daemon state) |
| 23 | Quit (`⌘Q` / dock Quit) | `quitMenuItemSelected:` 0x10211 → `handleQuitEvent:withReplyEvent:` 0xfd50 (`ev_566bfd35…`) → `confirmExit:` 0xfeac / `cancelExit:` 0x1008b; `applicationWillTerminate:` 0x12ede (`ev_e1d04a11…`) | `terminateDemon` 0xace6 (`ev_b9a5e865…`): `[remoteProxy terminateDemon]`, poll `_ProcessIsRunningWithBundleID` ×50×100 ms, else `_KillProcess`, log `killdemonprocess`/`Demon terminated!!!` | — (process teardown) |

### 6.1 `NotifySettingDidChange:` code table (observed)

From decompiled call sites (all via `remoteProxy`):

| Code | Call site | Meaning (inferred from context) |
|---|---|---|
| 0 | `disableSwitchMenuItem:` (0x1064a) disable; `sendLoginCommand:` (0x5aef) not-connected | KM switch off |
| 1 | `disableClipboardMenuItem:` (0x106df) disable | clipboard off |
| 2 | `disableSwitchMenuItem:` enable | KM switch on |
| 3 | `disableClipboardMenuItem:` enable; `deferredInitial…` (0x5c16) | clipboard on |
| 4 | `deferredInitial…` | position / switch-mode param |
| 6 | `deferredInitial…` | device-connected param |
| 7 | `deferredInitial…` (+ `enableAccessSetting:`) | AX-access param |
| 8 | `deferredInitial…` | KM/clipboard param |
| 17 (`0x11`) | `deferredInitial…` | hotkey param |
| 19 (`0x13`) | `sendLoginCommand:` (`isRemoteDevOn`) | remote-dev-on param |

The daemon's `THMFileManager` maps these to its `self+0x51`-style enable flags and `KMKeyMouse`/`KMClipboard` gates. Exact enum names live in GoBridgeDemon (not in this binary) — codes above are the *wire-visible* integers.

## 7. What this frontend does NOT do

- **No CGEvent tap, no `CGWarpMouseCursorPosition`, no `CGEventCreateMouseEvent`** — all cursor warping/replay is daemon/KMKeyMouse (`docs/mac-gobridge.md` § *KMKeyMouse*).
- **No `OTiTransfer` import** — `OTi_SendHIDPacket`/`SendSCSICommand*` are daemon+dylib only.
- **No socket strings** — frontend↔daemon is `NSConnection` (`GodDamnDaemon`); peer traffic is SCSI CDBs (daemon side).
- `updateKMSetting:andDirection:useHotkeyOnly:` (0xbef4) and `MainController_updateKMSetting…` are **stubs** in this build (`return;`, `ev_ab960322…`) — the KM settings push is actually `Preference` + `NotifySettingDidChange:`.

## 8. Unknowns / next steps

- UPipe file/clipboard CDBs — resolved: `0xD8` poll plus `0xD9 0x28`/`0x2A` 64 KiB packets (`docs/upipe-protocol.md`), decoded by `tools/wormhole_parse.py`.
- `NotifySettingDidChange:` enum names — require GoBridgeDemon `THMFileManager` decompile of the receiving switch.
- `setProtocolForProxy:` protocol object (`DAT_0002f3fc`) — interface definition for the distributed-object protocol; extract from GoBridgeDemon's `NSConnection` registration if needed.
-ppc slice of the universal binary was not analyzed (Ghidra analyzed the i386 slice, as in prior docs).

## 9. Related files

- `docs/mac-gobridge.md` — GoBridgeDemon + OTiTransfer + KMKeyMouse/KMClipboard/FileChgEvent function-level analysis (the 0xD9 side).
- `docs/protocol-mouse-upipe.md` — mouse relative-move encoding, `D9 '3'/'4'/'6'` framing, UPipe candidate structure.
- `docs/pe-analysis.md` — Windows SKLoader/OTiArchive (same vendor family).
