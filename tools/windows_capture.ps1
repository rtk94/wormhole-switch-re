<#
.SYNOPSIS
  Guided Windows-side session for the deliberate Windows <-> Mac UPipe capture (#50).

.DESCRIPTION
  Run in the Windows guest while usbmon records the Wormhole on the Linux host
  (docs/reproduction.md section 6.6) and Wormhole.app runs on the Mac.

  The script creates synthetic test files, puts each clipboard format on the
  Windows clipboard itself, tells you what to do on the Mac or in the Wormhole
  windows, and records a UTC marker for the start and end of every step, so the
  usbmon frames can be matched to steps afterwards.  After the Mac -> Windows
  steps it logs what arrived on the Windows clipboard and hashes what you pasted.

  Everything it writes goes to -WorkDir:
    files\      synthetic test files (sent to the Mac)
    inbox\      paste or upload here everything that comes from the Mac
    markers.jsonl, results.json

  Use test content only on both machines: clipboard data and file names travel
  in the capture.

.PARAMETER Plan
  full (default): the 22-step first session.  followup: the second run, for
  what the first left open (keyboard and mouse with the pointer grabbed by
  the VM viewer, Mac -> Windows file paste, the remote browser, drag and
  drop).  A followup run writes markers_followup.jsonl, results_followup.json
  and screenshots in shots\, so the first run's files stay.

.PARAMETER WorkDir
  Working folder.  Default: wormhole-capture on the Desktop, which is a
  DomainFolders entry, so the Mac can browse to it.

.PARAMETER From
  Step id to start at (to resume after an interruption).  Use -List to see ids.

.PARAMETER List
  Print the steps and exit.

.PARAMETER UploadUrl
  Base URL of the host's upload receiver.  At the end, markers.jsonl and
  results.json are PUT there.  Empty string to skip.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\windows_capture.ps1
#>
param(
    [ValidateSet('full', 'followup')][string]$Plan = 'full',
    [string]$WorkDir = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'wormhole-capture'),
    [string]$From = '',
    [switch]$List,
    [string]$UploadUrl = 'http://192.168.122.1:8765'
)

$ErrorActionPreference = 'Stop'

# The clipboard needs a single-threaded apartment.
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', $PSCommandPath,
                 '-Plan', $Plan, '-WorkDir', $WorkDir, '-UploadUrl', $UploadUrl)
    if ($From) { $argList += @('-From', $From) }
    if ($List) { $argList += '-List' }
    & powershell.exe @argList
    exit $LASTEXITCODE
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$FilesDir = Join-Path $WorkDir 'files'
$InboxDir = Join-Path $WorkDir 'inbox'
$Tag = if ($Plan -eq 'full') { '' } else { "_$Plan" }
$MarkerFile = Join-Path $WorkDir "markers$Tag.jsonl"
$ResultFile = Join-Path $WorkDir "results$Tag.json"
$ShotsDir = Join-Path $WorkDir 'shots'
$Results = [ordered]@{ plan = $Plan; started = (Get-Date).ToUniversalTime().ToString('o'); files = @{}; steps = [ordered]@{} }

# ------------------------------------------------------------------ helpers

function Write-Marker([string]$Step, [string]$Phase, [string]$Note = '') {
    $rec = [ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); step = $Step; phase = $Phase; note = $Note }
    Add-Content -Path $MarkerFile -Value ($rec | ConvertTo-Json -Compress) -Encoding UTF8
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLower()
}

function Get-TextSha256([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') })
}

function New-RandomFile([string]$Path, [long]$Size) {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] (1MB)
    $fs = [IO.File]::Open($Path, 'Create')
    try {
        $left = $Size
        while ($left -gt 0) {
            $n = [int][Math]::Min($left, $buf.Length)
            $rng.GetBytes($buf)
            $fs.Write($buf, 0, $n)
            $left -= $n
        }
    } finally { $fs.Close() }
}

function New-TestImage([string]$Path, [int]$W, [int]$H, [string]$Label, [int]$Hue) {
    $bmp = New-Object Drawing.Bitmap $W, $H
    $g = [Drawing.Graphics]::FromImage($bmp)
    for ($x = 0; $x -lt $W; $x += 4) {
        $c = [Drawing.Color]::FromArgb(255, ($Hue + $x) % 256, (2 * $x) % 256, (255 - $x) % 256)
        $g.FillRectangle((New-Object Drawing.SolidBrush $c), $x, 0, 4, $H)
    }
    $font = New-Object Drawing.Font 'Arial', 20
    $g.DrawString($Label, $font, [Drawing.Brushes]::White, 10, 10)
    $g.Dispose()
    $bmp.Save($Path, [Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

function New-CfHtml([string]$Fragment) {
    # CF_HTML: an ASCII header with byte offsets into the UTF-8 body.
    $pre = '<html><body><!--StartFragment-->'
    $post = '<!--EndFragment--></body></html>'
    $fmt = "Version:0.9`r`nStartHTML:{0:D10}`r`nEndHTML:{1:D10}`r`nStartFragment:{2:D10}`r`nEndFragment:{3:D10}`r`n"
    $enc = [Text.Encoding]::UTF8
    $startHtml = ($fmt -f 0, 0, 0, 0).Length
    $startFrag = $startHtml + $enc.GetByteCount($pre)
    $endFrag = $startFrag + $enc.GetByteCount($Fragment)
    $endHtml = $endFrag + $enc.GetByteCount($post)
    ($fmt -f $startHtml, $endHtml, $startFrag, $endFrag) + $pre + $Fragment + $post
}

function Set-ClipboardObject([hashtable]$Formats) {
    $do = New-Object Windows.Forms.DataObject
    foreach ($k in $Formats.Keys) { $do.SetData($k, $Formats[$k]) }
    [Windows.Forms.Clipboard]::SetDataObject($do, $true)
}

function Set-ClipboardFiles([string[]]$Paths) {
    $sc = New-Object Collections.Specialized.StringCollection
    foreach ($p in $Paths) { [void]$sc.Add($p) }
    [Windows.Forms.Clipboard]::SetFileDropList($sc)
}

function Get-ClipboardReport {
    $do = [Windows.Forms.Clipboard]::GetDataObject()
    $r = [ordered]@{ formats = @() }
    if ($null -eq $do) { return $r }
    $r.formats = @($do.GetFormats())
    if ([Windows.Forms.Clipboard]::ContainsText()) {
        $t = [Windows.Forms.Clipboard]::GetText()
        $r.text_chars = $t.Length
        $r.text_sha256 = Get-TextSha256 $t
        $r.text_head = $t.Substring(0, [Math]::Min(40, $t.Length))
    }
    if ([Windows.Forms.Clipboard]::ContainsImage()) {
        $img = [Windows.Forms.Clipboard]::GetImage()
        $r.image = '{0}x{1}' -f $img.Width, $img.Height
    }
    if ([Windows.Forms.Clipboard]::ContainsFileDropList()) {
        $r.files = @([Windows.Forms.Clipboard]::GetFileDropList() | ForEach-Object { Split-Path $_ -Leaf })
        # Where the GoBridge points Explorer, and whether the file is there yet.
        $r.file_paths = @([Windows.Forms.Clipboard]::GetFileDropList() | ForEach-Object {
            $i = Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue
            [ordered]@{ path = $_; exists = [bool]$i; size = $(if ($i -and -not $i.PSIsContainer) { $i.Length } else { $null }) }
        })
    }
    foreach ($f in @('Rich Text Format', 'HTML Format')) {
        if ($do.GetDataPresent($f)) {
            $v = [string]$do.GetData($f)
            $r[$f] = [ordered]@{ chars = $v.Length; sha256 = (Get-TextSha256 $v) }
        }
    }
    $r
}

function Save-Screenshot([string]$Name) {
    # The whole virtual screen, as PNG in shots\; uploaded at the end.
    New-Item -ItemType Directory -Force -Path $ShotsDir | Out-Null
    $b = [Windows.Forms.SystemInformation]::VirtualScreen
    $bmp = New-Object Drawing.Bitmap $b.Width, $b.Height
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
    $g.Dispose()
    $p = Join-Path $ShotsDir ("$Plan" + "_$Name.png")
    $bmp.Save($p, [Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Split-Path $p -Leaf
}

function Get-CursorTrace([int]$Seconds) {
    # Cursor position every 100 ms: shows when the pointer leaves for the Mac
    # (it parks at an edge) and when the Mac moves it.
    $out = New-Object Collections.ArrayList
    $end = (Get-Date).AddSeconds($Seconds)
    $last = $null
    while ((Get-Date) -lt $end) {
        $p = [Windows.Forms.Cursor]::Position
        $k = "$($p.X),$($p.Y)"
        if ($k -ne $last) { [void]$out.Add([ordered]@{ t = (Get-Date).ToUniversalTime().ToString('o'); x = $p.X; y = $p.Y }); $last = $k }
        Start-Sleep -Milliseconds 100
    }
    $s = [Windows.Forms.SystemInformation]::VirtualScreen
    [ordered]@{ screen = "$($s.Width)x$($s.Height)"; samples = $out.Count; trace = @($out | Select-Object -First 400) }
}

function Get-InboxReport {
    @(Get-ChildItem -LiteralPath $InboxDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ path = $_.FullName.Substring($InboxDir.Length + 1); size = $_.Length; sha256 = (Get-Sha256 $_.FullName) }
    })
}

function Wait-User([string]$Prompt) {
    $a = Read-Host "$Prompt  [Enter = done, s = skip, q = quit]"
    if ($a -eq 'q') { throw 'quit' }
    return ($a -ne 's')
}

# ------------------------------------------------------------- test files

function Initialize-TestFiles {
    New-Item -ItemType Directory -Force -Path $FilesDir, $InboxDir | Out-Null
    $u = [string][char]0x00FC + [char]0x00F1 + [char]0x00EF + [char]0x00E7 + [char]0x00F8 + [char]0x0111 + [char]0x00E9
    $check = [string][char]0x2713
    $spec = @(
        @{ name = 'small.txt'; text = "wormhole test file`r`nline 2`r`n" },
        @{ name = 'empty.bin'; size = 0 },
        @{ name = 'random_300k.bin'; size = 300000 },
        @{ name = 'random_20m.bin'; size = 20MB },
        @{ name = 'random_200m.bin'; size = 200MB },
        @{ name = "$u name $check.txt"; text = "unicode file name test $u $check`r`n" }
    )
    foreach ($s in $spec) {
        $p = Join-Path $FilesDir $s.name
        if (-not (Test-Path -LiteralPath $p)) {
            if ($s.ContainsKey('text')) { [IO.File]::WriteAllText($p, $s.text, (New-Object Text.UTF8Encoding $false)) }
            else { New-RandomFile $p $s.size }
        }
    }
    $tree = Join-Path $FilesDir 'folder_tree'
    New-Item -ItemType Directory -Force -Path (Join-Path $tree 'sub\deeper') | Out-Null
    foreach ($rel in @('a.txt', 'sub\b.txt', 'sub\deeper\c.txt')) {
        $p = Join-Path $tree $rel
        if (-not (Test-Path -LiteralPath $p)) { [IO.File]::WriteAllText($p, "folder tree $rel`r`n") }
    }
    for ($i = 1; $i -le 3; $i++) {
        $p = Join-Path $FilesDir ("image_$i.png")
        if (-not (Test-Path -LiteralPath $p)) { New-TestImage $p (320 + 40 * $i) 200 "image $i" (70 * $i) }
    }
    Get-ChildItem -LiteralPath $FilesDir -Recurse -File | ForEach-Object {
        $Results.files[$_.FullName.Substring($FilesDir.Length + 1)] = [ordered]@{ size = $_.Length; sha256 = (Get-Sha256 $_.FullName) }
    }
}

function F([string]$Name) { Join-Path $FilesDir $Name }

# ------------------------------------------------------------------- steps
# Each step: Id, Title, optional Setup (runs first, e.g. sets the clipboard),
# the instructions for you, and optional Check (runs after you press Enter).

$U = [string][char]0x00FC + [char]0x00F1 + [char]0x00EF + [char]0x00E7 + [char]0x00F8 + [char]0x0111 + [char]0x00E9 + ' ' + [char]0x2713 + ' ' + [char]0x65E5 + [char]0x672C

$Steps = @(
    @{ Id = 'input-w2m'; Title = 'Input, Windows controls the Mac'
       Do = 'Move the pointer across the screen edge to the Mac. On the Mac: move the mouse in a square, left/right click, scroll, type "wormhole 123" in TextEdit, press Volume Up, Volume Down, Mute, Play/Pause on the Windows keyboard (or the VM keyboard). Come back to Windows.' },
    @{ Id = 'input-m2w'; Title = 'Input, Mac controls Windows'
       Do = 'From the Mac, move the pointer across the edge to Windows. In Windows: move in a square, click, scroll, type "wormhole 456" in Notepad, press Volume Up/Down/Mute on the Mac keyboard. Go back to the Mac, then return here.' },

    @{ Id = 'cb-w2m-text'; Title = 'Clipboard Windows -> Mac: plain text'
       Setup = { [Windows.Forms.Clipboard]::SetText('wormhole plain text 0123456789') }
       Do = 'On the Mac, paste (Cmd-V) into a TextEdit plain-text document.' },
    @{ Id = 'cb-w2m-unicode'; Title = 'Clipboard Windows -> Mac: Unicode text'
       Setup = { [Windows.Forms.Clipboard]::SetText("unicode: $U") }
       Do = 'On the Mac, paste into TextEdit.' },
    @{ Id = 'cb-w2m-rtf'; Title = 'Clipboard Windows -> Mac: RTF + text'
       Setup = { Set-ClipboardObject @{
                   'Rich Text Format' = '{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}{\colortbl;\red200\green0\blue0;}\f0\fs24 wormhole \b bold\b0 , \i italic\i0 , \cf1 red\cf0 .\par}';
                   'UnicodeText' = 'wormhole bold, italic, red.' } }
       Do = 'On the Mac, paste into a TextEdit rich-text document. Note whether bold/italic/red survive.' },
    @{ Id = 'cb-w2m-html'; Title = 'Clipboard Windows -> Mac: HTML + text'
       Setup = { Set-ClipboardObject @{
                   'HTML Format' = (New-CfHtml '<p>wormhole <b>html</b> <a href="https://example.com/">link</a> &#x2713;</p>');
                   'UnicodeText' = 'wormhole html link' } }
       Do = 'On the Mac, paste into a TextEdit rich-text document.' },
    @{ Id = 'cb-w2m-image'; Title = 'Clipboard Windows -> Mac: bitmap (DIB)'
       Setup = { $img = [Drawing.Image]::FromFile((F 'image_1.png')); [Windows.Forms.Clipboard]::SetImage($img); $img.Dispose() }
       Do = 'On the Mac, paste into Preview (File > New from Clipboard) or a TextEdit rich-text document.' },
    @{ Id = 'cb-w2m-file'; Title = 'Clipboard Windows -> Mac: one file'
       Setup = { Set-ClipboardFiles @((F 'random_300k.bin')) }
       Do = 'On the Mac, paste into a Finder folder (e.g. ~/wormhole-inbox).' },
    @{ Id = 'cb-w2m-files'; Title = 'Clipboard Windows -> Mac: several files (empty, Unicode name, 20 MiB)'
       Setup = { Set-ClipboardFiles @((F 'small.txt'), (F 'empty.bin'), (Get-ChildItem -LiteralPath $FilesDir -Filter '*name*.txt').FullName, (F 'random_20m.bin')) }
       Do = 'On the Mac, paste into the Finder folder.' },
    @{ Id = 'cb-w2m-images'; Title = 'Clipboard Windows -> Mac: several image files'
       Setup = { Set-ClipboardFiles @((F 'image_1.png'), (F 'image_2.png'), (F 'image_3.png')) }
       Do = 'On the Mac, paste into the Finder folder, then also try pasting into a TextEdit rich-text document.' },
    @{ Id = 'cb-w2m-folder'; Title = 'Clipboard Windows -> Mac: a folder tree'
       Setup = { Set-ClipboardFiles @((F 'folder_tree')) }
       Do = 'On the Mac, paste into the Finder folder.' },

    @{ Id = 'cb-m2w-text'; Title = 'Clipboard Mac -> Windows: plain text'
       Do = 'On the Mac, copy a line of test text from TextEdit. Then paste it into Notepad here.'
       Check = { Get-ClipboardReport } },
    @{ Id = 'cb-m2w-rich'; Title = 'Clipboard Mac -> Windows: rich text'
       Do = 'On the Mac, copy styled text (bold/colour) from a TextEdit rich-text document. Paste into WordPad (or Word) here.'
       Check = { Get-ClipboardReport } },
    @{ Id = 'cb-m2w-image'; Title = 'Clipboard Mac -> Windows: image'
       Do = 'On the Mac, press Cmd-Ctrl-Shift-4 and drag a small area (screenshot to clipboard). Paste into Paint here.'
       Check = { Get-ClipboardReport } },
    @{ Id = 'cb-m2w-files'; Title = 'Clipboard Mac -> Windows: files'
       Do = "On the Mac, copy two or three test files in Finder (include an empty one if you can). Paste them in Explorer into: $InboxDir"
       Check = { [ordered]@{ clipboard = (Get-ClipboardReport); inbox = (Get-InboxReport) } } },
    @{ Id = 'cb-m2w-folder'; Title = 'Clipboard Mac -> Windows: folder'
       Do = "On the Mac, copy a test folder with a subfolder in Finder. Paste it in Explorer into: $InboxDir"
       Check = { Get-InboxReport } },

    @{ Id = 'browse-mac-side'; Title = 'Wormhole.app on the Mac browses Windows'
       Do = "In Wormhole.app's remote browser on the Mac: open Desktop > wormhole-capture > files, copy small.txt and random_300k.bin to the Mac; upload one test file from the Mac into wormhole-capture\inbox; in inbox create a New Folder, rename it to renamed_by_mac, then move the uploaded file to the Trash."
       Check = { Get-InboxReport } },
    @{ Id = 'browse-win-side'; Title = 'Wormhole on Windows browses the Mac'
       Do = "In the Wormhole window on Windows (tray icon), open the Mac's Desktop: copy a test file from the Mac into $InboxDir, upload small.txt from $FilesDir to the Mac, create a folder on the Mac, rename it, delete it."
       Check = { Get-InboxReport } },

    @{ Id = 'abort-w2m'; Title = 'Abort: cancel Windows -> Mac mid-transfer'
       Setup = { Set-ClipboardFiles @((F 'random_200m.bin')) }
       Do = 'On the Mac, paste into Finder, then cancel the copy while it is running (the x in the progress window, or in Wormhole.app).' },
    @{ Id = 'abort-m2w'; Title = 'Abort: cancel Mac -> Windows mid-transfer'
       Do = "On the Mac, copy a large test file (100 MB or more; e.g. mkfile 200m ~/big.bin). Paste in Explorer into $InboxDir and cancel the copy while it is running."
       Check = { Get-InboxReport } },
    @{ Id = 'dragdrop'; Title = 'Drag and drop across the edge'
       Do = "Drag small.txt from $FilesDir across the screen edge onto the Mac's Desktop. Then drag a file from the Mac back into Windows. Note what happens." },
    @{ Id = 'idle'; Title = 'Idle baseline'
       Do = 'Touch nothing for 30 seconds, then press Enter.' }
)

# Second run (-Plan followup): what the first run left open.
$FollowupSteps = @(
    @{ Id = 'settings-win'; Title = 'Wormhole settings on Windows'
       Do = 'Open the Wormhole window on Windows (tray icon; try right-click and double-click) and its settings. Leave the settings page that shows the screen arrangement or the Mac position on screen, then press Enter: the script takes a screenshot. Note the menu items and any hotkey.'
       Check = { [ordered]@{ shot = (Save-Screenshot 'settings-win') } } },
    @{ Id = 'settings-mac'; Title = 'Wormhole settings on the Mac'
       Do = 'On the Mac, open Wormhole.app and its preferences. Note on which side of the Mac screen it puts Windows, and whether keyboard/mouse sharing is enabled. Set Windows to the LEFT or RIGHT of the Mac if it is not set.' },
    @{ Id = 'grab'; Title = 'Grab the pointer in the VM viewer'
       Do = 'The VM now has no tablet device, so the viewer grabs the pointer: click inside the Windows screen. The viewer title should say "Press Ctrl+Alt to release pointer" (Ctrl+Alt releases it; do not release during the input steps). The pointer now stops at the Windows screen edges instead of leaving the window.' },
    @{ Id = 'input-edges'; Title = 'Find the edge that leads to the Mac'
       Do = 'After Enter, for 40 seconds: push the pointer hard against the left edge, then top, right, bottom, about 5 s each. If it jumps to the Mac, move the Mac pointer a little and come back. Note which edge worked. (Cursor positions are recorded.)'
       Check = { Get-CursorTrace 40 } },
    @{ Id = 'input-w2m'; Title = 'Input, Windows controls the Mac'
       Do = 'Cross to the Mac by that edge. With the VM keyboard and mouse (still grabbed): move in a square, left click, right click, scroll, type "wormhole 123" in TextEdit, press Volume Up, Volume Down, Mute, Play/Pause if the keyboard has them. Come back to Windows.' },
    @{ Id = 'input-m2w'; Title = 'Input, Mac controls Windows'
       Do = 'Release the grab (Ctrl+Alt). On the Mac, move the Mac pointer across the edge toward Windows. If it arrives, move in a square, click into THIS window, then press Enter here with the Mac keyboard.'
       Check = { [ordered]@{ typed = (Read-Host '  With the Mac keyboard, type "wormhole 456" here and press Enter'); cursor = (Get-CursorTrace 10) } } },
    @{ Id = 'm2w-file-inspect'; Title = 'Mac -> Windows file: what lands on the clipboard'
       Do = 'On the Mac, copy ONE non-empty test file in Finder (e.g. random_300k.bin from ~/wormhole-inbox). Do not paste yet. Wait 5 s, then press Enter: the script reads the Windows clipboard.'
       Check = { Get-ClipboardReport } },
    @{ Id = 'm2w-file-paste'; Title = 'Mac -> Windows file: paste in Explorer'
       Do = "Open $InboxDir in Explorer, click an empty spot in it and press Ctrl+V. If nothing happens, try right-click > Paste. Wait for any progress window to finish."
       Check = { [ordered]@{ clipboard = (Get-ClipboardReport); inbox = (Get-InboxReport) } } },
    @{ Id = 'm2w-file-desktop'; Title = 'Mac -> Windows file: paste on the Desktop'
       Do = 'On the Mac, copy the same file again. On the Windows Desktop, right-click > Paste.'
       Check = { [ordered]@{ clipboard = (Get-ClipboardReport); desktop = @(Get-ChildItem -LiteralPath ([Environment]::GetFolderPath('Desktop')) -File | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } | ForEach-Object { [ordered]@{ name = $_.Name; size = $_.Length } }) } } },
    @{ Id = 'm2w-files-two'; Title = 'Mac -> Windows: two non-empty files'
       Do = "On the Mac, copy two non-empty test files. Paste in Explorer into $InboxDir."
       Check = { [ordered]@{ clipboard = (Get-ClipboardReport); inbox = (Get-InboxReport) } } },
    @{ Id = 'browse-win'; Title = 'Look for the remote browser on Windows'
       Do = "Look through the Wormhole tray menu and window for anything that opens the Mac's files ('Remote', 'Browse', 'GO! Bridge', a Mac icon in Explorer's sidebar, a drive letter). If you find it, open the Mac's Desktop and copy a test file into $InboxDir. Leave the most useful window on screen and press Enter for a screenshot."
       Check = { [ordered]@{ shot = (Save-Screenshot 'browse-win'); inbox = (Get-InboxReport) } } },
    @{ Id = 'browse-mac'; Title = 'Remote browser on the Mac'
       Do = "In Wormhole.app on the Mac, open the remote browser for Windows (it worked with the Linux peer). Browse to Desktop > wormhole-capture > files and copy small.txt to the Mac. Note what you see." },
    @{ Id = 'dragdrop-w2m'; Title = 'Drag and drop Windows -> Mac'
       Do = "Grab the pointer again (click into the VM). Drag small.txt from $FilesDir across the Mac edge and drop it on the Mac Desktop. Note what happens." },
    @{ Id = 'dragdrop-m2w'; Title = 'Drag and drop Mac -> Windows'
       Do = "Release the grab (Ctrl+Alt). On the Mac, drag a small test file across the edge onto Windows and drop it into $InboxDir in Explorer."
       Check = { Get-InboxReport } },
    @{ Id = 'idle'; Title = 'Idle baseline'
       Do = 'Touch nothing for 30 seconds, then press Enter.' }
)
if ($Plan -eq 'followup') { $Steps = $FollowupSteps }

# ------------------------------------------------------------------- main

if ($List) {
    $Steps | ForEach-Object { '{0,-16} {1}' -f $_.Id, $_.Title }
    exit 0
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
Write-Host "Work folder: $WorkDir"
Write-Host 'Creating test files (the 200 MiB one takes a moment)...'
Initialize-TestFiles
Write-Marker 'setup' 'end' ("files=" + $Results.files.Count)

Write-Host ''
Write-Host 'Before continuing: usbmon must be recording on the Linux host, and Wormhole.app'
Write-Host 'must be running on the Mac with both sides logged in.'
[void](Wait-User 'Ready?')
Write-Marker 'session' 'start' ("guest_utc_offset_min=" + [int]([TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes))

$started = -not $From
$n = 0
try {
    foreach ($s in $Steps) {
        $n++
        if (-not $started) { if ($s.Id -eq $From) { $started = $true } else { continue } }
        Write-Host ''
        Write-Host ('[{0}/{1}] {2}  ({3})' -f $n, $Steps.Count, $s.Title, $s.Id) -ForegroundColor Cyan
        Write-Marker $s.Id 'start'
        $rec = [ordered]@{ title = $s.Title; start = (Get-Date).ToUniversalTime().ToString('o') }
        try {
            if ($s.Setup) { & $s.Setup; Write-Marker $s.Id 'setup-done' }
        } catch { $rec.setup_error = $_.Exception.Message; Write-Host "  setup failed: $($_.Exception.Message)" -ForegroundColor Yellow }
        Write-Host ('  ' + $s.Do)
        $done = Wait-User '  Done?'
        $rec.done = $done
        if ($done -and $s.Check) {
            try { $rec.check = & $s.Check } catch { $rec.check_error = $_.Exception.Message }
            if ($rec.check) {
                $j = $rec.check | ConvertTo-Json -Depth 5 -Compress
                if ($j.Length -gt 600) { $j = $j.Substring(0, 600) + ' ...' }
                Write-Host ('  ' + $j)
            }
        }
        $note = Read-Host '  Anything to note? (Enter for nothing)'
        if ($note) { $rec.note = $note }
        $rec.end = (Get-Date).ToUniversalTime().ToString('o')
        Write-Marker $s.Id 'end' $note
        $Results.steps[$s.Id] = $rec
        $Results | ConvertTo-Json -Depth 8 | Set-Content -Path $ResultFile -Encoding UTF8
    }
} catch {
    if ($_.Exception.Message -ne 'quit') { throw }
    Write-Host 'Stopped. Resume with -From <step id>.'
}

Write-Marker 'session' 'end'
$Results.inbox = Get-InboxReport
$Results.finished = (Get-Date).ToUniversalTime().ToString('o')
$Results | ConvertTo-Json -Depth 8 | Set-Content -Path $ResultFile -Encoding UTF8
Write-Host ''
Write-Host "Markers: $MarkerFile"
Write-Host "Results: $ResultFile"

if ($UploadUrl) {
    $up = @($MarkerFile, $ResultFile)
    if ($Plan -ne 'full' -and (Test-Path -LiteralPath $ShotsDir)) {
        $up += @(Get-ChildItem -LiteralPath $ShotsDir -Filter "$Plan*.png" | ForEach-Object { $_.FullName })
    }
    foreach ($f in $up) {
        try {
            Invoke-WebRequest -Uri ("$UploadUrl/" + (Split-Path $f -Leaf)) -Method Put -InFile $f -UseBasicParsing | Out-Null
            Write-Host "Uploaded $(Split-Path $f -Leaf)"
        } catch { Write-Host "Upload of $(Split-Path $f -Leaf) failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
}
Write-Host 'Now stop tcpdump on the Linux host.'
