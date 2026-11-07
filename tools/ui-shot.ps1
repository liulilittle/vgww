# ============================================================================
# ui-shot.ps1 - CLI direct-page screenshot bridge (S5.20 D1/D2) + batch12 T1
# DPI tier protocol.
#
# Launches vgww.exe with --config=<path> --ui-page=<id> (native UI starts on
# the requested page, no manual navigation), polls for the main window, then
# captures via the app's own debug `screenshot` op (GDI PrintWindow INSIDE the
# process; occlusion-independent and DPI-correct - it returns the physical
# client size, so PS never queries physical screen coordinates; see D-1/D-2 in
# .opencode/discover.md).
#
# Page identity fingerprint (D2): the sidebar paints a 3 px #007AFF accent bar
# inside the selected nav row (logical x in [16,19]); the script translates
# the requested page id to its nav row and verifies the frame shows the accent
# bar at exactly that row plus a dark sidebar background. A frame that is
# bright / bar-less / bar-at-wrong-row is a fingerprint MISS -> retry, and if
# the retries expire it is reported and the exit code is non-zero.
#
# ----------------------------------------------------------------------------
# batch12 T1 (2026-10-15): -Scale tier mode.
#
# -Scale <0.5|0.75|1.0|1.25|1.5> drives a SINGLE debug batch
#     [dpi -> resize -> metrics -> render(paint) -> screenshot -> state]
# in that exact order and hard-asserts:
#   * dpi echo scale == requested tier and state.scale == requested tier;
#   * metrics.dpi == 96 * tier (window/renderer DPI binding);
#   * render.paint_count >= metrics.paint_count + 1 (a full paint really ran
#     between the measurements - this is the anti-stale-frame assertion; the
#     render(paint) op is structurally required, `wait` cannot substitute
#     because it never sleeps);
#   * screenshot dims == 980*tier x 640*tier EXACTLY (op report AND png bytes);
#   * page fingerprint at the requested scale.
# Out-of-range / unsupported -Scale values are a hard usage error (exit 2) -
# the old silent clamp [0.9,2.5] -> 1.0 is REMOVED; nothing is ever silently
# clamped or fell back.
#
# -Protocol seam (negative-case harness, default Auto):
#   Auto    = Full when -Scale is given, else legacy screenshot-only;
#   Full    = the 6-op tier protocol above (requires -Scale);
#   NoRender= [dpi, resize, screenshot, state] - deliberately WITHOUT the
#             render(paint) op (C4 race probe; see batch12 audit B 3.5);
#   Off     = [screenshot] only - deliberately un-protocolled (R4 negative:
#             with -Scale the app still sits at the real system scale, so the
#             dims assertion must FAIL instead of stamping a wrong frame
#             as the requested tier).
#
# -Evidence <path> writes a JSON sidecar (raw op envelopes, png sha256, dims,
# fingerprint, tree/draw_ops canonical JSON) for the tier gate driver
# (ui-tier-gate.ps1) and for audit replay.
#
# Legacy mode (no -Scale, no -Protocol): same single `screenshot` op as
# S5.20, but the derived scale `w/980` is now ASSERT-then-use: the frame must
# be consistent with the 980x640 logical window (|h - 640*s| <= 1, s in
# [0.5,3.0]) or the run is an explicit FAIL - the old silent `clamp to 1.0`
# is gone.
#
# Exit codes (-Scale given / strict): 0 PASS, 1 FAIL/BLOCKED, 2 usage/ERROR,
# 3 kill-ceiling failure. Legacy (no -Scale): 0 PASS or BLOCKED (S5.20
# contract), 1 derived-scale assertion failure, 2 exe missing, 3 kill failure.
#
# Iron rules: the vgww process is Stop-Process -Force'd no matter what
# (success or failure), with a hard 30 s ceiling; output PNG:
# <OutDir>/s520-shot-<id>.png (default OutDir = repo /logs); feedback:
# three-zone mean/std + hwnd + fingerprint + protocol asserts.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools/ui-shot.ps1 `
#       -Page <id> [-Config <repo>\config.json] [-Exe ...\vgww.exe] `
#       [-Scale 1.25] [-Protocol Auto|Full|NoRender|Off] [-Evidence path.json] `
#       [-OutDir <repo>\logs]
# ============================================================================
param(
  [Parameter(Mandatory=$true)][string]$Page,
  [string]$Config = "$PSScriptRoot\..\config.example.json",
  [string]$Exe = "$PSScriptRoot\..\build\Release\vgww.exe",
  [int]$DebugPort = 19777,
  [double]$Scale = -1,
  [ValidateSet("Auto","Full","NoRender","Off")][string]$Protocol = "Auto",
  # batch19 R4-P3: reading direction of the captured language. RTL mirrors the
  # sidebar accent bar to the item's right edge, so the fingerprint samples the
  # mirrored x window (the row identity + dark check are unchanged).
  [ValidateSet("ltr","rtl")][string]$Dir = "ltr",
  [string]$Evidence = "",
  [string]$OutDir = "$PSScriptRoot\..\logs",
  [int]$SettleMs = 600,
  [int]$PollSec = 5,
  [int]$KillCeilingSec = 30,
  [int]$MaxAttempts = 3
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class S520N {
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
}
"@

# ---------------------------------------------------------------------------
# D1c (2026-10-14): window identification helpers. vgww.exe (console
# subsystem) owns BOTH the VgwwWindow and a ConsoleWindowClass console for the
# same PID; MainWindowHandle can latch onto the console before the UI window
# exists (observed under CPU load), so captures documented a black console or
# the wallpaper instead of the UI. FindUiWindowHwnd picks the first visible
# top-level window whose class is NOT ConsoleWindowClass.
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class S520Window {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
    [DllImport("user32.dll", CharSet = CharSet.Ansi)] public static extern int GetClassNameA(IntPtr hWnd, StringBuilder className, int maxLength);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    public static IntPtr FindUiWindowHwnd(uint targetPid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr hWnd, IntPtr lParam) {
            uint pid;
            GetWindowThreadProcessId(hWnd, out pid);
            if (pid == targetPid && IsWindowVisible(hWnd)) {
                var sb = new StringBuilder(256);
                GetClassNameA(hWnd, sb, sb.Capacity);
                if (sb.ToString() != "ConsoleWindowClass") { found = hWnd; return false; }
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
"@

# Geometry / identity constants (mirrors src/ui/theme.h + src/ui/controls.*).
# The window is borderless (WM_NCCALCSIZE returns the full window as client),
# so a physical screenshot pixel == logical DIP * scale.
# ---------------------------------------------------------------------------
$navOrder = @("dashboard","leases","portmap","firewall","ratelimit","bridge","settings","about","console")
$rowMap = @{}
for ($i = 0; $i -lt $navOrder.Count; $i++) { $rowMap[$navOrder[$i]] = $i }
$kRowH = 32.0; $kPitch = 36.0
$kBarCountMin = 16                   # base count at s>=1; sub-1 scales linearly (batch15: raised 12->16)
$kSidebarDarkMax = 70.0              # mean luminance of the left gutter under 70 => dark theme panel

function Get-Zone([System.Drawing.Bitmap]$bmp, [int]$x0, [int]$y0, [int]$x1, [int]$y1) {
  $sum = 0.0; $sum2 = 0.0; $n = 0
  for ($x = $x0; $x -lt $x1 -and $x -lt $bmp.Width; $x += 2) {
    for ($y = $y0; $y -lt $y1 -and $y -lt $bmp.Height; $y += 2) {
      $c = $bmp.GetPixel($x, $y)
      $v = ($c.R + $c.G + $c.B) / 3.0
      $sum += $v; $sum2 += $v * $v; $n++
    }
  }
  $m = $sum / $n; $s = [Math]::Sqrt([Math]::Max(0.0, ($sum2 / $n) - ($m * $m)))
  return (([Math]::Round($m, 1)), ([Math]::Round($s, 1)))
}

function Test-Fingerprint([System.Drawing.Bitmap]$bmp, [float]$scale, [string]$id) {
  # Nav rows: titlebar 40 + stack pad 12 + row 32/36 pitch; the accent bar is
  # painted INSIDE the selected nav item at item.x + 4 with nav items at
  # x = 12 (controls.cpp; tree: shell.nav.dashboard rect [12,52,196,32]),
  # i.e. x in [16,19] logical, row centre y = 68 + 36*row. All physical
  # positions = logical * scale.
  $exp = $rowMap[$id]
  $w = $bmp.Width; $h = $bmp.Height
  if ($null -eq $exp) {
    return [pscustomobject]@{ hit = $false; row = -1; cnt = 0; dark = $false;
                              reason = "unknown page id '$id'" }
  }
  $counts = New-Object 'System.Collections.Generic.List[int]'
  for ($i = 0; $i -lt $navOrder.Count; $i++) {
    $cy = (68.0 + 36.0 * $i) * $scale              # expected bar centre y (physical)
    $yTop = [int][Math]::Floor($cy - 14.0 * $scale)
    $yBot = [int][Math]::Ceiling($cy + 14.0 * $scale)
    if ($Dir -eq "rtl") {
      # The 220 px sidebar mirrors to the window's RIGHT edge, so the nav
      # item (and its accent bar) sits at a width-dependent x - the old
      # hardcoded [199,206] assumed the LTR item x=12 and never matched.
      # The bar is the LTR window [14,21] mirrored about the client width:
      # [W-21, W-14] (W = logical client width); e.g. W=980 -> [959,966]
      # which covers the measured bar [961,964] at item right edge inset 4.
      $logicalW = [double]$w / [double]$scale
      $x0 = [int][Math]::Floor(($logicalW - 21.0) * $scale)
      $x1 = [int][Math]::Ceiling(($logicalW - 14.0) * $scale)
    } else {
      $x0 = [int][Math]::Floor(14.0 * $scale)
      $x1 = [int][Math]::Ceiling(21.0 * $scale)    # bar x is [16,19]; pads absorb AA
    }
    $cnt = 0
    for ($x = $x0; $x -lt $x1 -and $x -lt $w; $x++) {
      for ($y = $yTop; $y -lt $yBot -and $y -lt $h; $y += 2) {
        $c = $bmp.GetPixel($x, $y)
        $r = [int]$c.R; $g = [int]$c.G; $b = [int]$c.B
        if ($b -gt 110 -and ($b - $r) -gt 70 -and ($b - $g) -gt 40) { $cnt++ }
      }
    }
    $counts.Add($cnt)
  }
  $mRow = -1; $mCnt = 0
  for ($i = 0; $i -lt $navOrder.Count; $i++) {
    if ($counts[$i] -gt $mCnt) { $mCnt = $counts[$i]; $mRow = $i }
  }
  # batch15: sampled bar window ~s^2; byte-stable measured counts for tiers 0.5/0.75/1.0/1.25/1.5 are 9/14/30/48/72.
  # Count floor = round(16*min(1,s)) -> 8/12/16/16/16 (max tightening keeping >=1 measured-count margin at 0.5; k12's blind band cnt in [6,7] is now rejected).
  # Row-identity and dark-sidebar checks are unchanged.
  $countMin = [int][Math]::Max(4, [Math]::Round($kBarCountMin * [Math]::Min(1.0, [double]$scale)))
  # dark sidebar: sample the panel interior (left 8..200 logical px), below the
  # titlebar (y>40 logical), mean luminance must stay under the dark threshold.
  $sum = 0.0; $n = 0
  $sx0 = [int][Math]::Floor(8.0 * $scale)
  $sx1 = [int][Math]::Floor(200.0 * $scale)
  $sy0 = [int][Math]::Floor(44.0 * $scale)
  for ($x = $sx0; $x -lt $sx1 -and $x -lt $w; $x += 6) {
    for ($y = $sy0; $y -lt $h; $y += 6) {
      $c = $bmp.GetPixel($x, $y)
      $sum += ($c.R + $c.G + $c.B) / 3.0
      $n++
    }
  }
  $dark = ($n -eq 0) -or (($sum / $n) -lt $kSidebarDarkMax)
  $reason = "OK"
  if ($mCnt -lt $countMin)     { $reason = "no accent bar (max=$mCnt < $countMin)" }
  elseif ($mRow -ne $exp)      { $reason = "bar row=$mRow exp=$exp" }
  elseif (-not $dark)          { $reason = "sidebar not dark (mean=$([Math]::Round($sum/$n,1)))" }
  $hit = ($mCnt -ge $countMin) -and ($mRow -eq $exp) -and $dark
  return [pscustomobject]@{ hit = $hit; row = $mRow; cnt = $mCnt; dark = $dark;
                            reason = $reason }
}

# ---------------------------------------------------------------------------
# batch12 T1: tier / protocol validation (fail loudly, never clamp).
$kTiers = @(0.5, 0.75, 1.0, 1.25, 1.5)
$scaleGiven = ($Scale -gt 0)
if (-not $scaleGiven -and $PSBoundParameters.ContainsKey('Scale')) {
  Write-Output "ERROR -Scale $Scale is not a positive tier value (allowed 0.5/0.75/1.0/1.25/1.5; silent legacy fallback is forbidden)"
  exit 2
}
if ($scaleGiven) {
  $tierOk = $false
  foreach ($t in $kTiers) { if ([Math]::Abs($Scale - $t) -lt 1e-9) { $tierOk = $true; break } }
  if (-not $tierOk) {
    $msg = "ERROR unsupported -Scale $Scale (allowed 0.5/0.75/1.0/1.25/1.5; silent clamp is forbidden)"
    Write-Output $msg
    exit 2
  }
}
$mode = $Protocol
if ($mode -eq "Auto") { $mode = $(if ($scaleGiven) { "Full" } else { "ScreenshotOnly" }) }
elseif ($mode -eq "Off") { $mode = "ScreenshotOnly" }
elseif (($mode -eq "Full" -or $mode -eq "NoRender") -and -not $scaleGiven) {
  Write-Output "ERROR -Protocol $Protocol requires -Scale (tier protocol needs a target tier)"
  exit 2
}
$strict = $scaleGiven
$expectedW = 0; $expectedH = 0
if ($scaleGiven) {
  $expectedW = [int][Math]::Round(980.0 * $Scale)
  $expectedH = [int][Math]::Round(640.0 * $Scale)
}

$stamp = { param([DateTime]$t) $t.ToString("yyyy-MM-dd HH:mm:ss") }
$id = $Page -replace '[^A-Za-z0-9._-]', '_'
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$outPng = Join-Path $OutDir "s520-shot-$id.png"
$outLog = Join-Path $OutDir "s520-shot-$id.log"
$startT = Get-Date
$scaleLabel = if ($scaleGiven) { "$Scale" } else { "legacy" }
$line = "===== ui-shot -Page=$Page Config=$Config Scale=$scaleLabel Protocol=$mode start=$(& $stamp $startT) ====="
$line | Add-Content -LiteralPath $outLog
Write-Output $line

if ($navOrder -notcontains $Page) {
  $w2 = "WARN unknown page '$Page' (app will fall back to the home page)"
  $w2 | Add-Content -LiteralPath $outLog
  Write-Output $w2
}

if (-not (Test-Path -LiteralPath $Exe)) {
  $e = "ERROR vgww exe not found: $Exe"
  $e | Add-Content -LiteralPath $outLog
  Write-Output $e
  exit 2
}

$argv = @("--config=$Config", "--ui-page=$Page", "--ui-debug-port=$DebugPort")
# The app writes ui-debug-screenshot.png into its CWD, so launch it with a
# scratch dir unique per debug port (parallel tier runs use distinct ports).
$shotDir = Join-Path $env:TEMP "vgww-uishot-$DebugPort"
if (-not (Test-Path -LiteralPath $shotDir)) { New-Item -ItemType Directory -Path $shotDir | Out-Null }
$shotPng = Join-Path $shotDir "ui-debug-screenshot.png"
if (Test-Path -LiteralPath $shotPng) { Remove-Item -LiteralPath $shotPng -Force }
$p = Start-Process -FilePath $Exe -ArgumentList $argv -WorkingDirectory $shotDir -PassThru
"PID=$($p.Id) launched=$(& $stamp (Get-Date))" | Add-Content -LiteralPath $outLog

$deadline = (Get-Date).AddSeconds($PollSec)
$hwnd = [IntPtr]::Zero
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 250
  $p.Refresh()
  if ($p.HasExited) { break }
  $h = [S520Window]::FindUiWindowHwnd([uint32]$p.Id)
  if ($h -ne [IntPtr]::Zero) { $hwnd = $h; break }
}

$result = ""
$resultKind = ""
$fp = $null
$scaleUsed = 0.0
$finalW = 0; $finalH = 0; $finalSha = ""
$attemptsUsed = 0
$paintDelta = -1
$passedAttempt = $false
$attemptLog = New-Object System.Collections.Generic.List[string]
if ($p.HasExited) {
  $result = "BLOCKED reason=EXITED(code=$($p.ExitCode)) before window"
  $resultKind = "BLOCKED"
} elseif ($hwnd -eq [IntPtr]::Zero) {
  $result = "BLOCKED reason=NOWINDOW after $PollSec s"
  $resultKind = "BLOCKED"
} else {
  for ($try = 1; $try -le $MaxAttempts; $try++) {
    $attemptsUsed = $try
    Start-Sleep -Milliseconds $SettleMs
    if (Test-Path -LiteralPath $shotPng) { Remove-Item -LiteralPath $shotPng -Force }
    $batch = $null
    switch ($mode) {
      "Full" { $batch = @(@{op="dpi";scale=$Scale}, @{op="resize";w=980;h=640},
                          @{op="metrics"}, @{op="render";mode="paint"},
                          @{op="screenshot"}, @{op="tree"}, @{op="draw_ops"},
                          @{op="state"}) }
      "NoRender" { $batch = @(@{op="dpi";scale=$Scale}, @{op="resize";w=980;h=640},
                              @{op="screenshot"}, @{op="tree"}, @{op="draw_ops"},
                              @{op="state"}) }
      "ScreenshotOnly" { $batch = @(@{op="screenshot"}) }
    }
    $resp = $null
    try {
      $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$DebugPort/debug" -Method Post `
                -Body (ConvertTo-Json -InputObject $batch -Compress -Depth 4) `
                -ContentType 'application/json' -TimeoutSec 10
    } catch {
      $attemptLog.Add("try=$try protocol=$mode debug POST failed: $($_.Exception.Message)")
      continue
    }
    $rs = @($resp.results)
    $reasons = New-Object System.Collections.Generic.List[string]
    $opDpi = $null; $opResize = $null; $opMetrics = $null; $opRender = $null
    $opShot = $null; $opState = $null; $opTree = $null; $opOps = $null
    if ($mode -eq "Full" -and $rs.Count -ge 8) {
      $opDpi = $rs[0]; $opResize = $rs[1]; $opMetrics = $rs[2]
      $opRender = $rs[3]; $opShot = $rs[4]; $opTree = $rs[5]
      $opOps = $rs[6]; $opState = $rs[7]
    } elseif ($mode -eq "NoRender" -and $rs.Count -ge 6) {
      $opDpi = $rs[0]; $opResize = $rs[1]; $opShot = $rs[2]
      $opTree = $rs[3]; $opOps = $rs[4]; $opState = $rs[5]
    } elseif ($rs.Count -ge 1) {
      $opShot = $rs[0]
    } else {
      $reasons.Add("empty batch response")
    }
    if ($null -ne $opDpi) {
      if (-not $opDpi.ok) { $reasons.Add("dpi op failed: $($opDpi.error)") }
      elseif ([Math]::Abs([double]$opDpi.data.scale - $Scale) -gt 1e-4) {
        $reasons.Add("dpi echo scale=$($opDpi.data.scale) exp=$Scale")
      }
    }
    if ($null -ne $opResize -and -not $opResize.ok) { $reasons.Add("resize op failed: $($opResize.error)") }
    if ($null -ne $opMetrics) {
      if (-not $opMetrics.ok) { $reasons.Add("metrics op failed: $($opMetrics.error)") }
      else {
        $expDpi = 96.0 * $Scale
        if ([Math]::Abs([double]$opMetrics.data.dpi - $expDpi) -gt 0.5) {
          $reasons.Add("metrics.dpi=$($opMetrics.data.dpi) exp=$expDpi")
        }
      }
    }
    if ($null -ne $opRender) {
      if (-not $opRender.ok) { $reasons.Add("render op failed: $($opRender.error)") }
      elseif ($opRender.data.blocked) { $reasons.Add("render paint blocked: $($opRender.data.reason)") }
      elseif ($null -ne $opMetrics -and $opMetrics.ok) {
        $d = [long]$opRender.data.paint_count - [long]$opMetrics.data.paint_count
        if ($d -lt 1) { $reasons.Add("paint_count delta=$d exp>=1") } else { $paintDelta = $d }
      }
    }
    if ($null -ne $opState) {
      if ([Math]::Abs([double]$opState.data.scale - $Scale) -gt 1e-4) {
        $reasons.Add("state.scale=$($opState.data.scale) exp=$Scale")
      }
    }
    $opW = -1; $opH = -1
    if ($null -ne $opShot) {
      if (-not $opShot.ok) { $reasons.Add("screenshot op failed: $($opShot.error)") }
      elseif ($opShot.data.blocked) { $reasons.Add("screenshot op blocked: $($opShot.data.reason)") }
      else {
        $opW = [int]$opShot.data.width; $opH = [int]$opShot.data.height
        if ($scaleGiven -and ($opW -ne $expectedW -or $opH -ne $expectedH)) {
          $reasons.Add("op dims ${opW}x${opH} exp ${expectedW}x${expectedH}")
        }
      }
    }
    if (-not (Test-Path -LiteralPath $shotPng)) {
      $reasons.Add("app wrote no png")
      $attemptLog.Add("try=$try protocol=$mode op_dims=${opW}x${opH} reasons=[$($reasons -join '; ')]")
      continue
    }
    $bmp = New-Object System.Drawing.Bitmap $shotPng
    $w = $bmp.Width; $h = $bmp.Height
    $sUse = 0.0
    if ($scaleGiven) {
      $sUse = $Scale
      if ($w -ne $expectedW -or $h -ne $expectedH) {
        $reasons.Add("png dims ${w}x${h} exp ${expectedW}x${expectedH}")
      }
    } else {
      # batch12 legacy path: assert-then-use the derived scale (no clamp).
      $sUse = $w / 980.0
      if ($sUse -lt 0.5 -or $sUse -gt 3.0) {
        $reasons.Add("derived scale $([Math]::Round($sUse,4)) outside [0.5,3.0] (no silent clamp)")
      } elseif ([Math]::Abs($h - 640.0 * $sUse) -gt 1.0) {
        $reasons.Add("png dims ${w}x${h} inconsistent with 980x640 logical window (derived s=$([Math]::Round($sUse,4)))")
      }
    }
    $fp = Test-Fingerprint $bmp $sUse $Page
    $sbw = [int][Math]::Floor(220.0 * $sUse)
    $tbh = [int][Math]::Floor(40.0 * $sUse)
    $t = Get-Zone $bmp 0 0 $w $tbh
    $sb = Get-Zone $bmp 0 $tbh $sbw $h
    $ct = Get-Zone $bmp $sbw $tbh $w $h
    $fpGate = ($mode -ne "NoRender")
    if ($fpGate -and -not $fp.hit) { $reasons.Add("fingerprint: $($fp.reason)") }
    try { $bmp.Save($outPng, [System.Drawing.Imaging.ImageFormat]::Png) } catch { }
    $bmp.Dispose()
    $scaleUsed = $sUse
    $finalW = $w; $finalH = $h
    $attemptLog.Add("try=$try protocol=$mode dims=${w}x${h} op_dims=${opW}x${opH} title=[$($t[0])/$($t[1])] sidebar=[$($sb[0])/$($sb[1])] content=[$($ct[0])/$($ct[1])] fp_hit=$($fp.hit) row=$($fp.row) cnt=$($fp.cnt) dark=$($fp.dark) reasons=[$($reasons -join '; ')]")
    if ($reasons.Count -eq 0) { $passedAttempt = $true; break }
  }
  $attemptLog | ForEach-Object { $_ | Add-Content -LiteralPath $outLog; Write-Output $_ }
  if (Test-Path -LiteralPath $outPng) { $finalSha = (Get-FileHash -LiteralPath $outPng -Algorithm SHA256).Hash }
  $topLine = "hwnd=$hwnd scale=$([Math]::Round($scaleUsed,2)) visible=$([S520N]::IsWindowVisible($hwnd)) capture=app-screenshot-op protocol=$mode attempts=$attemptsUsed"
  $lastLine = if ($attemptLog.Count -gt 0) { $attemptLog[$attemptLog.Count - 1] } else { "" }
  if ($passedAttempt) {
    $resultKind = "PASS"
    $result = "PASS $topLine dims=${finalW}x${finalH} fp_hit=1 row=$($fp.row) expRow=$($rowMap[$Page]) cnt=$($fp.cnt) paint_delta=$paintDelta sha256=$finalSha png=$outPng"
  } else {
    $rr = $lastLine -replace '^.*reasons=\[', '' -replace '\]$', ''
    if ($rr -eq $lastLine) { $rr = $lastLine }
    $legacyScaleFail = (-not $strict) -and ($rr -match 'derived scale|inconsistent with 980x640')
    if (-not $strict -and -not $legacyScaleFail) {
      $resultKind = "BLOCKED"
      $result = "BLOCKED $topLine dims=${finalW}x${finalH} reason=$rr"
    } else {
      $resultKind = "FAIL"
      $result = "FAIL $topLine dims=${finalW}x${finalH} reason=$rr"
    }
  }
}
$result | Add-Content -LiteralPath $outLog
Write-Output $result

# batch12 T1: evidence sidecar for the tier gate driver / audit replay.
if ($Evidence -ne "" -and ($resultKind -eq "PASS" -or $resultKind -eq "FAIL")) {
  $treeOk = $false; $treeCanon = ""; $opsOk = $false; $opsCount = -1; $opsCanon = ""
  if ($null -ne $opTree -and $null -ne $opOps) {
    # batch22 D-BASELINE-EVIDENCE-TIME: the tree/draw_ops are sampled INSIDE
    # the capture batch (right after the screenshot), so the evidence reflects
    # the exact frame the PNG shows. The old post-capture re-query raced the
    # second-resolution dashboard uptime text between evidence and pixels
    # (PNG pair shas stayed byte-stable while the sampled tree flipped 1s/2s).
    $treeOk = [bool]$opTree.ok
    if ($treeOk) { $treeCanon = (ConvertTo-Json -InputObject $opTree.data -Depth 64 -Compress) }
    $opsOk = [bool]$opOps.ok
    if ($opsOk) {
      $opsCount = [int]$opOps.data.count
      $opsCanon = (ConvertTo-Json -InputObject $opOps.data -Depth 64 -Compress)
    }
  } elseif (-not $p.HasExited -and $hwnd -ne [IntPtr]::Zero) {
    try {
      $mb = @(@{op="tree"}, @{op="draw_ops"})
      $mresp = Invoke-RestMethod -Uri "http://127.0.0.1:$DebugPort/debug" -Method Post `
                 -Body (ConvertTo-Json -InputObject $mb -Compress -Depth 4) `
                 -ContentType 'application/json' -TimeoutSec 10
      if ($mresp.results.Count -ge 2) {
        $treeOk = [bool]$mresp.results[0].ok
        if ($treeOk) { $treeCanon = (ConvertTo-Json -InputObject $mresp.results[0].data -Depth 64 -Compress) }
        $opsOk = [bool]$mresp.results[1].ok
        if ($opsOk) {
          $opsCount = [int]$mresp.results[1].data.count
          $opsCanon = (ConvertTo-Json -InputObject $mresp.results[1].data -Depth 64 -Compress)
        }
      }
    } catch { }
  }
  $evDir = Split-Path -Parent $Evidence
  if ($evDir -ne "" -and -not (Test-Path -LiteralPath $evDir)) { New-Item -ItemType Directory -Path $evDir | Out-Null }
  $fpJson = $null
  if ($null -ne $fp) {
    $fpJson = [ordered]@{ hit = $fp.hit; row = $fp.row; cnt = $fp.cnt; dark = $fp.dark; reason = $fp.reason }
  }
  $dpiEcho = $null; $stateScale = $null; $metricsDpi = $null
  $pcBefore = $null; $pcAfter = $null
  if ($null -ne $opDpi -and $opDpi.ok) { $dpiEcho = [double]$opDpi.data.scale }
  if ($null -ne $opState -and $opState.ok) { $stateScale = [double]$opState.data.scale }
  if ($null -ne $opMetrics -and $opMetrics.ok) {
    $metricsDpi = [double]$opMetrics.data.dpi
    $pcBefore = [long]$opMetrics.data.paint_count
  }
  if ($null -ne $opRender -and $opRender.ok -and -not $opRender.data.blocked) {
    $pcAfter = [long]$opRender.data.paint_count
  }
  $ev = [ordered]@{
    schema = "b12-ui-shot-evidence/1"
    page = $Page
    tier = $(if ($scaleGiven) { $Scale } else { [Math]::Round($scaleUsed, 6) })
    protocol = $mode
    result = $resultKind
    run_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    config = $Config
    exe = $Exe
    debug_port = $DebugPort
    expected_w = $expectedW
    expected_h = $expectedH
    png = $outPng
    sha256 = $finalSha
    width = $finalW
    height = $finalH
    fingerprint = $fpJson
    paint_delta = $paintDelta
    dpi_echo_scale = $dpiEcho
    state_scale = $stateScale
    metrics_dpi = $metricsDpi
    metrics_paint_count = $pcBefore
    render_paint_count = $pcAfter
    attempts = $attemptsUsed
    tree_ok = $treeOk
    tree_canon = $treeCanon
    draw_ops_ok = $opsOk
    draw_ops_count = $opsCount
    draw_ops_canon = $opsCanon
  }
  [System.IO.File]::WriteAllText($Evidence, (ConvertTo-Json -InputObject $ev -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
}

# Iron rule: force-kill regardless of outcome, hard 30 s ceiling.
$killT = Get-Date
$ceiling = (Get-Date).AddSeconds($KillCeilingSec)
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
if (-not $p.HasExited) {
  while ((Get-Date) -lt $ceiling -and -not $p.HasExited) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 250
  }
}
$p.Refresh()
$killed = $p.HasExited
$interval = [Math]::Round(($killT - $startT).TotalSeconds, 1)
$mut = "kill=$(& $stamp $killT) interval=$interval s ceiling=$KillCeilingSec s"
$mut | Add-Content -LiteralPath $outLog
Write-Output $mut
$left = @(Get-Process -Name vgww -ErrorAction SilentlyContinue).Count
$lr = "leftover_vgww=$left"
$lr | Add-Content -LiteralPath $outLog
Write-Output $lr
if (-not $killed) { $nk = "WARN process did not exit before ceiling"; $nk | Add-Content -LiteralPath $outLog; Write-Output $nk; exit 3 }
if ($resultKind -eq "PASS") { exit 0 }
if ($resultKind -eq "FAIL" -and -not $strict) { exit 1 }
if ($resultKind -eq "BLOCKED" -and -not $strict) { exit 0 }   # S5.20 contract
exit 1
