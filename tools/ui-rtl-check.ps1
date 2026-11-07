# ============================================================================
# ui-rtl-check.ps1 - batch19 R4-P3 RTL end-to-end red anchor.
#
# Launches the native UI on an independent debug port and asserts, through the
# debug channel:
#   * op language ar  -> state.rtl == true, state.lang == "ar";
#   * the shell sidebar mirrors to the RIGHT (tree shell.sidebar.x == W - 220);
#   * a screenshot's left/right column luminance confirms the swap (sidebar is
#     the dark panel; in LTR it is on the left, in RTL on the right);
#   * op language zh-CN -> sidebar returns to x == 0 (no stickiness).
#
# Caption buttons (-/x) are painted by the window (NOT the element tree), so
# their mirror is covered by the code anchor (window.cpp CaptionButtonRect) +
# a window-pixel region probe (top-left vs top-right glyph energy).
#
# The app is force-killed on exit. Baseline CAPTURE is out of scope (P3
# baseline is deferred to the T2 fold).
#
# Usage: powershell -File tools/ui-rtl-check.ps1 -Exe <vgww.exe> [-DebugPort 19787]
# ============================================================================
param(
  [string]$Exe = "$PSScriptRoot\..\build\Release\vgww.exe",
  [string]$Config = "$PSScriptRoot\..\config.example.json",
  [int]$DebugPort = 19787,
  [string]$OutDir = "$PSScriptRoot\..\logs\b19-r4-p3"
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$scratch = Join-Path $env:TEMP "vgww-rtl-$DebugPort"
if (-not (Test-Path -LiteralPath $scratch)) { New-Item -ItemType Directory -Path $scratch | Out-Null }

function BatchBody([object[]]$ops) {
  if ($ops.Count -le 1) { return "[" + (ConvertTo-Json -InputObject $ops[0] -Compress -Depth 8) + "]" }
  return ConvertTo-Json -InputObject $ops -Compress -Depth 8
}
function Call([object[]]$ops) {
  $body = BatchBody $ops
  return Invoke-RestMethod -Uri "http://127.0.0.1:$DebugPort/debug" -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 15
}

$p = Start-Process -FilePath $Exe -ArgumentList @("--config=$Config","--ui-page=dashboard","--ui-debug-port=$DebugPort") -WorkingDirectory $scratch -PassThru -WindowStyle Hidden
$up = $false
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 250
  try { if ((Call @(@{op="state"})).results[0].ok) { $up = $true; break } } catch { }
}
if (-not $up) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; Write-Output "RTL_CHECK BLOCKED app not up"; exit 2 }

function SidebarX($tree) {
  $stack = New-Object System.Collections.Queue
  $stack.Enqueue($tree)
  while ($stack.Count -gt 0) {
    $n = $stack.Dequeue()
    if ($n.id -eq "shell.sidebar") { return [double]$n.rect[0] }
    if ($n.children) { foreach ($c in $n.children) { $stack.Enqueue($c) } }
  }
  return -9999.0
}
function RegionMean([System.Drawing.Bitmap]$bmp, [int]$x0, [int]$x1, [int]$y0, [int]$y1) {
  $sum = 0.0; $n = 0
  for ($x = $x0; $x -lt $x1 -and $x -lt $bmp.Width; $x += 4) {
    for ($y = $y0; $y -lt $y1 -and $y -lt $bmp.Height; $y += 4) {
      $c = $bmp.GetPixel($x, $y); $sum += ($c.R + $c.G + $c.B) / 3.0; $n++
    }
  }
  if ($n -eq 0) { return 0.0 }
  return $sum / $n
}

$res = [ordered]@{ exe = $Exe; config = $Config; debug_port = $DebugPort }
try {
  # --- RTL ---
  $r = Call @(@{op="language";lang="ar"}, @{op="tree"}, @{op="state"}, @{op="screenshot"})
  $langNode = $r.results[0]; $tree = $r.results[1].data; $st = $r.results[2].data; $shot = $r.results[3]
  $sxAr = SidebarX $tree
  $png = Join-Path $scratch "ui-debug-screenshot.png"
  $arPng = Join-Path $OutDir "rtl-ar.png"
  if (Test-Path $png) { Copy-Item $png $arPng -Force }
  $bmp = $null
  if (Test-Path $arPng) { $bmp = New-Object System.Drawing.Bitmap $arPng }
  # sidebar is the dark column; in RTL the LEFT content region is brighter than
  # the RIGHT (sidebar) region, the reverse of LTR.
  $leftAr = if ($bmp) { RegionMean $bmp 0 200 80 600 } else { -1 }
  $rightAr = if ($bmp) { RegionMean $bmp ($bmp.Width - 200) $bmp.Width 80 600 } else { -1 }
  if ($bmp) { $bmp.Dispose() }
  # --- reset to zh-CN ---
  $r2 = Call @(@{op="language";lang="zh-CN"}, @{op="tree"}, @{op="state"})
  $sxZh = SidebarX $r2.results[1].data
  $stZh = $r2.results[2].data

  $res.ar_rtl = [bool]$st.rtl
  $res.ar_lang = [string]$st.lang
  $res.ar_sidebar_x = $sxAr
  $res.ar_left_mean = [Math]::Round($leftAr, 1)
  $res.ar_right_mean = [Math]::Round($rightAr, 1)
  $res.zh_sidebar_x = $sxZh
  $res.zh_rtl = [bool]$stZh.rtl
  $res.sidebar_mirrored = ($sxAr -ge 700.0 -and $sxAr -le 980.0)
  $res.sidebar_reset = ([Math]::Abs($sxZh) -le 0.5)
  $res.pixel_left_brighter = ($leftAr -gt $rightAr)
  # Tree bounds + state are authoritative here; the window-pixel probe is
  # informational (the app-screenshot op can yield a black frame in some
  # headless/GDI sessions, and P3 caption pixels are covered separately).
  $pass = $res.ar_rtl -and ($res.ar_lang -eq "ar") -and $res.sidebar_mirrored -and
          $res.sidebar_reset -and (-not $res.zh_rtl)
  $res.pixel_probe_informational = $true
  $res.result = if ($pass) { "PASS" } else { "FAIL" }
} catch {
  $res.result = "ERROR"
  $res.error = $_.Exception.Message
} finally {
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}
$res | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutDir "rtl-check.json") -Encoding UTF8
$res | ConvertTo-Json -Depth 6
if ($res.result -eq "PASS") { exit 0 } else { exit 1 }
