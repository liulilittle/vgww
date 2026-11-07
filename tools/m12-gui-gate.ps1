# ============================================================================
# m12-gui-gate.ps1 - batch11 M12 acceptance driver (main agent).
# Scenarios s1..s8 per b11-final-spec.md + audits v3 section 4.3; evidence into
# logs/m12-gate/. One scenario per invocation; app instance is force-killed
# on exit (zero-residue iron rule). Run via:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\m12-gui-gate.ps1 `
#       -Scenario s3 -Tier 1.5
# ============================================================================
param(
  [Parameter(Mandatory=$true)][ValidateSet("s1","s2","s3","s4","s5","s6","s7","s8","s9")][string]$Scenario,
  [double]$Tier = 1.5,
  [string]$OutRoot = "$PSScriptRoot\..\logs\m12-gate",
  [int]$DebugPort = 19777,
  [string]$Config = "$PSScriptRoot\..\config.example.json",
  [string]$Exe = "$PSScriptRoot\..\build\Release\vgww.exe"
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class DpiAwareM12 { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); }
public class WinRectM12 {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static int[] Get(IntPtr h){ RECT r; GetWindowRect(h, out r); return new int[]{r.L,r.T,r.R,r.B}; }
}
"@
[void][DpiAwareM12]::SetProcessDPIAware()

$scratch = Join-Path $env:TEMP "vgww-m12-gate-$DebugPort"
if (-not (Test-Path -LiteralPath $scratch)) { New-Item -ItemType Directory -Path $scratch | Out-Null }
if (-not (Test-Path -LiteralPath $OutRoot)) { New-Item -ItemType Directory -Path $OutRoot | Out-Null }
$logPath = Join-Path $OutRoot "run.log"
function Log([string]$m) { $line = "$(Get-Date -Format 'HH:mm:ss') [$Scenario/t$Tier] $m"; $line | Add-Content -LiteralPath $logPath; Write-Output $line }
function batch { return $args[0] }

$script:app = $null
function Start-App([string]$page) {
  if (@(Get-Process vgww -ErrorAction SilentlyContinue).Count -gt 0) { Log "ABORT: vgww already running"; exit 2 }
  $argv = @("--config=$Config", "--ui-page=$page", "--ui-debug-port=$DebugPort")
  $script:app = Start-Process -FilePath $Exe -ArgumentList $argv -WorkingDirectory $scratch -PassThru
  $deadline = (Get-Date).AddSeconds(10)
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 250
    $script:app.Refresh()
    if ($script:app.HasExited) { Log "ABORT: app exited code=$($script:app.ExitCode)"; exit 2 }
    try { $r = Invoke-RestMethod -Uri "http://127.0.0.1:$DebugPort/debug" -Method Post -Body '[{"op":"state"}]' -ContentType 'application/json' -TimeoutSec 2
          if ($r.results[0].ok) { Log "app up pid=$($script:app.Id) page=$page"; return } } catch { }
  }
  Log "ABORT: state poll timeout"; exit 2
}
function Stop-App() {
  if ($null -ne $script:app) { Stop-Process -Id $script:app.Id -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500 }
  $left = @(Get-Process vgww -ErrorAction SilentlyContinue).Count
  Log "leftover_vgww=$left"
}
function Inv($batch) {
  $arr = @($batch)
  $body = if ($arr.Count -le 1) { "[" + (ConvertTo-Json -InputObject $arr[0] -Compress -Depth 8) + "]" } else { ConvertTo-Json -InputObject $arr -Compress -Depth 8 }
  for ($i = 0; $i -lt 3; $i++) {
    try { return Invoke-RestMethod -Uri "http://127.0.0.1:$DebugPort/debug" -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 15 }
    catch { if ($i -eq 2) { throw } ; Start-Sleep -Milliseconds 300 }
  }
}
function Set-Tier() {
  $r = Inv(batch @(@{op="dpi";scale=$Tier}, @{op="resize";w=980;h=640}, @{op="render";mode="paint"}))
  if (-not $r.results[0].ok) { Log "ABORT: dpi op failed $($r.results[0].error)"; exit 2 }
}
function Shot([string]$name) {
  $r = Inv(batch @(@{op="render";mode="paint"}, @{op="screenshot"}, @{op="metrics"}))
  $shot = $r.results[1]; $met = $r.results[2]
  if (-not $shot.ok -or $shot.blocked) { Log "ABORT: screenshot blocked $($shot.reason)"; exit 2 }
  $png = Join-Path $scratch "ui-debug-screenshot.png"
  $dst = Join-Path $OutRoot "$name.png"
  Copy-Item -LiteralPath $png -Destination $dst -Force
  $side = [ordered]@{ name=$name; width=$shot.width; height=$shot.height; paint_count=$met.data.paint_count;
                      dirty_rect=$met.data.dirty_rect; dpi=$met.data.dpi; sha=(Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash }
  ($side | ConvertTo-Json -Compress) | Add-Content -LiteralPath $logPath
  Log "shot $name dims=$($shot.width)x$($shot.height) paint=$($met.data.paint_count)"
  return $side
}
function ShotRaw([string]$name) {
  $r = Inv(batch @(@{op="screenshot"}, @{op="metrics"}))
  $shot = $r.results[0]; $met = $r.results[1]
  if (-not $shot.ok -or $shot.blocked) { Log "ABORT: screenshot blocked $($shot.reason)"; exit 2 }
  $png = Join-Path $scratch "ui-debug-screenshot.png"
  $dst = Join-Path $OutRoot "$name.png"
  Copy-Item -LiteralPath $png -Destination $dst -Force
  $side = [ordered]@{ name=$name; raw=$true; width=$shot.width; height=$shot.height; paint_count=$met.data.paint_count;
                      dirty_rect=$met.data.dirty_rect; sha=(Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash }
  ($side | ConvertTo-Json -Compress) | Add-Content -LiteralPath $logPath
  Log "shot(raw) $name dims=$($shot.width)x$($shot.height) paint=$($met.data.paint_count)"
  return $side
}
function Get-Tree() {
  $r = Inv(batch @(@{op="tree"}))
  return $r.results[0].data
}
function Find-Node($node, [scriptblock]$pred) {
  if ($null -eq $node) { return $null }
  if (& $pred $node) { return $node }
  foreach ($c in $node.children) { $found = Find-Node $c $pred; if ($null -ne $found) { return $found } }
  return $null
}
function PxDiff([string]$a, [string]$b, [int]$tol = 2) {
  $pa = Join-Path $OutRoot "$a.png"; $pb = Join-Path $OutRoot "$b.png"
  $out = & powershell -NoProfile -File "$PSScriptRoot\ui-pixel-diff.ps1" -A $pa -B $pb -Tolerance $tol
  return ($out | ConvertFrom-Json)
}
function CropAndDiff([string]$a, [string]$b, [int]$x, [int]$y, [int]$w, [int]$h, [int]$tol = 2) {
  $pa = Join-Path $OutRoot "$a.png"; $pb = Join-Path $OutRoot "$b.png"
  $ca = Join-Path $OutRoot "_crop_${a}_${x}_${y}.png"; $cb = Join-Path $OutRoot "_crop_${b}_${x}_${y}.png"
  foreach ($pair in @(@($pa,$ca), @($pb,$cb))) {
    $img = [System.Drawing.Image]::FromFile($pair[0])
    $rect = New-Object System.Drawing.Rectangle($x, $y, $w, $h)
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.DrawImage($img, (New-Object System.Drawing.Rectangle(0,0,$w,$h)), $rect, [System.Drawing.GraphicsUnit]::Pixel)
    $g.Dispose(); $bmp.Save($pair[1], [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose(); $img.Dispose()
  }
  return (PxDiff (Split-Path $ca -Leaf) (Split-Path $cb -Leaf) $tol)
}
function CropPng([string]$src, [string]$dst, [int]$x, [int]$y, [int]$w, [int]$h) {
  $img = [System.Drawing.Image]::FromFile((Join-Path $OutRoot "$src.png"))
  $x2 = [Math]::Max(0, [Math]::Min($x, $img.Width - 1)); $y2 = [Math]::Max(0, [Math]::Min($y, $img.Height - 1))
  $w2 = [Math]::Max(1, [Math]::Min($w, $img.Width - $x2)); $h2 = [Math]::Max(1, [Math]::Min($h, $img.Height - $y2))
  $bmp = New-Object System.Drawing.Bitmap($w2, $h2)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.DrawImage($img, (New-Object System.Drawing.Rectangle(0, 0, $w2, $h2)), (New-Object System.Drawing.Rectangle($x2, $y2, $w2, $h2)), [System.Drawing.GraphicsUnit]::Pixel)
  $g.Dispose(); $bmp.Save((Join-Path $OutRoot "$dst.png"), [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose(); $img.Dispose()
}
function BoxDiff([string]$a, [string]$b, [int[]]$box) {
  $w = $box[2] - $box[0] + 1; $h = $box[3] - $box[1] + 1
  if ($w -le 0 -or $h -le 0) { return [pscustomobject]@{ status = "ok"; count = 0; bbox = @(0, 0, -1, -1) } }
  $ca = "_cropA_${a}"; $cb = "_cropB_${b}"
  CropPng $a $ca $box[0] $box[1] $w $h
  CropPng $b $cb $box[0] $box[1] $w $h
  return (PxDiff $ca $cb)
}
function StripsMinus([int[]]$old, [int[]]$new) {
  $boxes = @()
  $ix0 = [Math]::Max($old[0], $new[0]); $iy0 = [Math]::Max($old[1], $new[1])
  $ix1 = [Math]::Min($old[2], $new[2]); $iy1 = [Math]::Min($old[3], $new[3])
  if ($ix0 -gt $ix1 -or $iy0 -gt $iy1) { return ,$old }
  if ($old[1] -lt $iy0) { $boxes += ,@($old[0], $old[1], $old[2], ($iy0 - 1)) }
  if ($iy1 -lt $old[3]) { $boxes += ,@($old[0], ($iy1 + 1), $old[2], $old[3]) }
  if ($old[0] -lt $ix0) { $boxes += ,@($old[0], $iy0, ($ix0 - 1), $iy1) }
  if ($ix1 -lt $old[2]) { $boxes += ,@(($ix1 + 1), $iy0, $old[2], $iy1) }
  return $boxes
}
function RegionMean([string]$a, [int]$x, [int]$y, [int]$w, [int]$h) {
  $img = [System.Drawing.Image]::FromFile((Join-Path $OutRoot "$a.png"))
  $bmp = New-Object System.Drawing.Bitmap($img)
  $sum = 0.0; $n = 0
  for ($xx = $x; $xx -lt ($x+$w) -and $xx -lt $bmp.Width; $xx += 3) {
    for ($yy = $y; $yy -lt ($y+$h) -and $yy -lt $bmp.Height; $yy += 3) {
      $c = $bmp.GetPixel($xx, $yy); $sum += ($c.R + $c.G + $c.B) / 3.0; $n++
    }
  }
  $bmp.Dispose(); $img.Dispose()
  return [Math]::Round($sum / $n, 2)
}

try {
  Log "start exe=$Exe tier=$Tier"
  switch ($Scenario) {
    "s3" {
      Start-App "portmap"; Set-Tier
      $tree = Get-Tree
      $btn = Find-Node $tree { param($n) $n.id -eq "portmap.add" }
      if ($null -eq $btn) { Log "ABORT: portmap.add not found"; Stop-App; exit 2 }
      $br = $btn.rect
      $b0 = [int]([double]$br[0] * $Tier); $b1 = [int]([double]$br[1] * $Tier)
      $b2 = [int]((([double]$br[0] + [double]$br[2])) * $Tier); $b3 = [int]((([double]$br[1] + [double]$br[3])) * $Tier)
      $box = @(($b0 - 4), ($b1 - 4), ($b2 + 4), ($b3 + 4))
      Log "focus-box(physical)=$($box -join ',')"
      $null = Shot "s3-baseline"
      $r = Inv(batch @(@{op="click";id="portmap.add"}, @{op="tick";ms=1200}, @{op="render";mode="paint"}))
      Log "click.add ok=$($r.results[0].ok)"
      $null = Shot "s3-open"
      $r = Inv(batch @(@{op="key";vk=27}, @{op="tick";ms=800}, @{op="render";mode="paint"}))
      Log "esc key ok=$($r.results[0].ok)"
      $null = Shot "s3-closed"
      $d1 = PxDiff "s3-baseline" "s3-closed"
      $d2 = PxDiff "s3-open" "s3-closed"
      Log ("ASSERT closed-vs-baseline " + ($d1 | ConvertTo-Json -Compress))
      Log ("SANITY open-vs-closed " + ($d2 | ConvertTo-Json -Compress))
      $inBox = ($d1.count -eq 0) -or (($d1.bbox[0] -ge $box[0]) -and ($d1.bbox[1] -ge $box[1]) -and ($d1.bbox[2] -le $box[2]) -and ($d1.bbox[3] -le $box[3]))
      Log "no-ghost: diff confined to focus target = $inBox"
      $pass = ($d1.status -eq "ok" -and $inBox -and $d2.count -gt 0)
      Log ("RESULT s3=" + $(if ($pass) { "PASS" } else { "FAIL" }))
    }
    "s1" {
      Start-App "portmap"; Set-Tier
      $null = Shot "s1-pre"
      $null = Inv(batch @(@{op="click";id="portmap.add"}, @{op="tick";ms=2500}, @{op="render";mode="paint"}))
      $tree = Get-Tree
      $dlg = Find-Node $tree { param($n) $n.role -eq "DialogHost" }
      $ti = Find-Node $dlg { param($n) $n.role -eq "TextInput" }
      if ($null -eq $dlg -or $null -eq $ti) { Log "ABORT: dialog/input not found"; Stop-App; exit 2 }
      $dr = $dlg.rect; $tr = $ti.rect
      Log "dialog rect=$($dr -join ',') input rect=$($tr -join ',')"
      $cx = [int]($tr[0] + $tr[2] / 2); $cy = [int]($tr[1] + $tr[3] / 2)
      $null = Inv(batch @(@{op="click";x=$cx;y=$cy}, @{op="tick";ms=500}, @{op="render";mode="paint"}))
      $null = Shot "s1-open"
      $null = Inv(batch @(@{op="type";text="hello"}, @{op="tick";ms=500}, @{op="render";mode="paint"}, @{op="metrics"}))
      $null = Shot "s1-typed"
      $d = PxDiff "s1-open" "s1-typed"
      $mx0 = [int]($tr[0] * $Tier) - 10; $my0 = [int]($tr[1] * $Tier) - 10
      $mx1 = [int](($tr[0] + $tr[2]) * $Tier) + 10; $my1 = [int](($tr[1] + $tr[3]) * $Tier) + 10
      $inbox = ($d.count -eq 0) -or (($d.bbox[0] -ge $mx0) -and ($d.bbox[1] -ge $my0) -and ($d.bbox[2] -le $mx1) -and ($d.bbox[3] -le $my1))
      Log "typed-vs-open count=$($d.count) bbox=$($d.bbox -join ',') inbox(input+10)=$inbox"
      $sx = 244; $sy = 156; $sw = 716; $sh = 468
      $m1 = RegionMean "s1-open" $sx $sy $sw $sh
      $m2 = RegionMean "s1-typed" $sx $sy $sw $sh
      Log "scrim-region mean open=$m1 typed=$m2 delta=$([Math]::Round([Math]::Abs($m2-$m1),2)) (expect <=2)"
      $ops = Inv(batch @(@{op="draw_ops"}))
      Log "draw_ops typing-frame count=$($ops.results[0].data.count)"
      Log ("RESULT s1=" + $(if ($inbox -and ([Math]::Abs($m2-$m1) -le 2)) { "PASS" } else { "FAIL" }))
    }
    "s2" {
      Start-App "settings"; Set-Tier
      $null = Shot "s2-closed"
      $null = Inv(batch @(@{op="click";id="settings.mode"}, @{op="tick";ms=300}, @{op="render";mode="paint"}))
      $null = Shot "s2-open"
      $dOpen = PxDiff "s2-closed" "s2-open"
      Log ("open-diff " + ($dOpen | ConvertTo-Json -Compress))
      if ($dOpen.count -le 0) { Log "RESULT s2=FAIL (popup did not open)"; Stop-App; exit 0 }
      $pop = @(($dOpen.bbox[0] - 6), ($dOpen.bbox[1] - 6), ($dOpen.bbox[2] + 6), ($dOpen.bbox[3] + 6))
      $hx = [int]((($dOpen.bbox[0] + $dOpen.bbox[2]) / 2) / $Tier)
      $hy1 = [int](((($dOpen.bbox[1] + $dOpen.bbox[3]) / 2)) / $Tier)
      $hy2 = $hy1 + 15
      Log "hover rows at logical $hx,$hy1 and $hx,$hy2 (popup+6 physical $($pop -join ','))"
      $null = Inv(batch @(@{op="hover";x=$hx;y=$hy1}, @{op="tick";ms=100}, @{op="render";mode="paint"}))
      $null = Shot "s2-hover1"
      $null = Inv(batch @(@{op="hover";x=$hx;y=$hy2}, @{op="tick";ms=100}, @{op="render";mode="paint"}))
      $null = Shot "s2-hover2"
      $d = PxDiff "s2-open" "s2-hover1"
      $d12 = PxDiff "s2-hover1" "s2-hover2"
      Log ("hover1-diff " + ($d | ConvertTo-Json -Compress))
      Log ("hover1-vs-hover2 " + ($d12 | ConvertTo-Json -Compress))
      $in1 = ($d.count -eq 0) -or (($d.bbox[0] -ge $pop[0]) -and ($d.bbox[1] -ge $pop[1]) -and ($d.bbox[2] -le $pop[2]) -and ($d.bbox[3] -le $pop[3]))
      $in12 = ($d12.count -eq 0) -or (($d12.bbox[0] -ge $pop[0]) -and ($d12.bbox[1] -ge $pop[1]) -and ($d12.bbox[2] -le $pop[2]) -and ($d12.bbox[3] -le $pop[3]))
      Log "hover confined to popup+6 = $in1 / row-to-row = $in12"
      Log ("RESULT s2=" + $(if ($in1 -and $in12) { "PASS" } else { "FAIL" }))
    }
    "s5" {
      Start-App "settings"; Set-Tier
      $tree = Get-Tree
      $sel = Find-Node $tree { param($n) $n.id -eq "settings.mode" }
      if ($null -eq $sel) { Log "ABORT: settings.mode not found"; Stop-App; exit 2 }
      $y0 = [double]$sel.rect[1]
      $null = Shot "s5-base"
      $null = Inv(batch @(@{op="click";id="settings.mode"}, @{op="tick";ms=300}, @{op="render";mode="paint"}))
      $null = Shot "s5-popup0"
      $d0 = PxDiff "s5-base" "s5-popup0"
      if ($d0.count -le 0) { Log "RESULT s5=FAIL (popup did not open)"; Stop-App; exit 0 }
      $oldBox = @([int]$d0.bbox[0], [int]$d0.bbox[1], [int]$d0.bbox[2], [int]$d0.bbox[3])
      Log ("popup0 box(physical)=" + ($oldBox -join ',') + " count=" + $d0.count)
      $wp = @(600, [int]($y0 + 14))
      foreach ($gid in @("settings.group.gateway", "settings.group.basic", "settings.group.dhcp")) {
        $g = Find-Node $tree { param($n) $n.id -eq $gid }
        if ($null -ne $g) { $wp = @([int]([double]$g.rect[0] + 120), [int]([double]$g.rect[1] + 8)); break }
      }
      Log "wheel point logical $($wp -join ',')"
      $moved = $false; $sel2 = $null
      foreach ($dlt in @(-300, -600)) {
        $rw = Inv(batch @(@{op="wheel";x=$wp[0];y=$wp[1];delta=$dlt}, @{op="tick";ms=400}, @{op="render";mode="paint"}))
        Log ("wheel(" + $dlt + ") resp " + ($rw.results[0] | ConvertTo-Json -Compress))
        $tree = Get-Tree
        $sel2 = Find-Node $tree { param($n) $n.id -eq "settings.mode" }
        $y1 = [double]$sel2.rect[1]
        $moved = ([Math]::Abs($y1 - $y0) -gt 1.0)
        Log "select y0=$y0 y1=$y1 moved=$moved"
        if ($moved) { break }
      }
      $null = Shot "s5-popup1"
      $null = Inv(batch @(@{op="click";id="settings.mode"}, @{op="tick";ms=300}, @{op="render";mode="paint"}))
      $null = Shot "s5-closed"
      $d1 = PxDiff "s5-popup1" "s5-closed"
      Log ("post-close diff " + ($d1 | ConvertTo-Json -Compress))
      $newBox = @([int]$d1.bbox[0], [int]$d1.bbox[1], [int]$d1.bbox[2], [int]$d1.bbox[3])
      $strips = StripsMinus $oldBox $newBox
      $clean = $true
      foreach ($s in $strips) { $r = BoxDiff "s5-popup1" "s5-closed" $s; Log ("strip " + ($s -join ',') + " count=" + $r.count); if ($r.count -gt 0) { $clean = $false } }
      $pass = ($moved -and $d1.count -gt 0 -and $clean)
      Log "no-ghost old-popup region clean = $clean"
      Log ("RESULT s5=" + $(if ($pass) { "PASS" } else { "FAIL" }))
    }
    "s6" {
      Start-App "portmap"; Set-Tier
      $null = Inv(batch @(@{op="click";id="portmap.add"}, @{op="tick";ms=2500}, @{op="render";mode="paint"}))
      $tree = Get-Tree
      $dlg = Find-Node $tree { param($n) $n.role -eq "DialogHost" }
      $ti = Find-Node $dlg { param($n) $n.role -eq "TextInput" }
      if ($null -eq $ti) { Log "ABORT: input not found"; Stop-App; exit 2 }
      $tr = $ti.rect
      $cx = [int]($tr[0] + $tr[2] / 2); $cy = [int]($tr[1] + $tr[3] / 2)
      $null = Inv(batch @(@{op="click";x=$cx;y=$cy}, @{op="type";text="abc"}, @{op="tick";ms=500}, @{op="render";mode="paint"}))
      $null = Shot "s6-t0"
      $null = Inv(batch @(@{op="tick";ms=10500}, @{op="render";mode="paint"}))
      $null = Shot "s6-a"
      $null = Inv(batch @(@{op="tick";ms=2000}, @{op="render";mode="paint"}))
      $null = Shot "s6-b"
      $sx = [int](27 * $Tier); $sy = [int](467 * $Tier); $sw = [int](200 * $Tier); $sh = [int](133 * $Tier)
      $bx = [int](240 * $Tier); $by = [int](628 * $Tier); $bw = [int](720 * $Tier); $bh = [Math]::Max(4, [int](10 * $Tier))
      $s1a = RegionMean "s6-t0" $sx $sy $sw $sh; $s1b = RegionMean "s6-a" $sx $sy $sw $sh; $s1c = RegionMean "s6-b" $sx $sy $sw $sh
      $s2a = RegionMean "s6-t0" $bx $by $bw $bh; $s2b = RegionMean "s6-a" $bx $by $bw $bh; $s2c = RegionMean "s6-b" $bx $by $bw $bh
      Log "sidebar strip means t0=$s1a a=$s1b b=$s1c"
      Log "bottom strip means t0=$s2a a=$s2b b=$s2c"
      $maxDelta = [Math]::Max([Math]::Max([Math]::Abs($s1a - $s1b), [Math]::Abs($s1b - $s1c)), [Math]::Max([Math]::Abs($s2a - $s2b), [Math]::Abs($s2b - $s2c)))
      $dab = PxDiff "s6-a" "s6-b"
      $in = ($dab.count -eq 0) -or (($dab.bbox[0] -ge ([int]($tr[0] * $Tier) - 10)) -and ($dab.bbox[1] -ge ([int]($tr[1] * $Tier) - 10)) -and ($dab.bbox[2] -le ([int](($tr[0] + $tr[2]) * $Tier) + 10)) -and ($dab.bbox[3] -le ([int](($tr[1] + $tr[3]) * $Tier) + 10)))
      Log ("a-vs-b " + ($dab | ConvertTo-Json -Compress) + " inInput=$in")
      Log "scrim max step delta=$maxDelta (expect <=2)"
      Log ("RESULT s6=" + $(if (($maxDelta -le 2) -and $in) { "PASS" } else { "FAIL" }))
    }
    "s7" {
      Start-App "settings"; Set-Tier
      $null = Shot "s7-base"
      $script:app.Refresh()
      $wr = [WinRectM12]::Get($script:app.MainWindowHandle)
      Log "vgww rect physical = $($wr -join ',')"
      $childScript = 'Add-Type -AssemblyName System.Windows.Forms; $f=New-Object System.Windows.Forms.Form; $f.FormBorderStyle="None"; $f.StartPosition="Manual"; $f.Location=New-Object System.Drawing.Point(0,0); $f.Size=New-Object System.Drawing.Size(2560,1600); $f.BackColor=[System.Drawing.Color]::Magenta; $f.TopMost=$true; $t=New-Object System.Windows.Forms.Timer; $t.Interval=1600; $t.Add_Tick({$f.Close()}); $t.Start(); $f.Show(); [System.Windows.Forms.Application]::Run($f)'
      $child = Start-Process powershell -ArgumentList '-NoProfile','-Command', $childScript -PassThru -WindowStyle Hidden
      Start-Sleep -Milliseconds 700
      $cw = $wr[2] - $wr[0]; $ch = $wr[3] - $wr[1]
      $cb = New-Object System.Drawing.Bitmap($cw, $ch)
      $cg = [System.Drawing.Graphics]::FromImage($cb)
      $cg.CopyFromScreen($wr[0], $wr[1], 0, 0, $cb.Size)
      $cg.Dispose()
      $mg = 0; $tot = 0
      for ($x = 0; $x -lt $cw; $x += 20) { for ($y = 0; $y -lt $ch; $y += 20) { $c = $cb.GetPixel($x, $y); $tot++; if ($c.R -gt 180 -and $c.B -gt 180 -and $c.G -lt 120) { $mg++ } } }
      $cb.Dispose()
      $cov = [Math]::Round($mg / [double]$tot, 3)
      Log "occlusion coverage magenta_frac=$cov (expect >0.5)"
      try { $child | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue } catch { }
      Start-Sleep -Milliseconds 500
      $null = Inv(batch @(@{op="state"}))
      $null = ShotRaw "s7-post"
      $d = PxDiff "s7-base" "s7-post"
      Log ("occlusion-restore " + ($d | ConvertTo-Json -Compress))
      $pass = ($cov -gt 0.5) -and ($d.status -eq "ok") -and ($d.count -eq 0)
      Log ("RESULT s7=" + $(if ($pass) { "PASS" } else { "FAIL" }))
    }
    "s8" {
      Start-App "settings"; Set-Tier
      $null = Shot "s8-closed"
      $null = Inv(batch @(@{op="click";id="settings.mode"}, @{op="tick";ms=300}, @{op="render";mode="paint"}))
      $null = Shot "s8-popup"
      $d = PxDiff "s8-closed" "s8-popup"
      Log ("open-diff " + ($d | ConvertTo-Json -Compress))
      if ($d.count -le 0) { Log "RESULT s8=FAIL (popup not open)"; Stop-App; exit 0 }
      $x0 = [int]$d.bbox[0]; $x1 = [int]$d.bbox[2]; $y0 = [int]$d.bbox[1]
      $img = [System.Drawing.Image]::FromFile((Join-Path $OutRoot "s8-popup.png")); $bmp = New-Object System.Drawing.Bitmap($img)
      $means = @()
      for ($r = $y0 - 4; $r -le $y0 + 2; $r++) {
        if ($r -lt 0) { $means += 0.0; continue }
        $sum = 0.0; $n = 0
        for ($x = $x0; $x -le $x1; $x += 5) { $c = $bmp.GetPixel($x, $r); $sum += ($c.R + $c.G + $c.B) / 3.0; $n++ }
        $means += [Math]::Round($sum / $n, 2)
      }
      $bmp.Dispose(); $img.Dispose()
      Log ("edge rows y0-4..y0+2 means=" + ($means -join ','))
      $artifact = ([Math]::Abs($means[3] - $means[1]) -gt 3)
      Log "outer-edge 1px spike artifact = $artifact (expect False)"
      Log ("RESULT s8=" + $(if (-not $artifact) { "PASS" } else { "FAIL" }))
    }
    "s9" {
      Start-App "portmap"; Set-Tier
      $tree = Get-Tree
      $tbl = Find-Node $tree { param($n) $n.id -eq "portmap.table" }
      if ($null -eq $tbl) { Log "ABORT: portmap.table not found"; Stop-App; exit 2 }
      $tr = $tbl.rect
      $px = [int]($tr[0] + $tr[2] / 2); $py = [int]($tr[1] + $tr[3] / 2 + 60)
      Log "table rect=$($tr -join ',') point logical $px,$py"
      $null = Inv(batch @(@{op="hover";x=$px;y=$py}, @{op="tick";ms=100}, @{op="render";mode="paint"}))
      $null = Shot "s9-base"
      $rw = Inv(batch @(@{op="wheel";x=$px;y=$py;delta=-300}, @{op="tick";ms=200}, @{op="render";mode="paint"}))
      Log ("wheel(down) resp " + ($rw.results[0] | ConvertTo-Json -Compress))
      $cons = [bool]$rw.results[0].data.consumed
      $null = Shot "s9-mid"
      $null = Inv(batch @(@{op="wheel";x=$px;y=$py;delta=300}, @{op="tick";ms=200}, @{op="render";mode="paint"}))
      $null = ShotRaw "s9-back"
      $d1 = PxDiff "s9-base" "s9-mid"
      $d2 = PxDiff "s9-base" "s9-back"
      Log ("down-shift " + ($d1 | ConvertTo-Json -Compress))
      Log ("back-to-base " + ($d2 | ConvertTo-Json -Compress))
      $pass = ($cons -and ($d1.count -gt 0) -and ($d2.status -eq "ok") -and ($d2.count -eq 0))
      Log ("RESULT s9=" + $(if ($pass) { "PASS" } else { "FAIL" }))
    }
    default {
      Log "scenario $Scenario not implemented in v1"; Stop-App; exit 2
    }
  }
} finally {
  Stop-App
}
