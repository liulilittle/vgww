# ============================================================================
# ui-tier-gate.ps1 - batch12 T3 three-tier DPI hard gate driver
# (reusable by batch11 M12: "whole window fully cleared -> partial
# invalidation" pixel verification).
#
# Two phases so each invocation stays short and re-runnable:
#
#   collect : for every (tier, page) cell, runs tools/ui-shot.ps1 in Full
#             protocol (-Scale <tier>) into <OutRoot>\s<tier>\run<k>\ and
#             keeps capturing until two CONSECUTIVE independent runs have the
#             same png sha256 (bounded by -MaxRunsPerCell). Existing evidence
#             is reused unless -Force is given.
#
#   verify  : reads the collected evidence and asserts, per the batch12 spec:
#             (1) two independent captures per (tier,page) SHA-equal
#                 (consecutive pair; otherwise FAIL);
#             (2) their pixel diff is 0 with the b7 criterion (>2 channel
#                 tolerance; ui-pixel-diff.ps1) - authoritative pixel gate;
#             (3) dims exactly 980*tier x 640*tier (evidence + png bytes);
#             (4) state.scale == tier and metrics.dpi == 96*tier (re-read from
#                 the stored raw op values, not just the tool's verdict);
#             (5) render.paint_count - metrics.paint_count >= 1 (delta both
#                 stored and re-checked);
#             (6) tree and draw_ops canonical JSON identical across the tiers
#                 of this verify call (logical invariant; physical conversion
#                 is ignored by construction - both are logical/DIP payloads);
#             (7) optional -PreDir: the tier==(-PreTier) retained capture is
#                 pixel-diffed against <PreDir>\s520-shot-<page>.png with the
#                 same zero-diff criterion (b7 150% baseline preservation).
#             Cross-tier PIXEL byte comparison is never performed (AA differs
#             between tiers by design).
#
# Exit codes: 0 = all assertions passed; 1 = any assertion failed;
#             2 = usage / collect error. Machine-readable summary is written
#             to <OutRoot>\verify-summary-<tag>.txt (same text printed).
#
# Usage:
#   collect: powershell -File tools/ui-tier-gate.ps1 -Mode collect `
#                -Tiers 1.25 -Pages leases,portmap
#   verify : powershell -File tools/ui-tier-gate.ps1 -Mode verify `
#                -Tiers 1.0,1.25,1.5 -PreDir <repo>\logs\b12-baseline-current
# ============================================================================
param(
  [ValidateSet("collect","verify")][string]$Mode = "verify",
  [string]$Tiers = "1.0,1.25,1.5",
  # batch19 R3-2: `console` is deliberately NOT in the default page set. Its
  # body is the live captured stdout/stderr ring, so two independent runs are
  # pixel-equal within tolerance (ui-pixel-diff count=0) but NOT byte-equal
  # (png sha differs) - the consecutive-SHA pair rule would never converge.
  # Pass -Pages ...,console explicitly to capture it for inspection; the page
  # itself is covered by tests/test_ui.cpp TestB19ConsolePage and by
  # tools/ui-shot.ps1 -Page console (nav fingerprint row 8).
  [string]$Pages = "dashboard,leases,portmap,firewall,ratelimit,bridge,settings,about",
  [string]$OutRoot = "$PSScriptRoot\..\logs\b12-tier",
  [string]$Exe = "$PSScriptRoot\..\build\Release\vgww.exe",
  [string]$Config = "$PSScriptRoot\..\config.example.json",
  [int]$DebugPort = 19777,
  [string]$PreDir = "",
  [double]$PreTier = 1.5,
  [int]$MaxRunsPerCell = 4,
  [switch]$Force,
  # batch19 R4-P3: RTL mode - a distinct baseline tree and ui-shot -Dir rtl.
  # Baseline CAPTURE is deferred until the T2 fold (use with a -Rtl OutRoot).
  [switch]$Rtl
)
$ErrorActionPreference = "Stop"
$Inv = [Globalization.CultureInfo]::InvariantCulture
$shotTool = Join-Path $PSScriptRoot "ui-shot.ps1"
$diffTool = Join-Path $PSScriptRoot "ui-pixel-diff.ps1"

$kTiers = @(0.5, 0.75, 1.0, 1.25, 1.5)
$tierList = @()
foreach ($t in $Tiers.Split(',')) {
  $v = [double]::Parse($t.Trim(), $Inv)
  $ok = $false
  foreach ($k in $kTiers) { if ([Math]::Abs($v - $k) -lt 1e-9) { $ok = $true; break } }
  if (-not $ok) { Write-Output "ERROR unsupported tier $t (allowed 0.5/0.75/1.0/1.25/1.5)"; exit 2 }
  if (-not ($tierList -contains $v)) { $tierList += $v }
}
$pageList = @()
foreach ($p in $Pages.Split(',')) { $pageList += $p.Trim() }
$DirLabel = if ($Rtl) { "rtl" } else { "ltr" }
if ($Rtl -and $OutRoot -notmatch '-rtl$') { $OutRoot = "$OutRoot-rtl" }

function TierDir([double]$t) { return "s" + $t.ToString("0.###", $Inv) }
function ExpectedDims([double]$t) {
  return [pscustomobject]@{ w = [int][Math]::Round(980.0 * $t); h = [int][Math]::Round(640.0 * $t) }
}

if ($Mode -eq "collect") {
  if (-not (Test-Path -LiteralPath $shotTool)) { Write-Output "ERROR ui-shot.ps1 not found next to this script"; exit 2 }
  $bad = 0
  foreach ($tier in $tierList) {
    $tierStr = $tier.ToString($Inv)
    foreach ($page in $pageList) {
      $lastSha = ""
      $pairFound = $false
      $shas = @()
      $run = 0
      while ($run -lt $MaxRunsPerCell) {
        $run++
        $cellRoot = Join-Path (Join-Path $OutRoot (TierDir $tier)) "run$run"
        $evPath = Join-Path $cellRoot "$page.evidence.json"
        if (-not (Test-Path -LiteralPath $evPath) -or $Force) {
          if (-not (Test-Path -LiteralPath $cellRoot)) { New-Item -ItemType Directory -Path $cellRoot | Out-Null }
          $psArgs = @("-NoProfile","-ExecutionPolicy","Bypass","-File",$shotTool,
                      "-Page",$page,"-Scale",$tierStr,"-Config",$Config,"-Exe",$Exe,
                      "-Dir",$DirLabel,
                      "-DebugPort","$DebugPort","-OutDir",$cellRoot,"-Evidence",$evPath)
          $out = & powershell @psArgs 2>&1
          $out | Set-Content -LiteralPath (Join-Path $cellRoot "$page.ui-shot.out") -Encoding UTF8
          if ($LASTEXITCODE -ne 0) {
            Write-Output "COLLECT_ERROR tier=$tier page=$page run=$run ui-shot exit=$LASTEXITCODE"
            $out | Select-Object -Last 5
            exit 2
          }
        }
        $ev = Get-Content -LiteralPath $evPath -Raw | ConvertFrom-Json
        if ($ev.result -ne "PASS") { Write-Output "COLLECT_ERROR tier=$tier page=$page run=$run evidence result=$($ev.result)"; exit 2 }
        $sha = [string]$ev.sha256
        $shas += $sha
        if ($run -ge 2 -and $sha -eq $lastSha) { $pairFound = $true; break }
        $lastSha = $sha
      }
      if ($pairFound) {
        Write-Output ("COLLECT_OK tier={0} page={1,-10} runs={2} pair_sha={3}" -f $tierStr, $page, $run, $lastSha.Substring(0,16))
      } else {
        Write-Output ("COLLECT_WARN tier={0} page={1,-10} runs={2} no consecutive pair shas={3}" -f $tierStr, $page, $run, (($shas | ForEach-Object { $_.Substring(0,12) }) -join ","))
        $bad++
      }
    }
  }
  if ($bad -gt 0) { Write-Output "COLLECT_DONE with $bad cell(s) missing a consecutive pair (verify will FAIL them)"; exit 1 }
  Write-Output "COLLECT_DONE all cells have a consecutive pair"
  exit 0
}

# ---------------------------------------------------------------- verify ---
Add-Type -AssemblyName System.Drawing
$rows = New-Object System.Collections.Generic.List[string]
$fails = New-Object System.Collections.Generic.List[string]
$tierTag = (($tierList | ForEach-Object { TierDir $_ }) -join "_")

function FirstDiff([string]$a, [string]$b) {
  if ($null -eq $a) { return "a=null" }
  if ($null -eq $b) { return "b=null" }
  $n = [Math]::Min($a.Length, $b.Length)
  $i = 0
  while ($i -lt $n -and $a[$i] -eq $b[$i]) { $i++ }
  $s = [Math]::Max(0, $i - 50)
  $la = $a.Substring($s, [Math]::Min(110, $a.Length - $s))
  $lb = $b.Substring($s, [Math]::Min(110, $b.Length - $s))
  return "diff@$i a=...$la... b=...$lb..."
}

$treeByPage = @{}
$opsByPage = @{}
$anyFail = $false

foreach ($page in $pageList) {
  foreach ($tier in $tierList) {
    $tierStr = $tier.ToString($Inv)
    $td = TierDir $tier
    $exp = ExpectedDims $tier
    $cellBase = Join-Path $OutRoot $td
    $cellFails = @()

    $evs = @()
    if (Test-Path -LiteralPath $cellBase) {
      $runDirs = Get-ChildItem -LiteralPath $cellBase -Directory -Filter "run*" | Sort-Object { [int]($_.Name -replace '[^0-9]','') }
      foreach ($rd in $runDirs) {
        $p = Join-Path $rd.FullName "$page.evidence.json"
        if (Test-Path -LiteralPath $p) {
          $evs += [pscustomobject]@{ dir = $rd.FullName; ev = (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json) }
        }
      }
    }
    if ($evs.Count -lt 2) {
      $cellFails += "evidence<2 (found $($evs.Count))"
      $anyFail = $true
      $rows.Add(("{0,-10} tier={1,-5} FAIL {2}" -f $page, $tierStr, ($cellFails -join "; ")))
      $fails.Add("$page/${tierStr}: $($cellFails -join '; ')")
      continue
    }

    $pair = $null
    for ($i = $evs.Count - 1; $i -ge 1; $i--) {
      if ([string]$evs[$i].ev.sha256 -eq [string]$evs[$i-1].ev.sha256) { $pair = @($evs[$i-1], $evs[$i]); break }
    }
    $pairFound = ($null -ne $pair)
    if (-not $pairFound) { $pair = @($evs[$evs.Count-2], $evs[$evs.Count-1]) }
    $retained = $pair[1]
    $ev = $retained.ev

    if (-not $pairFound) { $cellFails += "no_consecutive_sha_pair(last=$([string]$ev.sha256 -replace '^(.{12}).*','$1'))" }
    if ($ev.result -ne "PASS") { $cellFails += "ui-shot result=$($ev.result)" }
    if ($ev.protocol -ne "Full") { $cellFails += "protocol=$($ev.protocol)" }
    if ([Math]::Abs([double]$ev.tier - $tier) -gt 1e-9) { $cellFails += "evidence tier=$($ev.tier)" }

    $pngMain = Join-Path $retained.dir "s520-shot-$page.png"
    if (-not (Test-Path -LiteralPath $pngMain)) { $cellFails += "png missing" }
    else {
      $shaNow = (Get-FileHash -LiteralPath $pngMain -Algorithm SHA256).Hash
      if ($shaNow -ne [string]$ev.sha256) { $cellFails += "png sha != evidence sha (tampered/stale)" }
      $bmp = New-Object System.Drawing.Bitmap $pngMain
      $pw = $bmp.Width; $ph = $bmp.Height
      $bmp.Dispose()
      if ($pw -ne $exp.w -or $ph -ne $exp.h) { $cellFails += "png dims ${pw}x${ph} exp $($exp.w)x$($exp.h)" }
    }
    if ([int]$ev.width -ne $exp.w -or [int]$ev.height -ne $exp.h) { $cellFails += "ev dims $($ev.width)x$($ev.height) exp $($exp.w)x$($exp.h)" }
    if ([int]$ev.expected_w -ne $exp.w -or [int]$ev.expected_h -ne $exp.h) { $cellFails += "ev expected dims mismatch" }

    if ($null -ne $ev.state_scale) {
      if ([Math]::Abs([double]$ev.state_scale - $tier) -gt 1e-4) { $cellFails += "state.scale=$($ev.state_scale)" }
    } else { $cellFails += "state_scale missing" }
    if ($null -ne $ev.metrics_dpi) {
      if ([Math]::Abs([double]$ev.metrics_dpi - 96.0 * $tier) -gt 0.5) { $cellFails += "metrics.dpi=$($ev.metrics_dpi)" }
    } else { $cellFails += "metrics_dpi missing" }
    if ($null -ne $ev.dpi_echo_scale) {
      if ([Math]::Abs([double]$ev.dpi_echo_scale - $tier) -gt 1e-4) { $cellFails += "dpi echo=$($ev.dpi_echo_scale)" }
    } else { $cellFails += "dpi_echo missing" }
    if ([int]$ev.paint_delta -lt 1) { $cellFails += "paint_delta=$($ev.paint_delta)" }
    if ($null -ne $ev.metrics_paint_count -and $null -ne $ev.render_paint_count) {
      if ([long]$ev.render_paint_count -lt ([long]$ev.metrics_paint_count + 1)) {
        $cellFails += "pc delta=$([long]$ev.render_paint_count - [long]$ev.metrics_paint_count)"
      }
    } elseif ($ev.protocol -eq "Full") { $cellFails += "paint_count fields missing" }
    if (-not $ev.fingerprint.hit) { $cellFails += "fingerprint hit=false" }
    if (-not $ev.tree_ok) { $cellFails += "tree_ok=false" }
    if (-not $ev.draw_ops_ok) { $cellFails += "draw_ops_ok=false" }

    # (2) zero pixel diff between the retained consecutive pair
    $pd = -1
    if ($pairFound) {
      $pngPrev = Join-Path $pair[0].dir "s520-shot-$page.png"
      if (Test-Path -LiteralPath $pngPrev) {
        $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $diffTool -A $pngPrev -B $pngMain 2>&1
        $pd = [long](($raw | ConvertFrom-Json).count)
        if ($pd -ne 0) { $cellFails += "pair pixel diff=$pd" }
      } else { $cellFails += "pair prev png missing" }
    }

    # (7) pre-dir baseline (b7 gate shape) for the real-system tier
    $pre = "n/a"
    if ($PreDir -ne "" -and [Math]::Abs($tier - $PreTier) -lt 1e-9) {
      $prePng = Join-Path $PreDir "s520-shot-$page.png"
      if (-not (Test-Path -LiteralPath $prePng)) { $cellFails += "pre png missing: $prePng" }
      else {
        $raw2 = & powershell -NoProfile -ExecutionPolicy Bypass -File $diffTool -A $prePng -B $pngMain 2>&1
        $preCount = [long](($raw2 | ConvertFrom-Json).count)
        $pre = "$preCount"
        if ($preCount -ne 0) { $cellFails += "pre/post pixel diff=$preCount" }
      }
    }

    # (6) cross-tier canon collection
    if (-not $treeByPage.ContainsKey($page)) { $treeByPage[$page] = @{}; $opsByPage[$page] = @{} }
    $treeByPage[$page][$tierStr] = [string]$ev.tree_canon
    $opsByPage[$page][$tierStr] = [string]$ev.draw_ops_canon

    $status = if ($cellFails.Count -eq 0) { "PASS" } else { "FAIL" }
    if ($cellFails.Count -gt 0) { $anyFail = $true; $fails.Add("$page/${tierStr}: $($cellFails -join '; ')") }
    $rows.Add(("{0,-10} tier={1,-5} {2} pair={3,-5} pixdiff={4,-4} dims={5}x{6} state={7} dpi={8} paintD={9} fp={10} tree={11} ops={12} pre={13} {14}" -f `
      $page, $tierStr, $status, $pairFound, $pd, $ev.width, $ev.height, `
      $(if ($null -ne $ev.state_scale) { [Math]::Round([double]$ev.state_scale,3) } else { "?" }), `
      $(if ($null -ne $ev.metrics_dpi) { [Math]::Round([double]$ev.metrics_dpi,1) } else { "?" }), `
      $ev.paint_delta, $ev.fingerprint.hit, $ev.tree_ok, $ev.draw_ops_ok, $pre, `
      $(if ($cellFails.Count -gt 0) { "[" + ($cellFails -join '; ') + "]" } else { "" })))
  }
}

# (6) cross-tier logical equality per page
foreach ($page in $pageList) {
  $treeMap = $treeByPage[$page]
  $opsMap = $opsByPage[$page]
  if ($null -eq $treeMap -or $treeMap.Count -lt 2) { continue }
  $firstTier = ($tierList | ForEach-Object { $_.ToString($Inv) } | Where-Object { $treeMap.ContainsKey($_) } | Select-Object -First 1)
  $treeRef = $treeMap[$firstTier]
  $opsRef = $opsMap[$firstTier]
  $pageCrossOk = $true
  foreach ($tier in $tierList) {
    $ts = $tier.ToString($Inv)
    if (-not $treeMap.ContainsKey($ts)) { continue }
    if ($treeMap[$ts] -ne $treeRef) {
      $anyFail = $true
      $pageCrossOk = $false
      $d = FirstDiff $treeRef $treeMap[$ts]
      $fails.Add("$page tree cross-tier mismatch (${firstTier} vs ${ts}): $d")
      $rows.Add(("{0,-10} tree cross-tier FAIL {1}" -f $page, $d))
    }
    if ($opsMap[$ts] -ne $opsRef) {
      $anyFail = $true
      $pageCrossOk = $false
      $d2 = FirstDiff $opsRef $opsMap[$ts]
      $fails.Add("$page draw_ops cross-tier mismatch (${firstTier} vs ${ts}): $d2")
      $rows.Add(("{0,-10} draw_ops cross-tier FAIL {1}" -f $page, $d2))
    }
  }
  if ($pageCrossOk) {
    $rows.Add(("{0,-10} tree/draw_ops cross-tier logical equality PASS over tiers {1}" -f $page, (($tierList | ForEach-Object { $_.ToString($Inv) }) -join ",")))
  }
}

$tag = "$tierTag$(if ($PreDir -ne '') { '_pre' } else { '' })"
if (-not (Test-Path -LiteralPath $OutRoot)) { New-Item -ItemType Directory -Path $OutRoot | Out-Null }
$summaryPath = Join-Path $OutRoot "verify-summary-$tag.txt"
$header = @(
  "===== ui-tier-gate verify tiers=[$((($tierList | ForEach-Object { $_.ToString($Inv) }) -join ','))] pages=[$($pageList.Count)] preDir=$PreDir at=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ====="
)
$text = ($header + $rows + $(if ($anyFail) { @("OVERALL: FAIL") } else { @("OVERALL: PASS") }) + $fails)
$text | Set-Content -LiteralPath $summaryPath -Encoding UTF8
$text | ForEach-Object { Write-Output $_ }

if ($anyFail) { exit 1 } else { exit 0 }
