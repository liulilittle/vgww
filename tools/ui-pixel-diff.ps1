# ============================================================================
# ui-pixel-diff.ps1 - persistent pixel differ for the UI hard gates (batch12
# T2). Replaces the ad-hoc C# LockBits snippet that b7 used and lost.
#
# Compares two PNGs pixel by pixel via GDI+ LockBits (no GetPixel loops):
#   * a pixel counts as DIFFERENT when any R/G/B channel differs by more than
#     -Tolerance (default 2), exactly the b7 criterion;
#   * reports diff_count, maxdelta and the differing bbox (inclusive pixel
#     coordinates) plus the SHA256 of both inputs.
#
# Exit codes:
#   0 = zero differing pixels (within tolerance)  -> gate PASS
#   1 = one or more differing pixels              -> gate FAIL
#   2 = error (missing file, dims mismatch, ...)  -> gate BLOCKED
#
# Stdout is a single-line JSON object (machine readable):
#   {"status":"ok","w":1470,"h":960,"tolerance":2,"count":0,"maxdelta":0,
#    "bbox":[0,0,-1,-1],"sha_equal":false,"sha_a":"...","sha_b":"..."}
# bbox is [x0,y0,x1,y1] with x0>y0==-1 sentinel when count==0.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools/ui-pixel-diff.ps1 `
#       -A <png-a> -B <png-b> [-Tolerance 2]
# ============================================================================
param(
  [Parameter(Mandatory=$true)][string]$A,
  [Parameter(Mandatory=$true)][string]$B,
  [int]$Tolerance = 2
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$srcA = (Resolve-Path -LiteralPath $A -ErrorAction SilentlyContinue)
$srcB = (Resolve-Path -LiteralPath $B -ErrorAction SilentlyContinue)

function Fail-Json([string]$status, [string]$detail, [int]$code) {
  [pscustomobject]@{
    status    = $status
    detail    = $detail
    a         = $A
    b         = $B
  } | ConvertTo-Json -Compress | Write-Output
  exit $code
}

if ($null -eq $srcA) { Fail-Json "missing_input" "a not found: $A" 2 }
if ($null -eq $srcB) { Fail-Json "missing_input" "b not found: $B" 2 }

$pathA = $srcA.Path
$pathB = $srcB.Path
$shaA = (Get-FileHash -LiteralPath $pathA -Algorithm SHA256).Hash
$shaB = (Get-FileHash -LiteralPath $pathB -Algorithm SHA256).Hash

Add-Type -ReferencedAssemblies "System.Drawing" -TypeDefinition @"
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public class UiPixelDiff {
    // Returns a CSV-ish payload, parsed on the PowerShell side:
    //   "ok;W;H;count;maxdelta;x0;y0;x1;y1" or "dimsmismatch;Wa;Ha;Wb;Hb"
    public static string Compare(string pathA, string pathB, int tol) {
        using (var ia = new Bitmap(pathA))
        using (var ib = new Bitmap(pathB)) {
            if (ia.Width != ib.Width || ia.Height != ib.Height) {
                return "dimsmismatch;" + ia.Width + ";" + ia.Height + ";" +
                       ib.Width + ";" + ib.Height;
            }
            int w = ia.Width;
            int h = ia.Height;
            var rect = new Rectangle(0, 0, w, h);
            var da = ia.LockBits(rect, ImageLockMode.ReadOnly,
                                 PixelFormat.Format32bppArgb);
            var db = ib.LockBits(rect, ImageLockMode.ReadOnly,
                                 PixelFormat.Format32bppArgb);
            try {
                int stride = da.Stride;
                byte[] pa = new byte[stride * h];
                byte[] pb = new byte[stride * h];
                Marshal.Copy(da.Scan0, pa, 0, pa.Length);
                Marshal.Copy(db.Scan0, pb, 0, pb.Length);
                long count = 0;
                int maxd = 0;   // global max channel delta (b7 maxdelta shape)
                int x0 = int.MaxValue, y0 = int.MaxValue, x1 = -1, y1 = -1;
                for (int y = 0; y < h; y++) {
                    int row = y * stride;
                    for (int x = 0; x < w; x++) {
                        int o = row + x * 4;
                        int dr = pa[o + 2] - pb[o + 2]; if (dr < 0) dr = -dr;
                        int dg = pa[o + 1] - pb[o + 1]; if (dg < 0) dg = -dg;
                        int dbb = pa[o] - pb[o];       if (dbb < 0) dbb = -dbb;
                        int d = dr;
                        if (dg > d) d = dg;
                        if (dbb > d) d = dbb;
                        if (d > maxd) maxd = d;
                        if (d > tol) {
                            count++;
                            if (x < x0) x0 = x;
                            if (x > x1) x1 = x;
                            if (y < y0) y0 = y;
                            if (y > y1) y1 = y;
                        }
                    }
                }
                if (count == 0) { x0 = -1; y0 = -1; }
                return "ok;" + w + ";" + h + ";" + count + ";" + maxd + ";" +
                       x0 + ";" + y0 + ";" + x1 + ";" + y1;
            } finally {
                ia.UnlockBits(da);
                ib.UnlockBits(db);
            }
        }
    }
}
"@ -ErrorAction Stop

$payload = [UiPixelDiff]::Compare($pathA, $pathB, $Tolerance)
$parts = $payload.Split(';')

if ($parts[0] -eq "dimsmismatch") {
  [pscustomobject]@{
    status = "dimsmismatch"
    a_dims = "$($parts[1])x$($parts[2])"
    b_dims = "$($parts[3])x$($parts[4])"
    sha_a  = $shaA
    sha_b  = $shaB
  } | ConvertTo-Json -Compress | Write-Output
  exit 2
}

$count    = [long]$parts[3]
$maxdelta = [int]$parts[4]
$x0 = [int]$parts[5]; $y0 = [int]$parts[6]
$x1 = [int]$parts[7]; $y1 = [int]$parts[8]

[pscustomobject]@{
  status      = "ok"
  w           = [int]$parts[1]
  h           = [int]$parts[2]
  tolerance   = $Tolerance
  count       = $count
  maxdelta    = $maxdelta
  bbox        = @($x0, $y0, $x1, $y1)
  sha_equal   = ($shaA -eq $shaB)
  sha_a       = $shaA
  sha_b       = $shaB
} | ConvertTo-Json -Compress -Depth 4 | Write-Output

if ($count -eq 0) { exit 0 } else { exit 1 }
