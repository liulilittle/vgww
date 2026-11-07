# W7 preparation: extract RCDATA resource 24001 from an exe and compare with a file.
# Usage: powershell -File w7-rcdat-extract.ps1 <exe> <out.bin> [<compare-file>]
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$Out,
  [string]$Compare
)
$ErrorActionPreference = 'Stop'
Add-Type -Namespace W7 -Name Res -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, uint dwFlags);
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr FindResourceW(IntPtr hModule, IntPtr lpName, IntPtr lpType);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr LockResource(IntPtr hResData);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FreeLibrary(IntPtr hModule);
'@
$LOAD_LIBRARY_AS_DATAFILE = 0x00000002
$RT_RCDATA = [IntPtr]10
$h = [W7.Res]::LoadLibraryExW($Exe, [IntPtr]::Zero, $LOAD_LIBRARY_AS_DATAFILE)
if ($h -eq [IntPtr]::Zero) { throw "LoadLibraryExW failed ($([Runtime.InteropServices.Marshal]::GetLastWin32Error()))" }
try {
  $info = [W7.Res]::FindResourceW($h, [IntPtr]24001, $RT_RCDATA)
  if ($info -eq [IntPtr]::Zero) { throw "RCDATA 24001 not found in $Exe" }
  $size = [W7.Res]::SizeofResource($h, $info)
  $res = [W7.Res]::LoadResource($h, $info)
  if ($res -eq [IntPtr]::Zero) { throw "LoadResource failed ($([Runtime.InteropServices.Marshal]::GetLastWin32Error()))" }
  $ptr = [W7.Res]::LockResource($res)
  $buf = New-Object byte[] $size
  [Runtime.InteropServices.Marshal]::Copy($ptr, $buf, 0, $size)
  [IO.File]::WriteAllBytes($Out, $buf)
  $sha = (Get-FileHash $Out -Algorithm SHA256).Hash
  Write-Output "RCDATA 24001: $size bytes -> $Out sha256=$sha"
  if ($Compare) {
    $target = [IO.File]::ReadAllBytes($Compare)
    $equal = ($target.Length -eq $size) -and (@(Compare-Object $target $buf -SyncWindow 0).Count -eq 0)
    Write-Output ("compare with {0}: {1} bytes; byte-equal={2}" -f $Compare, $target.Length, $equal)
    if (-not $equal) { exit 2 }
  }
} finally {
  [void][W7.Res]::FreeLibrary($h)
}
