param([string]$SourceRoot = (Get-Location).Path)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($PSVersionTable.Platform -ne 'Win32NT') { throw 'Run this harness on native Windows only' }
$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$root = Join-Path $env:RUNNER_TEMP ('managed-key-native-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$results = [ordered]@{ schema = 1; platform = [System.Environment]::OSVersion.VersionString; architecture = $env:PROCESSOR_ARCHITECTURE; source_commit = (& git -C $source rev-parse HEAD).Trim(); native_windows = $true; provider_operations = $false; evidence_root = $root }
if ($LASTEXITCODE -ne 0 -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Windows x64 source identity required' }
$utf8 = [System.Text.UTF8Encoding]::new($false)
$inputs = @('managed_key_file_windows.go', 'managed_key_file_windows_test.go', 'managed_key_file_windows_handles_test.go')
$results.source_hashes = [ordered]@{}
foreach ($name in $inputs) {
  $path = Join-Path $source ('internal/application/service/' + $name)
  $results.source_hashes[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$goVersion = (& go version | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Go unavailable' }
$results.go_version = $goVersion
$hostSource = Join-Path $source 'scripts/fixtures/managed-key-storage.mjs'
$hostSHA = (Get-FileHash -LiteralPath $hostSource -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hostSHA -ne '90f0a2b2a1cc43dde0546c1504c53a5ec6a3ea34c7b4200eb9bf3f0c8cbbb831') { throw 'Reviewed production host helper SHA differs' }
$results.production_host_helper_sha256 = $hostSHA
$env:WEKNORA_TEST_MANAGED_HOST_MODULE = $hostSource
$results.node_version = (& node --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Native Node unavailable for production host proof' }
$goMod = "module managed-key-windows-native-harness`n`ngo 1.26.0`n`nrequire golang.org/x/sys v0.46.0`n"
$sum = ((Get-Content -LiteralPath (Join-Path $source 'go.sum') | Where-Object { $_ -match '^golang.org/x/sys v0\.46\.0(?:/go.mod)? ' }) -join "`n") + "`n"
if (($sum.Trim() -split "`n").Length -ne 2) { throw 'Exact existing x/sys checksums required' }
foreach ($kind in @('baseline', 'current')) {
  $directory = Join-Path $root $kind
  New-Item -ItemType Directory -Path $directory | Out-Null
  [System.IO.File]::WriteAllText((Join-Path $directory 'go.mod'), $goMod, $utf8)
  [System.IO.File]::WriteAllText((Join-Path $directory 'go.sum'), $sum, $utf8)
  [System.IO.File]::WriteAllText((Join-Path $directory 'sentinel.go'), "package service`nimport `"errors`"`nvar ErrManagedWorkerUnavailable = errors.New(`"managed worker unavailable`")`n", $utf8)
  Copy-Item -LiteralPath (Join-Path $source 'internal/application/service/managed_key_file_windows_test.go') -Destination $directory
  if ($kind -eq 'baseline') {
    $baseline = (& git -C $source show 'f86f8ad5af1a0c056a63fd0a28c522bbb92b1000:internal/application/service/managed_key_file_other.go' | Out-String)
    if ($LASTEXITCODE -ne 0 -or $baseline -notmatch '^//go:build !darwin && !linux\r?\n') { throw 'Pinned baseline unavailable' }
    $baseline = $baseline -replace '^//go:build !darwin && !linux', '//go:build windows'
    [System.IO.File]::WriteAllText((Join-Path $directory 'managed_key_file_windows.go'), $baseline, $utf8)
  } else {
    foreach ($name in @('managed_key_file_windows.go', 'managed_key_file_windows_handles_test.go')) {
      Copy-Item -LiteralPath (Join-Path $source ('internal/application/service/' + $name)) -Destination $directory
    }
    foreach ($name in $inputs) {
      if ((Get-FileHash -LiteralPath (Join-Path $directory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $results.source_hashes[$name]) { throw 'Harness source differs from production bytes' }
    }
  }
}
$hostOld = Join-Path $root 'host-before.mjs'
$hostOldCode = @'
import fs from 'node:fs/promises'; import path from 'node:path';
export function createManagedKeyStorage(){ return {
 async prepareDirectory(p){await fs.mkdir(p,{recursive:true,mode:0o700});},
 async createFile(p){return fs.open(p,'wx',0o600);}, async verifyFile(){}
}; }
'@
[System.IO.File]::WriteAllText($hostOld, $hostOldCode, $utf8)
$env:GOTOOLCHAIN = 'local'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
$env:GOFLAGS = ''
$baselineDirectory = Join-Path $root 'baseline'
Push-Location $baselineDirectory
try {
  $baselineLog = (& go test -run '^TestManagedWindowsKeyFileReadsPrivateOwnerKey$' -count=1 -v . 2>&1 | Out-String)
  $baselineExit = $LASTEXITCODE
  [System.IO.File]::WriteAllText((Join-Path $root 'native-baseline-red.log'), $baselineLog, $utf8)
  if ($baselineExit -eq 0 -or $baselineLog -notmatch 'private current-user/SYSTEM/Administrators key rejected: managed worker unavailable') { throw 'Baseline must fail specifically for unsupported private key read' }
  $results.baseline_exit_code = $baselineExit
} finally { Pop-Location }
Push-Location (Join-Path $root 'current')
try {
  # The reviewed strict reader first exercises the old POSIX-only host pattern.
  # This is the exact native owner failure that the new host must resolve.
  $env:WEKNORA_TEST_MANAGED_HOST_MODULE = $hostOld
  $hostRed = (& go test -run '^TestManagedWindowsActualUserConfigHostLayout$' -count=1 -v . 2>&1 | Out-String)
  $hostRedExit = $LASTEXITCODE
  [System.IO.File]::WriteAllText((Join-Path $root 'native-host-before-red.log'), $hostRed, $utf8)
  if ($hostRedExit -eq 0 -or $hostRed -notmatch 'strict reader rejected production-prepared key: managed worker unavailable') { throw 'Old host must reproduce the native owner rejection' }
  $results.host_before_exit_code = $hostRedExit
  $env:WEKNORA_TEST_MANAGED_HOST_MODULE = $hostSource
  $currentLog = (& go test -count=1 -v . 2>&1 | Out-String)
  $currentExit = $LASTEXITCODE
  [System.IO.File]::WriteAllText((Join-Path $root 'native-current.log'), $currentLog, $utf8)
  $results.current_exit_code = $currentExit
  $results.current_pass_lines = ([regex]::Matches($currentLog, '(?m)^\s*--- PASS:')).Count
  if ($currentExit -ne 0 -or $results.current_pass_lines -lt 35 -or $currentLog -match '(?m)^\s*--- SKIP:') { throw 'Every native Windows key test must pass, with no skipped privilege cases' }
  $vet = (& go vet . 2>&1 | Out-String)
  [System.IO.File]::WriteAllText((Join-Path $root 'native-vet.log'), $vet, $utf8)
  $results.vet_exit_code = $LASTEXITCODE
  if ($LASTEXITCODE -ne 0) { throw 'Windows reader vet failed' }
} finally { Pop-Location }
$results.status = 'native_windows_reader_and_byte_identical_host_key_creation_verified'
[System.IO.File]::WriteAllText((Join-Path $root 'native-result.json'), ($results | ConvertTo-Json -Depth 8) + "`n", $utf8)
$results | ConvertTo-Json -Depth 8
if ($env:GITHUB_OUTPUT) { ('evidence=' + $root) | Add-Content -LiteralPath $env:GITHUB_OUTPUT }
