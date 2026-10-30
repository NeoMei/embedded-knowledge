param([string]$SourceRoot = (Get-Location).Path)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($PSVersionTable.Platform -ne 'Win32NT') { throw 'Native Windows is required' }
$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$root = Join-Path $env:RUNNER_TEMP ('managed-key-native-standard-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false)
$account = 'UHKey' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$password = ConvertTo-SecureString ('uH!7' + [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
$createdUser = $false
$process = $null
try {
  New-LocalUser -Name $account -Password $password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
  $createdUser = $true
  $sid = (Get-LocalUser -Name $account).SID.Value
  $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
  Add-LocalGroupMember -Group $usersGroup.Name -Member $account
  # This newly created, public-code staging directory grants the test user
  # read/execute only. No production key or credential is written here.
  $security = [Security.AccessControl.DirectorySecurity]::new()
  $security.SetAccessRuleProtection($true, $false)
  foreach ($trusted in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')) {
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($trusted), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
  }
  $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
  Set-Acl -LiteralPath $root -AclObject $security
  $goMod = "module managed-key-windows-native-harness`n`ngo 1.26.0`n`nrequire golang.org/x/sys v0.46.0`n"
  $sum = ((Get-Content -LiteralPath (Join-Path $source 'go.sum') | Where-Object { $_ -match '^golang.org/x/sys v0\.46\.0(?:/go.mod)? ' }) -join "`n") + "`n"
  if (($sum.Trim() -split "`n").Length -ne 2) { throw 'Existing x/sys checksums required' }
  [IO.File]::WriteAllText((Join-Path $root 'go.mod'), $goMod, $utf8)
  [IO.File]::WriteAllText((Join-Path $root 'go.sum'), $sum, $utf8)
  [IO.File]::WriteAllText((Join-Path $root 'sentinel.go'), "package service`nimport `"errors`"`nvar ErrManagedWorkerUnavailable = errors.New(`"managed worker unavailable`")`n", $utf8)
  $sourceHashes = [ordered]@{}
  foreach ($name in @('managed_key_file_windows.go', 'managed_key_file_windows_test.go', 'managed_key_file_windows_handles_test.go')) {
    $original = Join-Path $source ('internal/application/service/' + $name)
    Copy-Item -LiteralPath $original -Destination $root
    $sourceHashes[$name] = (Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sourceHashes[$name]) { throw 'Standard-user harness source differs' }
  }
  $helper = Join-Path $root 'managed-key-storage.mjs'
  Copy-Item -LiteralPath (Join-Path $source 'scripts/fixtures/managed-key-storage.mjs') -Destination $helper
  $helperSHA = (Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($helperSHA -ne (Get-FileHash -LiteralPath (Join-Path $source 'scripts/fixtures/managed-key-storage.mjs') -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Standard-user helper differs' }
  $env:GOTOOLCHAIN = 'local'; $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'; $env:GOFLAGS = ''
  $binary = Join-Path $root 'managed-standard.test.exe'
  Push-Location $root
  try {
    $compile = (& go test -c -o $binary . 2>&1 | Out-String)
    [IO.File]::WriteAllText((Join-Path $root 'standard-compile.log'), $compile, $utf8)
    if ($LASTEXITCODE -ne 0) { throw 'Standard-user harness compilation failed' }
  } finally { Pop-Location }
  $config = [ordered]@{ binary = $binary; helper = $helper; node = (Get-Command node.exe -ErrorAction Stop).Source; expected_sid = $sid }
  $configPath = Join-Path $root 'standard-config.json'
  [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json) + "`n", $utf8)
  $driver = @'
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'A standard non-administrator identity is required' }
$env:USERPROFILE = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$env:APPDATA = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData, [Environment+SpecialFolderOption]::Create)
$env:LOCALAPPDATA = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData, [Environment+SpecialFolderOption]::Create)
if (!$env:USERPROFILE -or !$env:APPDATA -or !$env:LOCALAPPDATA) { throw 'Standard-user profile unavailable' }
$env:TEMP = [IO.Path]::Combine($env:LOCALAPPDATA, 'Temp')
$env:TMP = $env:TEMP
[void][IO.Directory]::CreateDirectory($env:TEMP)
Import-Module -Name ([IO.Path]::Combine($PSHOME, 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
$settings = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($env:UH_NATIVE_STANDARD_CONFIGURATION))
if ($identity.User.Value -ne $settings.expected_sid) { throw 'The synthetic standard-user identity differs' }
[Console]::Out.WriteLine('STANDARD_NONADMIN=true')
$env:PATH = [IO.Path]::GetDirectoryName($settings.node) + ';' + $env:SystemRoot + '\System32;' + $env:SystemRoot
$env:WEKNORA_TEST_MANAGED_HOST_MODULE = $settings.helper
$testStart = [Diagnostics.ProcessStartInfo]::new()
$testStart.FileName = $settings.binary
$testStart.Arguments = '-test.run "^(TestManagedWindowsActualUserConfigHostLayout|TestManagedWindowsProductionHostPreparesEveryKeyKind|TestManagedWindowsProductionHostDirectoryOwnership|TestManagedWindowsProductionHostHoldsVerifiedEmptyFile|TestManagedWindowsHostLayoutInheritedPermissions|TestManagedWindowsKeyFileReadsPrivateOwnerKey)$" -test.v -test.count=1'
$testStart.UseShellExecute = $false
$testStart.CreateNoWindow = $true
$testStart.RedirectStandardOutput = $true
$testStart.RedirectStandardError = $true
$testStart.WorkingDirectory = $env:TEMP
$testProcess = [Diagnostics.Process]::Start($testStart)
try {
  $stdout = $testProcess.StandardOutput.ReadToEndAsync()
  $stderr = $testProcess.StandardError.ReadToEndAsync()
  if (!$testProcess.WaitForExit(180000)) { $testProcess.Kill(); throw 'Standard-user test process timed out' }
  [Console]::Out.Write($stdout.GetAwaiter().GetResult())
  [Console]::Error.Write($stderr.GetAwaiter().GetResult())
  [Console]::Out.WriteLine('STANDARD_TEST_EXIT=' + $testProcess.ExitCode)
  exit $testProcess.ExitCode
} finally { $testProcess.Dispose() }
'@
  $driverPath = Join-Path $root 'standard-driver.ps1'
  [IO.File]::WriteAllText($driverPath, $driver, $utf8)
  $start = [Diagnostics.ProcessStartInfo]::new()
  $start.FileName = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
  foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-File', $driverPath)) { $start.ArgumentList.Add($argument) }
  $start.UserName = $account
  $start.Domain = $env:COMPUTERNAME
  $start.Password = $password
  $start.LoadUserProfile = $true
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.WorkingDirectory = $root
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $start.Environment.Clear()
  $start.Environment['SystemRoot'] = $env:SystemRoot
  $start.Environment['WINDIR'] = $env:SystemRoot
  $start.Environment['UH_NATIVE_STANDARD_CONFIGURATION'] = $configPath
  $process = [Diagnostics.Process]::Start($start)
  $outputTask = $process.StandardOutput.ReadToEndAsync()
  $errorTask = $process.StandardError.ReadToEndAsync()
  if (!$process.WaitForExit(240000)) { $process.Kill($true); throw 'Standard-user tests timed out' }
  $output = $outputTask.GetAwaiter().GetResult()
  $errors = $errorTask.GetAwaiter().GetResult()
  [IO.File]::WriteAllText((Join-Path $root 'native-standard-user.log'), $output, $utf8)
  [IO.File]::WriteAllText((Join-Path $root 'native-standard-user-errors.log'), $errors, $utf8)
  $passes = ([regex]::Matches($output, '(?m)^\s*--- PASS:')).Count
  if ($process.ExitCode -ne 0 -or $passes -ne 6 -or $output -match '(?m)^\s*--- SKIP:') { throw 'Every normal standard-user test must pass without administrator membership' }
  $result = [ordered]@{ schema = 1; native_windows = $true; standard_user = $true; is_administrator = $false; source_commit = (& git -C $source rev-parse HEAD).Trim(); source_hashes = $sourceHashes; production_host_helper_sha256 = $helperSHA; exit_code = $process.ExitCode; pass_count = $passes; provider_operations = $false }
  [IO.File]::WriteAllText((Join-Path $root 'native-standard-result.json'), ($result | ConvertTo-Json -Depth 8) + "`n", $utf8)
  $result | ConvertTo-Json -Depth 8
} finally {
  if ($null -ne $process) { if (!$process.HasExited) { $process.Kill($true); $process.WaitForExit() }; $process.Dispose() }
  if ($createdUser) {
    try { Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$sid'" | Remove-CimInstance -ErrorAction Stop } catch { Write-Warning 'Synthetic standard-user profile cleanup unavailable' }
    Remove-LocalUser -Name $account -ErrorAction Stop
  }
  $password.Dispose()
}
