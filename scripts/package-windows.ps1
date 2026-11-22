<#
.SYNOPSIS
  Builds the Windows package of Proculus: dist\proculus-<version>-windows-<arch>.zip

.DESCRIPTION
  Proculus uses POSIX calls (fork, poll, process groups, POSIX sockets), so on Windows it is built under Cygwin, a POSIX
  layer. This script installs Cygwin (to C:\cygwin64, if it is not there yet), builds the program inside it, copies the
  few Cygwin DLLs it needs next to proculus.exe, smoke-tests the result and zips it. Then it builds the DESKTOP APPLICATION
  (Electron): a single Proculus-<version>-windows-<arch>-portable.exe that opens Proculus in a window of its own when
  double-clicked, no browser. That step needs Node.js (the script installs it with winget if it can).

  Run it from PowerShell in the repository (no administrator rights needed unless Cygwin needs to be installed in C:\):
      powershell -ExecutionPolicy Bypass -File scripts\package-windows.ps1

  The whole output is also written to dist\windows-build.log: send that file if something fails.
  The package needs nmap for real scans (https://nmap.org/download); the simulation needs nothing.

.PARAMETER CygwinRoot   where Cygwin is (or will be installed). Default C:\cygwin64
.PARAMETER Mirror       Cygwin download mirror
.PARAMETER SkipInstall  do not run the Cygwin installer (use what is there)
.PARAMETER SkipSmoke    skip starting the finished program as a test
.PARAMETER SkipDesktop  only build the zip; do not build the desktop application (Proculus-<version>-windows-<arch>-portable.exe)
#>
param(
	[string]$CygwinRoot = "C:\cygwin64",
	[string]$Mirror = "https://mirrors.kernel.org/sourceware/cygwin/",
	[switch]$SkipInstall,
	[switch]$SkipSmoke,
	[switch]$SkipDesktop
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$dist = Join-Path $repo "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$log = Join-Path $dist "windows-build.log"
Start-Transcript -Path $log -Force | Out-Null

try {
	# the Cygwin packages the build needs (if a name is wrong for your Cygwin version, the installer skips it and
	# scripts/package.sh says which library is missing)
	$packages = @(
		"gcc-g++", "gcc-core", "make", "cmake", "ninja", "pkg-config", "git", "zip", "unzip", "curl", "binutils",
		"libpcre2-devel", "libexpat-devel", "libssl-devel", "libsodium-devel", "libpq-devel", "zlib-devel"
	) -join ","

	$bash = Join-Path $CygwinRoot "bin\bash.exe"
	if (-not $SkipInstall -or -not (Test-Path $bash)) {
		Write-Host "==> Installing / updating Cygwin in $CygwinRoot (the first time this downloads a few hundred MB)"
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		$setup = Join-Path $env:TEMP "cygwin-setup-x86_64.exe"
		if (-not (Test-Path $setup)) { Invoke-WebRequest -Uri "https://cygwin.com/setup-x86_64.exe" -OutFile $setup -UseBasicParsing }
		$setupArgs = @("--quiet-mode", "--no-desktop", "--no-startmenu", "--no-admin", "--root", $CygwinRoot, "--site", $Mirror,
		          "--local-package-dir", (Join-Path $env:TEMP "cygwin-packages"), "--packages", $packages)
		$p = Start-Process -FilePath $setup -ArgumentList $setupArgs -Wait -PassThru
		if ($p.ExitCode -ne 0) { throw "the Cygwin installer failed (exit code $($p.ExitCode)); see its log in $CygwinRoot\var\log\setup.log" }
	}
	if (-not (Test-Path $bash)) { throw "Cygwin was not found at $CygwinRoot" }

	Write-Host "==> Building inside Cygwin"
	$env:PROCULUS_WIN_ROOT = $repo
	$env:CHERE_INVOKING = "1"
	if ($SkipSmoke) { $env:SKIP_SMOKE = "1" }
	# -o igncr: a checkout with Windows (CRLF) line endings still runs
	& $bash -lc 'cd "$(cygpath -u "$PROCULUS_WIN_ROOT")" && bash -o igncr scripts/package.sh windows'
	if ($LASTEXITCODE -ne 0) { throw "the build failed (exit code $LASTEXITCODE); the messages above and $log show where" }

	$zip = Get-ChildItem -Path $dist -Filter "proculus-*-windows-*.zip" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
	Write-Host ""
	Write-Host "Command-line package: $($zip.FullName)  (unpack, run start-simulation.cmd or start.cmd)"

	if (-not $SkipDesktop) {
		Write-Host "==> Building the desktop application (Electron)"
		$node = Get-Command node -ErrorAction SilentlyContinue
		if (-not $node -and (Get-Command winget -ErrorAction SilentlyContinue)) {
			Write-Host "Installing Node.js with winget..."
			winget install --id OpenJS.NodeJS.LTS -e --accept-package-agreements --accept-source-agreements
			$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
			$node = Get-Command node -ErrorAction SilentlyContinue
		}
		if (-not $node) { throw "Node.js is needed for the desktop application: install it from https://nodejs.org, open a new PowerShell and run this script again (or use -SkipDesktop)" }
		$staged = Get-ChildItem -Path $dist -Directory -Filter "proculus-*-windows-*" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
		& node (Join-Path $repo "desktop\build.js") $staged.FullName $dist
		if ($LASTEXITCODE -ne 0) { throw "building the desktop application failed (exit code $LASTEXITCODE)" }
		$app = Get-ChildItem -Path $dist -Filter "Proculus-*-portable.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
		Write-Host ""
		Write-Host "Desktop application: $($app.FullName)"
		Write-Host "Double-click it: Proculus opens in its own window. (Windows may show a SmartScreen warning for the unsigned program: More info > Run anyway.)"
	}
}
catch {
	Write-Host ""
	Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
	Write-Host "The full output is in $log"
	exit 1
}
finally {
	Stop-Transcript | Out-Null
}
