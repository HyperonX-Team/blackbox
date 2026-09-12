<#
  Blackbox installer for Windows.

    irm https://raw.githubusercontent.com/HyperonX-Team/blackbox/main/packaging/install.ps1 | iex

  Options:
    -Version     a release tag such as v0.2.0, or "latest" (default)
    -InstallDir  where to put the programs (default %LOCALAPPDATA%\Programs\Blackbox)
    -NoPath      do not add the install directory to your PATH

  Downloads the release archive for this machine, checks it against the
  release SHA256SUMS.txt, installs blackbox.exe and blackbox-gui.exe, and
  adds the install directory to your user PATH.
#>
[CmdletBinding()]
param(
  [string]$Version = 'latest',
  [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\Blackbox'),
  [switch]$NoPath
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = 'HyperonX-Team/blackbox'
$asset = 'blackbox-windows-x86_64.zip'

if ($Version -eq 'latest') {
  $base = "https://github.com/$repo/releases/latest/download"
} else {
  $base = "https://github.com/$repo/releases/download/$Version"
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("blackbox-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null

try {
  $zipPath = Join-Path $work $asset
  Write-Host "Downloading $asset"
  Invoke-WebRequest -Uri "$base/$asset" -OutFile $zipPath -UseBasicParsing

  # Verify against the published checksums when we can get them.
  try {
    $sumsPath = Join-Path $work 'SHA256SUMS.txt'
    Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile $sumsPath -UseBasicParsing
    $line = Select-String -Path $sumsPath -Pattern ([regex]::Escape(" $asset")) | Select-Object -First 1
    if ($line) {
      $expected = ($line.Line -split '\s+')[0].ToLower()
      $actual = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLower()
      if ($expected -ne $actual) { throw "checksum mismatch, refusing to install" }
      Write-Host "Checksum verified"
    }
  } catch [System.Net.WebException] {
    Write-Warning "Could not fetch SHA256SUMS.txt; skipping verification"
  }

  $extract = Join-Path $work 'unpacked'
  Expand-Archive -Path $zipPath -DestinationPath $extract -Force

  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  foreach ($exe in @('blackbox.exe', 'blackbox-gui.exe')) {
    $src = Join-Path $extract $exe
    if (Test-Path $src) {
      Copy-Item $src (Join-Path $InstallDir $exe) -Force
    }
  }

  if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    $parts = $userPath.Split(';') | Where-Object { $_ -ne '' }
    if ($parts -notcontains $InstallDir) {
      $newPath = (@($parts) + $InstallDir) -join ';'
      [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
      $env:Path = "$env:Path;$InstallDir"
      Write-Host "Added $InstallDir to your user PATH"
    }
  }

  Write-Host ""
  Write-Host "Installed to $InstallDir"
  Write-Host "  blackbox.exe      command line"
  Write-Host "  blackbox-gui.exe  desktop app"
  Write-Host ""
  Write-Host "Open a new terminal, then run: blackbox doctor"
}
finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
