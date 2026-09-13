<#
  Blackbox installer for Windows.

    irm https://github.com/HyperonX-Team/blackbox/releases/latest/download/install.ps1 | iex

  Options:
    -Version     a release tag such as v0.2.0, or "latest" (default)
    -InstallDir  where to put the programs (default %LOCALAPPDATA%\Programs\Blackbox)
    -NoPath      do not add the install directory to your PATH

  Downloads the release archive for this machine, checks it against the
  release SHA256SUMS.txt, installs blackbox.exe and blackbox-gui.exe, and
  adds the install directory to your user PATH.

  This file is deliberately pure ASCII so that Windows PowerShell 5.1 reads
  it correctly without a byte order mark.
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

# ------------------------------------------------------------------ output
function Show-Banner {
  Write-Host ''
  @(
    '  ____   _         _      ____  _  __ ____    ___  __  __',
    ' | __ ) | |       / \    / ___|| |/ /| __ )  / _ \ \ \/ /',
    ' |  _ \ | |      / _ \  | |    | '' / |  _ \ | | | | \  /',
    ' | |_) || |___  / ___ \ | |___ | . \ | |_) || |_| | /  \',
    ' |____/ |_____|/_/   \_\ \____||_|\_\|____/  \___/ /_/\_\'
  ) | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
}

function Show-Rule { Write-Host ('  ' + ('-' * 62)) -ForegroundColor DarkGray }
function Show-Title($text) { Write-Host ('  ' + $text) -ForegroundColor White }
function Show-Field($key, $value) {
  Write-Host ('  ' + $key.PadRight(10) + ' ') -NoNewline -ForegroundColor DarkGray
  Write-Host $value
}
function Show-Step($n, $total, $message) {
  Write-Host ('  [' + $n + '/' + $total + '] ' + $message) -ForegroundColor DarkGray
}
function Show-Ok($message) { Write-Host ('        ' + $message) -ForegroundColor Green }
function Fail($message) {
  Write-Host ''
  Write-Host ('  error ' + $message) -ForegroundColor Yellow
  Write-Host ''
  exit 1
}

if ($Version -eq 'latest') {
  $base = "https://github.com/$repo/releases/latest/download"
} else {
  $base = "https://github.com/$repo/releases/download/$Version"
}

Show-Banner
Show-Rule
Show-Title 'install a machine'
Write-Host ''
Show-Field 'platform' 'windows x86_64'
Show-Field 'release'  $Version
Show-Field 'archive'  $asset
Write-Host ''

$work = Join-Path ([IO.Path]::GetTempPath()) ("blackbox-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null

try {
  # 1 ---------------------------------------------------------------- download
  Show-Step 1 4 ('downloading ' + $asset)
  $zipPath = Join-Path $work $asset
  try {
    Invoke-WebRequest -Uri "$base/$asset" -OutFile $zipPath -UseBasicParsing
  } catch {
    Fail "download failed: $base/$asset"
  }
  Show-Ok ('{0:N0} bytes' -f (Get-Item $zipPath).Length)

  # 2 ---------------------------------------------------------------- verify
  Show-Step 2 4 'verifying checksum'
  $verified = $false
  try {
    $sumsPath = Join-Path $work 'SHA256SUMS.txt'
    Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile $sumsPath -UseBasicParsing
    $line = Select-String -Path $sumsPath -Pattern ([regex]::Escape(" $asset")) | Select-Object -First 1
    if ($line) {
      $expected = ($line.Line -split '\s+')[0].ToLower()
      $actual = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLower()
      if ($expected -ne $actual) { Fail 'checksum mismatch, refusing to install' }
      $verified = $true
    }
  } catch { }
  if ($verified) { Show-Ok 'matches SHA256SUMS.txt' } else { Show-Ok 'checksums not reachable, skipping' }

  # 3 ---------------------------------------------------------------- install
  Show-Step 3 4 ('installing to ' + $InstallDir)
  $extract = Join-Path $work 'unpacked'
  Expand-Archive -Path $zipPath -DestinationPath $extract -Force
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  foreach ($exe in @('blackbox.exe', 'blackbox-gui.exe')) {
    $src = Join-Path $extract $exe
    if (Test-Path $src) { Copy-Item $src (Join-Path $InstallDir $exe) -Force }
  }
  Show-Ok 'done'

  # 4 ---------------------------------------------------------------- PATH
  Show-Step 4 4 'adding to your PATH'
  if ($NoPath) {
    Show-Ok 'skipped (-NoPath)'
  } else {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    $parts = $userPath.Split(';') | Where-Object { $_ -ne '' }
    if ($parts -contains $InstallDir) {
      Show-Ok 'already on your PATH'
    } else {
      [Environment]::SetEnvironmentVariable('Path', ((@($parts) + $InstallDir) -join ';'), 'User')
      $env:Path = "$env:Path;$InstallDir"
      Show-Ok 'added'
    }
  }

  # ---------------------------------------------------------------- summary
  Write-Host ''
  Show-Rule
  Write-Host '  installed' -ForegroundColor White
  Write-Host ''
  Write-Host ('  ' + 'blackbox'.PadRight(14) + ' ') -NoNewline -ForegroundColor DarkGray
  Write-Host (Join-Path $InstallDir 'blackbox.exe')
  Write-Host ('  ' + 'blackbox-gui'.PadRight(14) + ' ') -NoNewline -ForegroundColor DarkGray
  Write-Host (Join-Path $InstallDir 'blackbox-gui.exe')
  Write-Host ''
  if ($NoPath) {
    Write-Host '  add it to your PATH' -ForegroundColor White
    Write-Host ''
    Write-Host ('  [Environment]::SetEnvironmentVariable(''Path'', $env:Path + '';' + $InstallDir + ''', ''User'')')
    Write-Host ''
  }
  Write-Host '  open a new terminal, then' -ForegroundColor White
  Write-Host ''
  Write-Host '  blackbox doctor'
  Write-Host ''
}
finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
