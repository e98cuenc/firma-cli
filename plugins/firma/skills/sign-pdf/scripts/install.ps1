# Installs the latest firma release for Windows into %LOCALAPPDATA%\firma (or $env:FIRMA_INSTALL_DIR),
# verifying the archive against the release's SHA256SUMS.txt, and adds it to the user's PATH.
$ErrorActionPreference = 'Stop'
$repo = if ($env:FIRMA_REPO) { $env:FIRMA_REPO } else { 'e98cuenc/firma-cli' }
$dest = if ($env:FIRMA_INSTALL_DIR) { $env:FIRMA_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'firma' }
$archive = 'firma-x86_64-windows.zip'
$base = "https://github.com/$repo/releases/latest/download"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$archive" -OutFile (Join-Path $tmp $archive)
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.txt" -OutFile (Join-Path $tmp 'SHA256SUMS.txt')
    $line = Get-Content (Join-Path $tmp 'SHA256SUMS.txt') | Where-Object { $_ -match "\s\*?$([regex]::Escape($archive))$" }
    $expected = ($line -split '\s+')[0]
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $archive)).Hash.ToLower()
    if (-not $expected -or $expected.ToLower() -ne $actual) { throw "checksum mismatch for $archive; not installing" }
    Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Copy-Item (Join-Path $tmp 'firma.exe') (Join-Path $dest 'firma.exe') -Force
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not ($userPath -split ';' | Where-Object { $_ -eq $dest })) {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$dest", 'User')
        Write-Output "added $dest to your PATH (open a new terminal)"
    }
    Write-Output "installed $(& (Join-Path $dest 'firma.exe') --version) to $dest"
} finally {
    Remove-Item -Recurse -Force $tmp
}
