# Build every release binary as a static Go program.
# CGO is disabled and the pure-Go resolver and user lookup are selected, so
# Linux and Windows binaries do not link libc. macOS still links libSystem and
# libresolv and the platform X.509 trust frameworks. scripts/check_static.py
# rejects anything else.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
New-Item -ItemType Directory -Force dist | Out-Null
$oldOS = $env:GOOS
$oldArch = $env:GOARCH
$oldCGO = $env:CGO_ENABLED
try {
  $env:CGO_ENABLED = '0'
  $sourceSHA256 = python scripts/source_identity.py
  if ($LASTEXITCODE -ne 0) { throw 'Source fingerprint failed' }
  foreach ($target in @('linux/amd64', 'linux/arm64', 'windows/amd64', 'windows/arm64', 'darwin/amd64', 'darwin/arm64')) {
    $parts = $target.Split('/')
    $env:GOOS = $parts[0]
    $env:GOARCH = $parts[1]
    $suffix = ''
    if ($env:GOOS -eq 'windows') { $suffix = '.exe' }
    $output = "dist/k957-$($env:GOOS)-$($env:GOARCH)$suffix"
    go build -trimpath -buildvcs=false -tags 'netgo osusergo' -ldflags "-s -w -linkmode=internal -X k957/internal/core.BuildSourceSHA256=$sourceSHA256" -o $output ./cmd/k957
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $target" }
    python scripts/check_static.py $output
    if ($LASTEXITCODE -ne 0) { throw "Static check failed: $output" }
    Write-Host "Built static $output"
  }
} finally {
  $env:GOOS = $oldOS
  $env:GOARCH = $oldArch
  $env:CGO_ENABLED = $oldCGO
}
