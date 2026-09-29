$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
New-Item -ItemType Directory -Force dist | Out-Null
$oldOS=$env:GOOS; $oldArch=$env:GOARCH; $oldCGO=$env:CGO_ENABLED
try {
  $env:CGO_ENABLED='0'
  foreach ($target in @('linux/amd64','linux/arm64','windows/amd64','windows/arm64','darwin/amd64','darwin/arm64')) {
    $parts=$target.Split('/'); $env:GOOS=$parts[0]; $env:GOARCH=$parts[1]
    $suffix=''; if ($env:GOOS -eq 'windows') {$suffix='.exe'}
    $output="dist/k957-$($env:GOOS)-$($env:GOARCH)$suffix"
    go build -trimpath -buildvcs=false -ldflags='-s -w' -o $output ./cmd/k957
    if ($LASTEXITCODE -ne 0) {throw "Build failed: $target"}
    Write-Host "Built $output"
  }
} finally {$env:GOOS=$oldOS; $env:GOARCH=$oldArch; $env:CGO_ENABLED=$oldCGO}
