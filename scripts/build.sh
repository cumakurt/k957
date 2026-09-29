#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
export CGO_ENABLED=0
for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
  target_os="${target%/*}"
  target_arch="${target#*/}"
  suffix=""
  if [ "$target_os" = windows ]; then suffix=".exe"; fi
  output="dist/k957-${target_os}-${target_arch}${suffix}"
  GOOS="$target_os" GOARCH="$target_arch" go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$output" ./cmd/k957
  printf '%s\n' "Built $output"
done
