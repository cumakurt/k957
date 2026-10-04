#!/usr/bin/env bash
# Build release binaries with CGO disabled and checked platform libraries.
# macOS retains the Go runtime and native X.509 platform frameworks.
set -euo pipefail
cd "$(dirname "$0")/.."

bold='' cyan='' green='' red='' dim='' reset=''
interactive=false
if [[ -t 1 && ${TERM:-dumb} != dumb ]]; then
  interactive=true
fi
if [[ -z ${NO_COLOR:-} ]] && { $interactive || [[ -n ${FORCE_COLOR:-} && ${FORCE_COLOR} != 0 ]]; }; then
  bold=$'\033[1m' cyan=$'\033[36m' green=$'\033[32m'
  red=$'\033[31m' dim=$'\033[2m' reset=$'\033[0m'
fi

started=$SECONDS
completed=0
target='preparation'
stage='initializing'
build_log=''
active_line=false

clear_status() {
  if $active_line; then printf '\r\033[K'; fi
  active_line=false
}

finish() {
  local code=$?
  trap - EXIT
  clear_status
  if (( code != 0 )); then
    printf '\n%sBUILD FAILED%s  %s / %s\n' "$red$bold" "$reset" "$target" "$stage" >&2
    printf '  Completed %s/6 targets in %ss. Exit code: %s\n' "$completed" "$((SECONDS - started))" "$code" >&2
    if [[ -n $build_log && -s $build_log ]]; then
      printf '\n' >&2
      cat "$build_log" >&2
    fi
  fi
  if [[ -n $build_log ]]; then rm -f -- "$build_log"; fi
  exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

status() {
  stage=$1
  clear_status
  printf '%s  [%s/6] %-15s%s  %s' "$cyan" "$((completed + 1))" "$target" "$reset" "$stage"
  if $interactive; then active_line=true; else printf '\n'; fi
}

printf '\n%s  K957%s  /  RELEASE BUILD\n' "$bold$cyan" "$reset"
printf '%s  ------------------------------------------------------------%s\n' "$dim" "$reset"
printf '  Targets  6  |  CGO disabled  |  netgo + osusergo\n'

build_log=$(mktemp "${TMPDIR:-/tmp}/k957-build.XXXXXXXX")
stage='source fingerprint'
source_sha256=$(python3 scripts/source_identity.py 2>"$build_log")
printf '  Source   %s\n' "${source_sha256:0:16}"
printf '  Output   dist/\n\n'
stage='output directory'
mkdir -p dist
export CGO_ENABLED=0
ldflags="-s -w -linkmode=internal -X k957/internal/core.BuildSourceSHA256=$source_sha256"

for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
  target_started=$SECONDS
  target_os="${target%/*}"
  target_arch="${target#*/}"
  suffix=''
  if [[ $target_os == windows ]]; then suffix='.exe'; fi
  output="dist/k957-${target_os}-${target_arch}${suffix}"

  status 'Compiling'
  GOOS="$target_os" GOARCH="$target_arch" go build \
    -trimpath -buildvcs=false -tags 'netgo osusergo' -ldflags="$ldflags" \
    -o "$output" ./cmd/k957 >"$build_log" 2>&1

  status 'Checking platform libraries'
  python3 scripts/check_static.py "$output" >"$build_log" 2>&1
  stage='artifact size'
  size=$(python3 -c 'import os, sys; print(f"{os.path.getsize(sys.argv[1]) / (1 << 20):.1f} MiB")' "$output" 2>"$build_log")
  clear_status
  printf '%s  DONE%s  %-15s  %6ss  %10s\n' "$green$bold" "$reset" "$target" "$((SECONDS - target_started))" "$size"
  printf '%s        %s%s\n' "$dim" "$output" "$reset"
  completed=$((completed + 1))
done

target='all targets'
stage='source consistency'
final_source_sha256=$(python3 scripts/source_identity.py 2>"$build_log")
if [[ $final_source_sha256 != "$source_sha256" ]]; then
  printf 'Source files changed during compilation. Rebuild before using these artifacts.\n' >"$build_log"
  exit 1
fi

printf '\n%s  BUILD COMPLETE%s  %s/6 targets  |  %ss elapsed\n' "$green$bold" "$reset" "$completed" "$((SECONDS - started))"
printf '  All artifacts passed the platform library policy.\n\n'
