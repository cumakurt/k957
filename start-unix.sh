#!/usr/bin/env sh
set -eu
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$(uname -s)" in Linux) platform=linux;; Darwin) platform=darwin;; *) echo 'Unsupported launcher platform'; exit 1;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64;; arm64|aarch64) arch=arm64;; *) echo 'Unsupported launcher architecture'; exit 1;; esac
exec "$base/dist/k957-$platform-$arch" wizard
