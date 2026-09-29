#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go vet ./...
go test -count=1 -cover ./...
# Optional native race build requires a C compiler:
# go test -race ./...
# Optional mutation campaigns:
# go test ./internal/core -run='^$' -fuzz=FuzzEnvelope -fuzztime=30s
# go test ./internal/core -run='^$' -fuzz=FuzzRules -fuzztime=30s
# go test ./internal/core -run='^$' -fuzz=FuzzStructuredLogs -fuzztime=30s
# go test ./internal/core -run='^$' -fuzz=FuzzPCAP -fuzztime=30s
# go test ./internal/core -run='^$' -fuzz=FuzzPCAPNG -fuzztime=30s
# Native CLI integration (requires a freshly built dist binary):
# python3 scripts/pcap_integration.py
# python3 scripts/pcapng_integration.py
# See docs/TEST_REPORT.md for all integration scripts and their dependencies.
# Full native validation with logs: python3 scripts/validate.py --out validation-results
