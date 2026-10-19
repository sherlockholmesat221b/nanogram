#!/bin/sh
# File: scripts/check.sh

set -eu

cd "$(git rev-parse --show-toplevel)"

unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
    printf '%s\n' "gofmt check failed; unformatted files:"
    printf '%s\n' "$unformatted"
    exit 1
fi

packages=$(go list ./client/... ./internal/... ./cmd/argbench)

go vet $packages
GOOS=js GOARCH=wasm go vet ./cmd/argwasm

go test -count=1 $packages

go mod verify

printf '%s\n' "all checks passed"
