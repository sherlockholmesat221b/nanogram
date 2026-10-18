#!/bin/sh
# File: scripts/build-web.sh

set -eu

mkdir -p web

GOOS=js GOARCH=wasm go build -o web/main.wasm ./cmd/argwasm

GOROOT=$(go env GOROOT)
WASM_EXEC="$GOROOT/lib/wasm/wasm_exec.js"

if [ ! -f "$WASM_EXEC" ]; then
    WASM_EXEC="$GOROOT/misc/wasm/wasm_exec.js"
fi

if [ ! -f "$WASM_EXEC" ]; then
    echo "error: wasm_exec.js not found in $GOROOT/lib/wasm/ or $GOROOT/misc/wasm/" >&2
    exit 1
fi

cp "$WASM_EXEC" web/wasm_exec.js

echo "ok"
