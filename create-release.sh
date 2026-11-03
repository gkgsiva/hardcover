#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" || ! "$VERSION" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Usage: $0 <version> (for example: v1.0.0)" >&2
    exit 2
fi

for command in zip; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Required command not found: $command" >&2
        exit 1
    fi
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="$SCRIPT_DIR/hardcover.koplugin-${VERSION}.zip"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

PLUGIN_DIR="$TEMP_DIR/hardcover.koplugin"
mkdir -p "$PLUGIN_DIR"
cp "$SCRIPT_DIR/main.lua" "$SCRIPT_DIR/_meta.lua" "$PLUGIN_DIR/"

(cd "$TEMP_DIR" && zip -q -r "$OUTPUT" hardcover.koplugin)
echo "Created release archive: $OUTPUT"
