#!/usr/bin/env bash

set -euo pipefail

# run `forge build --build-info --via-ir --optimize` first and check in out/build-info for the largest file (or any file that contains input and stuff for solc to consume)

intermediate=$(mktemp)
jq '.input' "$1" > "$intermediate"
jq 'del(.version) | walk(if type == "object" then del(.allowPaths, .basePath, .includePath, .includePaths, ._format) else . end)' "$intermediate" > "$2"
rm "$intermediate"
