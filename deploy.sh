#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Building..."
cargo build --release

echo "Installed claude-bash-hook (symlinked from ~/bin/)"
