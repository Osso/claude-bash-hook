#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Building..."
cargo build --release

for bin in claude-bash-hook approval_prompt; do
    src="$(pwd)/target/release/$bin"
    [[ -x "$src" ]] || { echo "missing build output: $src"; exit 1; }
done

ln -sfn "$(pwd)/target/release/approval_prompt" ~/bin/claude-bash-hook-approval

echo "Installed claude-bash-hook and claude-bash-hook-approval (symlinked from ~/bin/)"
