#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

# Remove old symlinks from previous deploys (cargo install needs a regular file).
rm -f ~/bin/claude-bash-hook ~/bin/claude-bash-hook-approval

cargo install --path . --root ~ --force \
    --bin claude-bash-hook \
    --bin claude-bash-hook-approval
