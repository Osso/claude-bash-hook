#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

# Remove stale copies from previous deploys (older installs targeted ~/bin;
# settings.json invokes the hook by absolute path from ~/.cargo/bin).
rm -f ~/bin/claude-bash-hook ~/bin/claude-bash-hook-approval ~/bin/php-readability

cargo install --path . --root ~/.cargo --force \
    --bin claude-bash-hook \
    --bin claude-bash-hook-approval \
    --bin php-readability
