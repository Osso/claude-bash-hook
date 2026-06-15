# Claude Bash Hook

PreToolUse hook for Claude Code that provides granular permission control over Bash and Nushell commands.

## Architecture

- **main.rs** - Hook entry point, reads JSON from stdin, outputs permission decisions
- **analyzer.rs** - Bash AST parsing using tree-sitter-bash
- **nushell.rs** - Nushell command parsing using nu-parser
- **config.rs** - TOML config loading and rule matching (glob patterns, subcommand detection)
- **wrappers/** - Unwrap wrapper commands to analyze inner commands:
  - Config-driven: sudo, authsudo, nice, nohup, time, strace, ltrace, nu, fish
  - Special handling: ssh, scp, rsync, env, kubectl exec, docker exec/compose, timeout, xargs, sh/bash/zsh, kitty-remote, wezterm-remote
- **scripts/** - Script content analysis (parses inline code to allow safe read-only scripts):
  - python.rs - Python via `-c` or heredoc (allows file I/O, denies subprocess/os.system/eval)
  - shell.rs - Shell scripts via `sh -c` / `bash -c` (re-parses inner commands through the same rule engine)
  - php.rs - PHP via `-r` flag (allows read-only operations, denies exec/system/passthru)
  - lua.rs - Lua/LuaJIT via `-e` flag (allows read-only ops, denies os.execute/io.popen/ffi)
  - perl.rs - Perl via `-e`/`-E` flag (allows read-only ops, asks on open-for-write/unlink/system/backticks)
  - node.rs - Node via `-e`/`-p`/`--eval`/`--print` (allows read-only ops, asks on fs writes/child_process/network/eval)
  - ruby.rs - Ruby via `-e` flag (allows read-only ops, asks on File writes/system/backticks/network/eval)
  - awk.rs - AWK/gawk/mawk programs (allows text processing, asks on in-script `> file`/`| cmd`/`getline`/`system()`)
- **tool_handlers.rs** - Non-bash tool handling (Write, Edit, regex-replace) with main thread blocking
- **sql.rs** - MySQL/MariaDB/SQLite query analysis (allow SELECT, ask for writes)
- **redis.rs** - Redis command analysis (allow read-only commands like GET/LLEN, ask for writes)
- **git.rs** - Git-specific rules (push branch protection, checkout handling)
- **docker.rs** - Docker run bind mount analysis
- **tar.rs** - Tar extraction path validation
- **rm.rs** - Delete command path validation
- **tee.rs** - Tee output path validation
- **copy_move.rs** - Write-target validation for cp/mv/install/ln/mkdir/touch/chmod/chown/chgrp, compression tools (gzip/gunzip/bzip2/xz/zstd/...), and output-file flags of fetchers/sorters (wget -O/-P, curl -o, sort/shuf -o, uniq OUTPUT), and yq/xq -i in-place edits. Shell output redirects (`>`, `>>`) are captured in analyzer.rs and checked in analysis.rs
- **advice.rs** - Optional AI-powered advice for permission decisions

## Build

```bash
cargo build --release
```

Deploy: `bash deploy.sh` (installs both binaries to `~/bin/` via `cargo install`)

## Config

Location: `~/.config/claude-bash-hook/config.toml`

Default config embedded in binary (`config.default.toml`). Copy and customize:

```bash
mkdir -p ~/.config/claude-bash-hook
cp config.default.toml ~/.config/claude-bash-hook/config.toml
```

### Config Format

```toml
default = "passthrough"  # allow, ask, deny, passthrough
enable_advice = false    # AI-powered advice for ask/deny decisions

[[rules]]
commands = ["ls", "cat", "git status"]  # Command or command+subcommand patterns
permission = "allow"                     # allow, ask, deny, passthrough, check_host
reason = "read-only commands"
cwd = "/home/user/project"              # Optional: only match in this directory tree

[[rules]]
commands = ["ssh", "scp"]
permission = "check_host"
reason = "remote connection"
host_rules = [
    { pattern = "*.internal.com", permission = "allow" },
    { pattern = "*", permission = "ask" },
]

[[wrappers]]
command = "sudo"
opts_with_args = ["-u", "-g"]  # Options that consume the next argument

[[suggestions]]
command = "git checkout"
message = "Consider using 'git switch' instead"

[[aliases]]
from = "fdfind"
to = "fd"
```

### Context Overrides

Rules support context-dependent permission overrides:

- **edit_mode_permission** - Override when Claude is in edit/acceptEdits mode
- **subagent_permission** - Override for subagent contexts (Task() workers)
- **main_thread_permission** - Override for main thread when `main_thread_default` is set

Priority: `subagent_permission` > `edit_mode_permission` > base `permission`

### Main Thread Control

When `main_thread_default` is set (e.g., `"deny"`), ALL main thread commands are blocked unless the matching rule has an explicit `main_thread_permission`. This forces delegation to Task() subagents.

Affects: Bash, Nushell, Write, Edit tools. Subagents are unaffected.

```toml
main_thread_default = "deny"  # Block all main thread commands

[[rules]]
commands = ["git status", "git log", "git diff"]
permission = "allow"
main_thread_permission = "allow"  # Exempt from main thread block
reason = "git read-only"
```

### Global Defaults

- **default** - Fallback for unmatched commands
- **subagent_default** - Fallback for unmatched commands in subagent context
- **main_thread_default** - When set, overrides all main thread permissions (rule and default)

### Permission Levels

- **allow** - Auto-approve, no user prompt
- **passthrough** - Let Claude Code's built-in system handle (for Bash only; becomes "ask" for Nushell MCP)
- **ask** - Prompt user for approval
- **deny** - Block with reason

## Hook Protocol

Receives JSON on stdin:
```json
{
  "tool_name": "Bash",
  "tool_input": { "command": "ls -la" },
  "permission_mode": "default",
  "cwd": "/home/user/project"
}
```

Outputs JSON to stdout (or nothing for passthrough):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "read-only commands"
  }
}
```

Also handles:
- `Write` / `Edit` tools - auto-allows paths in `write_allow_paths` (e.g., `/tmp/*`); asks on `ask_paths` or `ask_write_paths` (win over allow); denies on main thread when `main_thread_default` is set
- `ask_write_paths` - like `ask_paths` but for *modifying* ops only, not Read. Covers Write/Edit, rm/tee, cp/mv/install/ln/mkdir/touch/chmod/chown/chgrp targets, and shell output redirects (`>`, `>>`). For system dirs (`/usr/*`, etc.) where reads are frequent but writes are dangerous
- `mcp__regex-replace__regex_replace` - Auto-allows in edit mode, subagent, or dry run; asks otherwise
- `mcp__nushell__execute` - Nushell MCP tool (passthrough becomes ask)

## Testing

```bash
cargo test
```

## Logging

Logs to journald with identifier `claude-bash-hook`:

```bash
journalctl -t claude-bash-hook -f
```
