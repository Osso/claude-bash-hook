# claude-bash-hook

A PreToolUse hook that parses bash commands before execution. Understands wrappers (sudo, kubectl exec, ssh), SQL queries, and subcommands so you can allow `kubectl get` but ask for `kubectl delete`, or let SELECTs through while catching writes.

Beats manually approving every `ls` or blindly allowing everything.

## Installation

### 1. Build

```bash
git clone https://github.com/yourusername/claude-bash-hook
cd claude-bash-hook
cargo build --release
```

### 2. Install the binary

```bash
cp target/release/claude-bash-hook ~/.local/bin/
# or wherever you keep your binaries
```

### 3. Create config

```bash
mkdir -p ~/.config/claude-bash-hook
cp config.example.toml ~/.config/claude-bash-hook/config.toml
```

Edit `config.toml` to match your workflow. The example config has sensible defaults.

### 4. Register the hook

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "claude-bash-hook"
          }
        ]
      }
    ]
  }
}
```

## Config examples

```toml
# Default for unknown commands
default = "ask"

# Allow read-only commands
[[rules]]
commands = ["ls", "cat", "grep", "find", "ps", "df"]
permission = "allow"
reason = "read-only"

# Allow git read operations
[[rules]]
commands = ["git status", "git log", "git diff", "git branch"]
permission = "allow"
reason = "git read-only"

# Ask for git write operations
[[rules]]
commands = ["git push", "git push --force"]
permission = "ask"
reason = "git push"

# Recursive delete asks (not auto-denied)
[[rules]]
commands = ["rm -rf", "rm -r"]
permission = "ask"
reason = "recursive delete"
```

## Features

### Wrapper unwrapping

Commands like `sudo`, `env`, `kubectl exec`, `ssh`, and `timeout` are unwrapped to analyze the inner command:

```bash
sudo rm -rf /tmp    # checks "rm -rf" rule, not "sudo" rule
kubectl exec pod -- ls  # checks "ls" rule
```

### SQL query parsing

For `mysql`/`mariadb` commands, the `-e` query is parsed:

```bash
mysql -e "SELECT * FROM users"  # allowed (read-only)
mysql -e "DELETE FROM users"    # asks (write operation)
```

### Subcommand matching

Rules can match command + subcommand:

```bash
kubectl get pods    # matches "kubectl get" -> allow
kubectl delete pod  # matches "kubectl delete" -> ask
```

### Suggestions

Suggest better alternatives:

```toml
[[suggestions]]
command = "git checkout"
message = "Consider using 'git switch' or 'git restore' instead"
```

## How it works

1. Claude Code calls the hook before executing a bash command
2. Hook parses the command using tree-sitter-bash
3. Checks against rules in order (first match wins)
4. Returns `allow`, `ask`, or `deny` to Claude Code
