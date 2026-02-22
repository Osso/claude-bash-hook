//! Claude Code Bash Permission Hook
//!
//! A PreToolUse hook that analyzes bash and nushell commands and provides granular permission control.

mod advice;
mod analyzer;
mod cargo;
mod config;
mod curl;
mod docker;
mod git;
mod kill;
mod nushell;
mod output;
mod redis;
mod rm;
mod scripts;
mod sql;
mod tar;
mod tee;
mod wrappers;

use config::{Config, ExecContext, Permission, PermissionResult};
use log::info;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

/// Input from Claude Code hook
#[derive(Debug, Deserialize)]
struct HookInput {
    tool_name: String,
    tool_input: ToolInput,
    /// Permission mode: "default", "plan", "acceptEdits", "bypassPermissions"
    #[serde(default)]
    permission_mode: Option<String>,
    /// Working directory where Claude Code session started
    #[serde(default)]
    cwd: Option<String>,
    /// Path to the conversation transcript file
    /// Subagents have "/subagents/" in their path
    #[serde(default)]
    transcript_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ToolInput {
    command: Option<String>,
    cwd: Option<String>,
    // For Write tool
    file_path: Option<String>,
    // For regex-replace MCP tool
    dry_run: Option<bool>,
}

/// Check if edits are allowed based on permission mode
fn edits_allowed(mode: Option<&str>) -> bool {
    matches!(mode, Some("acceptEdits") | Some("bypassPermissions"))
}

/// Output to Claude Code
#[derive(Debug, Serialize)]
struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    event_name: String,
    #[serde(rename = "permissionDecision")]
    decision: String,
    #[serde(rename = "permissionDecisionReason")]
    reason: String,
}

/// Check if a Write tool path should be blocked
/// Returns Some((decision, reason)) if we should output a decision, None to pass through
pub(crate) fn check_write_path(path: &str) -> Option<(&'static str, String)> {
    // Block /tmp/* unless under /tmp/claude/*
    if path.starts_with("/tmp/") && !path.starts_with("/tmp/claude/") {
        return Some((
            "block",
            format!("Use /tmp/claude/ instead of /tmp/ for: {}", path),
        ));
    }
    // Allow everything else (pass through to Claude Code's normal handling)
    None
}

/// Output a hook decision
fn output_decision(decision: &str, reason: &str) {
    let output = HookOutput {
        hook_output: HookSpecificOutput {
            event_name: "PreToolUse".to_string(),
            decision: decision.to_string(),
            reason: reason.to_string(),
        },
    };

    if let Ok(json) = serde_json::to_string(&output) {
        println!("{}", json);
    }
}

fn main() {
    // Initialize journald logging (fails gracefully on non-systemd systems)
    if let Ok(logger) = systemd_journal_logger::JournalLog::new() {
        let _ = logger
            .with_syslog_identifier("claude-bash-hook".to_string())
            .install();
    }
    log::set_max_level(log::LevelFilter::Info);
    // Read input from stdin
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Failed to read stdin: {}", e);
        std::process::exit(1);
    }

    // Parse hook input
    let hook_input: HookInput = match serde_json::from_str(&input) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("Failed to parse input: {}", e);
            std::process::exit(1);
        }
    };

    // Handle Write tool - block /tmp/* unless under /tmp/claude/*
    if hook_input.tool_name == "Write" {
        if let Some(ref path) = hook_input.tool_input.file_path {
            if let Some(result) = check_write_path(path) {
                output_decision(&result.0, &result.1);
            }
        }
        return;
    }

    // Handle regex-replace MCP tool
    if hook_input.tool_name == "mcp__regex-replace__regex_replace" {
        let edit_mode = edits_allowed(hook_input.permission_mode.as_deref());
        let is_subagent = hook_input
            .transcript_path
            .as_deref()
            .is_some_and(|p| p.contains("/subagents/"));
        let is_dry_run = hook_input.tool_input.dry_run.unwrap_or(false);

        if edit_mode || is_dry_run || is_subagent {
            let reason = if is_dry_run {
                "regex replace (dry run)"
            } else if is_subagent {
                "regex replace (subagent)"
            } else {
                "regex replace (edit mode)"
            };
            output_decision("allow", reason);
        } else {
            output_decision("ask", "regex replace modifies files (not in edit mode)");
        }
        return;
    }

    // Handle Bash or Nushell MCP tool
    let is_bash = hook_input.tool_name == "Bash";
    let is_nushell = hook_input.tool_name == "mcp__nushell__execute";

    if !is_bash && !is_nushell {
        // Pass through - don't output anything for other tools
        return;
    }

    let command = match hook_input.tool_input.command {
        Some(cmd) => cmd,
        None => {
            // No command - pass through
            return;
        }
    };

    // Load config
    let config = Config::load_or_default();
    let ctx = ExecContext {
        edit_mode: edits_allowed(hook_input.permission_mode.as_deref()),
        is_subagent: hook_input
            .transcript_path
            .as_deref()
            .is_some_and(|p| p.contains("/subagents/")),
    };

    // Analyze the command (bash or nushell)
    let result = if is_nushell {
        analyze_nushell_command(&command, &config, ctx, hook_input.tool_input.cwd.as_deref())
    } else {
        analyze_command(&command, &config, ctx, hook_input.cwd.as_deref())
    };

    // For "passthrough" permission on Bash, let Claude Code's built-in system handle it
    // For nushell MCP, there's no built-in permission system, so ask explicitly
    let result = if result.permission == Permission::Passthrough {
        if is_nushell {
            PermissionResult {
                permission: Permission::Ask,
                reason: result.reason,
                suggestion: result.suggestion,
            }
        } else {
            // Bash: let Claude Code handle it
            info!(
                "decision=passthrough cwd={:?} command={:?} reason={:?}",
                hook_input.cwd, command, result.reason
            );
            return;
        }
    } else {
        result
    };

    // Log the decision
    let decision_str = match result.permission {
        Permission::Allow => "allow",
        Permission::Passthrough => "passthrough",
        Permission::Ask => "ask",
        Permission::Deny => "deny",
    };
    info!(
        "decision={} cwd={:?} command={:?} reason={:?}",
        decision_str, hook_input.cwd, command, result.reason
    );

    // Build reason, optionally with AI advice
    let reason = if config.enable_advice
        && matches!(result.permission, Permission::Ask | Permission::Deny)
    {
        let base_reason = output::format_reason(&command, &result);
        if let Some(advice) = advice::get_advice(&command, &result.reason, &result.permission) {
            format!("{}\n{}", base_reason, advice)
        } else {
            base_reason
        }
    } else {
        output::format_reason(&command, &result)
    };

    // Output the decision for allow/ask/deny
    let output = HookOutput {
        hook_output: HookSpecificOutput {
            event_name: "PreToolUse".to_string(),
            decision: match result.permission {
                Permission::Allow => "allow".to_string(),
                Permission::Passthrough => unreachable!(),
                Permission::Ask => "ask".to_string(),
                Permission::Deny => "deny".to_string(),
            },
            reason,
        },
    };

    match serde_json::to_string(&output) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize output: {}", e),
    }
}

/// Analyze a command and return the most restrictive permission
pub(crate) fn analyze_command(
    command: &str,
    config: &Config,
    ctx: ExecContext,
    initial_cwd: Option<&str>,
) -> PermissionResult {
    analyze_command_with_piped_query(command, config, ctx, initial_cwd, None, false)
}

/// Analyze a bash command with optional piped query context
fn analyze_command_with_piped_query(
    command: &str,
    config: &Config,
    ctx: ExecContext,
    initial_cwd: Option<&str>,
    outer_piped_query: Option<&str>,
    is_remote: bool,
) -> PermissionResult {
    let analysis = analyzer::analyze(command);

    if !analysis.success {
        return PermissionResult {
            permission: Permission::Deny,
            reason: format!("Bash syntax error: {}", analysis.error.unwrap_or_default()),
            suggestion: Some("Fix the syntax error and try again".to_string()),
        };
    }

    if analysis.commands.is_empty() {
        return PermissionResult {
            permission: Permission::Allow,
            reason: "No commands found".to_string(),
            suggestion: None,
        };
    }

    // Track virtual cwd through command chain (for cd /tmp/claude && tar -xf ...)
    // Only trust virtual_cwd if control flow is predictable (no conditionals)
    let has_uncertain_flow = command.contains(" || ")
        || command.contains("if ")
        || command.contains("case ")
        || command.contains("while ")
        || command.contains("for ")
        || command.contains("until ");

    let mut virtual_cwd: Option<String> = initial_cwd.map(String::from);

    // Check each command and return the most restrictive result
    let mut most_restrictive: Option<PermissionResult> = None;
    let mut prev_cmd: Option<&analyzer::Command> = None;

    for cmd in &analysis.commands {
        // Check for piped query: echo 'SQL' | mysql (or any command that might wrap mysql)
        // Use local piped query if detected, otherwise use outer piped query
        let local_piped_query = extract_piped_query(prev_cmd);
        let piped_query = local_piped_query.as_deref().or(outer_piped_query);

        let result = check_single_command(
            cmd,
            config,
            ctx,
            virtual_cwd.as_deref(),
            initial_cwd,
            has_uncertain_flow,
            piped_query,
            Some(command),
            is_remote,
        );

        most_restrictive = Some(match most_restrictive {
            None => result,
            Some(prev) if result.permission > prev.permission => result,
            Some(prev) => prev,
        });

        // Track cd commands to update virtual cwd for subsequent commands
        // (only if flow is predictable)
        if !has_uncertain_flow && cmd.name == "cd" {
            if let Some(dir) = cmd.args.first() {
                virtual_cwd = Some(dir.clone());
            }
        }

        prev_cmd = Some(cmd);
    }

    most_restrictive.unwrap_or_else(|| PermissionResult {
        permission: Permission::Allow,
        reason: String::new(),
        suggestion: None,
    })
}

/// Analyze a nushell command and return the most restrictive permission
fn analyze_nushell_command(
    command: &str,
    config: &Config,
    ctx: ExecContext,
    cwd: Option<&str>,
) -> PermissionResult {
    let analysis = nushell::analyze(command);

    if !analysis.success {
        return PermissionResult {
            permission: Permission::Deny,
            reason: format!(
                "Nushell syntax error: {}",
                analysis.error.unwrap_or_default()
            ),
            suggestion: Some("Fix the syntax error and try again".to_string()),
        };
    }

    // If no external commands, allow (nushell builtins are safe)
    if analysis.commands.is_empty() {
        return PermissionResult {
            permission: Permission::Allow,
            reason: "Nushell builtins only".to_string(),
            suggestion: None,
        };
    }

    // Check each external command against the same rules as bash
    let mut most_restrictive: Option<PermissionResult> = None;

    for cmd in &analysis.commands {
        // For nushell, cwd is both virtual and initial (no cd tracking)
        // No piped query support for nushell (different piping semantics)
        let result = check_single_command(cmd, config, ctx, cwd, cwd, false, None, None, false);

        most_restrictive = Some(match most_restrictive {
            None => result,
            Some(prev) if result.permission > prev.permission => result,
            Some(prev) => prev,
        });
    }

    most_restrictive.unwrap_or_else(|| PermissionResult {
        permission: Permission::Allow,
        reason: String::new(),
        suggestion: None,
    })
}

/// Extract a SQL query from a piped echo command
/// Returns Some(query) if prev_cmd is `echo 'SQL'`
/// The query is extracted regardless of the current command type,
/// so it can propagate through wrappers (ssh, docker exec, etc.)
fn extract_piped_query(prev_cmd: Option<&analyzer::Command>) -> Option<String> {
    // Check if previous command is echo
    let prev = prev_cmd?;
    if prev.name != "echo" && prev.name != "printf" {
        return None;
    }

    // Extract the query from echo arguments
    // Join all args (echo may have multiple args)
    if prev.args.is_empty() {
        return None;
    }

    Some(prev.args.join(" "))
}

/// Check a single command, handling wrappers recursively
fn check_single_command(
    cmd: &analyzer::Command,
    config: &Config,
    ctx: ExecContext,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    has_uncertain_flow: bool,
    piped_query: Option<&str>,
    full_command: Option<&str>,
    is_remote: bool,
) -> PermissionResult {
    // Special handling for docker compose - check BEFORE wrapper unwrapping
    if cmd.name == "docker" && cmd.args.first().map(|s| s.as_str()) == Some("compose") {
        // exec: allow locally, fall through to wrapper analysis for remote
        if let Some(result) = docker::check_docker_compose_exec(cmd, is_remote) {
            return result;
        }
        // run: allow based on bind mounts
        if let Some(result) = docker::check_docker_compose_run(cmd) {
            return result;
        }
    }

    // Check if this is a wrapper command
    if let Some(unwrap_result) = wrappers::unwrap_command(cmd, config) {
        // If there's an inner command, recursively analyze it
        // For nu -c, use nushell parser; for other wrappers, use bash parser
        if let Some(ref inner) = unwrap_result.inner_command {
            // Mark as remote if this wrapper has a host (SSH, scp, rsync)
            let inner_is_remote = is_remote || unwrap_result.host.is_some();

            let inner_result = if unwrap_result.wrapper == "nu" {
                // Use nushell parser for nu -c commands
                analyze_nushell_command(inner, config, ctx, virtual_cwd)
            } else {
                // Use bash parser for other wrappers
                // Pass piped_query so it can reach nested mysql commands
                analyze_command_with_piped_query(
                    inner,
                    config,
                    ctx,
                    virtual_cwd,
                    piped_query,
                    inner_is_remote,
                )
            };

            // For SSH with host, check host rules too
            if unwrap_result.host.is_some() {
                let host_result = config.check_command_with_host(
                    &cmd.name,
                    &cmd.args,
                    unwrap_result.host.as_deref(),
                    ctx,
                );

                // Return the more restrictive of host check and inner command check
                if host_result.permission > inner_result.permission {
                    return host_result;
                }
            }

            return inner_result;
        } else if unwrap_result.host.is_some() {
            // Wrapper with host but no inner command (like scp)
            return config.check_command_with_host(
                &cmd.name,
                &cmd.args,
                unwrap_result.host.as_deref(),
                ctx,
            );
        }
    }

    // Deny in-place file modification by text replacement tools
    // Inline/pipeline usage (sed 's/foo/bar/', awk '{print $1}') is allowed
    if cmd.name == "sed" && cmd.args.iter().any(|a| a == "-i" || a.starts_with("-i")) {
        return PermissionResult {
            permission: Permission::Deny,
            reason: "sed -i modifies files; use Edit tool or mcp__regex-replace__regex_replace"
                .to_string(),
            suggestion: None,
        };
    }
    // perl -i, -pi, -pie all indicate in-place editing (any short flag group containing 'i')
    if cmd.name == "perl"
        && cmd
            .args
            .iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('i'))
    {
        return PermissionResult {
            permission: Permission::Deny,
            reason: "perl -i modifies files; use Edit tool or mcp__regex-replace__regex_replace"
                .to_string(),
            suggestion: None,
        };
    }

    // Check cwd-based rules - if explicitly allowed, skip special analyzers
    // This allows project-specific overrides (e.g., allow php for xenforo project)
    // IMPORTANT: Skip cwd-based allows for remote commands (SSH, etc.) to prevent
    // local cwd from allowing dangerous remote operations
    if !is_remote {
        // Try virtual_cwd first, then initial_cwd
        let cwd_result = config.check_command_with_cwd(&cmd.name, &cmd.args, virtual_cwd, ctx);
        if cwd_result.permission == Permission::Allow {
            return cwd_result;
        }
        if initial_cwd != virtual_cwd {
            let cwd_result = config.check_command_with_cwd(&cmd.name, &cmd.args, initial_cwd, ctx);
            if cwd_result.permission == Permission::Allow {
                return cwd_result;
            }
        }
    }

    // Special handling for mysql/mariadb - allow read-only queries
    if config.is_mysql_alias(&cmd.name) {
        // First check -e flag query
        if let Some(result) = sql::check_mysql_query(cmd) {
            return result;
        }
        // Then check piped query (from echo 'SQL' | mysql)
        if let Some(query) = piped_query {
            return sql::check_piped_query(query);
        }
    }

    // Special handling for sqlite3 - allow read-only queries
    if cmd.name == "sqlite3" {
        // First check positional query argument
        if let Some(result) = sql::check_sqlite3_query(cmd) {
            return result;
        }
        // Then check piped query (from echo 'SQL' | sqlite3 db.sqlite)
        if let Some(query) = piped_query {
            return sql::check_piped_query(query);
        }
    }

    // Special handling for clickhouse-client - allow read-only queries
    if cmd.name == "clickhouse-client" {
        // First check -q flag query
        if let Some(result) = sql::check_clickhouse_query(cmd) {
            return result;
        }
        // Then check piped query (from echo 'SQL' | clickhouse-client)
        if let Some(query) = piped_query {
            return sql::check_piped_query(query);
        }
    }

    // Special handling for redis-cli/valkey-cli - allow read-only commands
    if cmd.name == "redis-cli" || cmd.name == "valkey-cli" {
        if let Some(result) = redis::check_redis_cli(cmd) {
            return result;
        }
    }

    // Special handling for php -r - allow read-only scripts
    if cmd.name == "php" {
        if let Some(result) = scripts::php::check_php_script(cmd) {
            return result;
        }
    }

    // Special handling for lua -e - allow read-only scripts
    if cmd.name == "lua" || cmd.name == "luajit" {
        if let Some(result) = scripts::lua::check_lua_script(cmd) {
            return result;
        }
    }

    // Special handling for python -c or heredoc - allow read-only scripts
    // or scripts that only write to project dir / /tmp
    if cmd.name.starts_with("python") {
        if let Some(result) = scripts::python::check_python_script(cmd, full_command, initial_cwd) {
            return result;
        }
        // python3 script.py - check if the script path itself is allowed
        if let Some(result) =
            scripts::check_interpreter_script(cmd, config, virtual_cwd, initial_cwd, ctx)
        {
            return result;
        }
    }

    // Special handling for git push - check target branch
    if cmd.name == "git" && cmd.args.first().map(|s| s.as_str()) == Some("push") {
        if let Some(result) = git::check_git_push(cmd, config, initial_cwd) {
            return result;
        }
    }

    // Special handling for git checkout - allow -b, ask for others
    if cmd.name == "git" && cmd.args.first().map(|s| s.as_str()) == Some("checkout") {
        if let Some(result) = git::check_git_checkout(cmd) {
            return result;
        }
    }

    // Special handling for git reset - allow unless --hard
    if cmd.name == "git" && cmd.args.first().map(|s| s.as_str()) == Some("reset") {
        if let Some(result) = git::check_git_reset(cmd) {
            return result;
        }
    }

    // Special handling for docker run - allow if no rw bind mounts
    if cmd.name == "docker" && cmd.args.first().map(|s| s.as_str()) == Some("run") {
        if let Some(result) = docker::check_docker_run(cmd) {
            return result;
        }
    }

    // Special handling for rm - allow deletion under /tmp/ or project dir
    if cmd.name == "rm" {
        if let Some(result) = rm::check_rm(cmd, virtual_cwd, initial_cwd) {
            return result;
        }
    }

    // Special handling for kill - block dangerous PIDs (1, -1)
    if cmd.name == "kill" {
        if let Some(result) = kill::check_kill(cmd) {
            return result;
        }
    }

    // Special handling for tee - allow writing to /tmp/ or /tmp/claude/ based on project
    if cmd.name == "tee" {
        if let Some(result) = tee::check_tee(cmd, initial_cwd) {
            return result;
        }
    }

    // Special handling for tar - allow extraction to /tmp/claude/
    if cmd.name == "tar" {
        if let Some(result) = tar::check_tar(cmd, virtual_cwd, has_uncertain_flow) {
            return result;
        }
    }

    // Special handling for magick - allow if output is info: (stdout only)
    if cmd.name == "magick" && cmd.args.last().is_some_and(|a| a == "info:") {
        return PermissionResult {
            permission: Permission::Allow,
            reason: "magick with info: output".to_string(),
            suggestion: None,
        };
    }

    // Special handling for curl - allow localhost, check host rules for others
    if cmd.name == "curl" {
        if let Some(result) = curl::check_curl(cmd, config, ctx) {
            return result;
        }
    }

    // Special handling for --help and --version - always allow
    if cmd
        .args
        .iter()
        .any(|a| a == "--help" || a == "-h" || a == "help")
    {
        return PermissionResult {
            permission: Permission::Allow,
            reason: "help request".to_string(),
            suggestion: None,
        };
    }
    if cmd
        .args
        .iter()
        .any(|a| a == "--version" || a == "-V" || a == "version")
    {
        return PermissionResult {
            permission: Permission::Allow,
            reason: "version check".to_string(),
            suggestion: None,
        };
    }

    // Allow scripts under /tmp/ (e.g., bash /tmp/claude/run-qemu.sh)
    if cmd.name.starts_with("/tmp/") {
        return PermissionResult {
            permission: Permission::Allow,
            reason: "script in /tmp".to_string(),
            suggestion: None,
        };
    }

    // Allow cargo target binaries when under the project cwd
    if let Some(result) = cargo::check_target_binary(cmd, virtual_cwd, initial_cwd) {
        return result;
    }

    // Regular command - check against rules
    // Try virtual_cwd first (from cd commands), then fall back to initial_cwd
    // This allows "cd /project && ./script" to match cwd-restricted rules
    if virtual_cwd.is_some() && virtual_cwd != initial_cwd {
        let result = config.check_command_with_cwd(&cmd.name, &cmd.args, virtual_cwd, ctx);
        // If virtual_cwd matched an allow rule, use it
        if result.permission == Permission::Allow {
            return result;
        }
    }

    // Fall back to initial_cwd
    config.check_command_with_cwd(&cmd.name, &cmd.args, initial_cwd, ctx)
}

#[cfg(test)]
mod tests;
