//! Claude Code Bash Permission Hook
//!
//! A PreToolUse hook that analyzes bash and nushell commands and provides granular permission control.

mod advice;
mod analyzer;
mod config;
mod docker;
mod git;
mod nushell;
mod rm;
mod sql;
mod tar;
mod tee;
mod wrappers;

use config::{Config, Permission, PermissionResult};
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
}

#[derive(Debug, Deserialize)]
struct ToolInput {
    command: Option<String>,
    cwd: Option<String>,
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

fn main() {
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
    let edit_mode = edits_allowed(hook_input.permission_mode.as_deref());

    // Analyze the command (bash or nushell)
    let result = if is_nushell {
        analyze_nushell_command(
            &command,
            &config,
            edit_mode,
            hook_input.tool_input.cwd.as_deref(),
        )
    } else {
        analyze_command(
            &command,
            &config,
            edit_mode,
            hook_input.tool_input.cwd.as_deref(),
        )
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
            return;
        }
    } else {
        result
    };

    // Build reason, optionally with AI advice
    let reason = if config.enable_advice
        && matches!(result.permission, Permission::Ask | Permission::Deny)
    {
        let base_reason = format_reason(&command, &result);
        if let Some(advice) = advice::get_advice(&command, &result.reason, &result.permission) {
            format!("{}\n{}", base_reason, advice)
        } else {
            base_reason
        }
    } else {
        format_reason(&command, &result)
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
fn analyze_command(
    command: &str,
    config: &Config,
    edit_mode: bool,
    initial_cwd: Option<&str>,
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
    let mut most_restrictive = PermissionResult::default();
    most_restrictive.permission = Permission::Allow;

    for cmd in &analysis.commands {
        let result = check_single_command(
            cmd,
            config,
            edit_mode,
            virtual_cwd.as_deref(),
            initial_cwd,
            has_uncertain_flow,
        );

        if result.permission > most_restrictive.permission {
            most_restrictive = result;
        }

        // Track cd commands to update virtual cwd for subsequent commands
        // (only if flow is predictable)
        if !has_uncertain_flow && cmd.name == "cd" {
            if let Some(dir) = cmd.args.first() {
                virtual_cwd = Some(dir.clone());
            }
        }
    }

    most_restrictive
}

/// Analyze a nushell command and return the most restrictive permission
fn analyze_nushell_command(
    command: &str,
    config: &Config,
    edit_mode: bool,
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
    let mut most_restrictive = PermissionResult::default();
    most_restrictive.permission = Permission::Allow;

    for cmd in &analysis.commands {
        // For nushell, cwd is both virtual and initial (no cd tracking)
        let result = check_single_command(cmd, config, edit_mode, cwd, cwd, false);

        if result.permission > most_restrictive.permission {
            most_restrictive = result;
        }
    }

    most_restrictive
}

/// Check a single command, handling wrappers recursively
fn check_single_command(
    cmd: &analyzer::Command,
    config: &Config,
    edit_mode: bool,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    has_uncertain_flow: bool,
) -> PermissionResult {
    // Check if this is a wrapper command
    if let Some(unwrap_result) = wrappers::unwrap_command(cmd, config) {
        // If there's an inner command, recursively analyze it
        if let Some(ref inner) = unwrap_result.inner_command {
            let inner_result = analyze_command(inner, config, edit_mode, virtual_cwd);

            // For SSH with host, check host rules too
            if unwrap_result.host.is_some() {
                let host_result = config.check_command_with_host(
                    &cmd.name,
                    &cmd.args,
                    unwrap_result.host.as_deref(),
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
            );
        }
    }

    // Special handling for sed -i (in-place edit)
    if cmd.name == "sed" && cmd.args.iter().any(|a| a == "-i" || a.starts_with("-i")) {
        if !edit_mode {
            return PermissionResult {
                permission: Permission::Ask,
                reason: "sed -i modifies files (not in edit mode)".to_string(),
                suggestion: None,
            };
        }
    }

    // Special handling for mysql/mariadb - allow read-only queries
    if matches!(
        cmd.name.as_str(),
        "mysql"
            | "mariadb"
            | "mysql-prod"
            | "mysql-prod-root"
            | "mysql-external"
            | "mysql-replication"
    ) {
        if let Some(result) = sql::check_mysql_query(cmd) {
            return result;
        }
    }

    // Special handling for sqlite3 - allow read-only queries
    if cmd.name == "sqlite3" {
        if let Some(result) = sql::check_sqlite3_query(cmd) {
            return result;
        }
    }

    // Special handling for git push - check target branch
    if cmd.name == "git" && cmd.args.first().map(|s| s.as_str()) == Some("push") {
        if let Some(result) = git::check_git_push(cmd) {
            return result;
        }
    }

    // Special handling for git checkout - allow -b, ask for others
    if cmd.name == "git" && cmd.args.first().map(|s| s.as_str()) == Some("checkout") {
        if let Some(result) = git::check_git_checkout(cmd) {
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
        if let Some(result) = rm::check_rm(cmd, initial_cwd) {
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

    // Regular command - check against rules
    config.check_command_with_cwd(&cmd.name, &cmd.args, virtual_cwd)
}

/// Format the reason string
fn format_reason(command: &str, result: &PermissionResult) -> String {
    let mut reason = if result.reason.is_empty() {
        command.to_string()
    } else {
        format!("{}: {}", shorten_command(command), result.reason)
    };

    if let Some(ref suggestion) = result.suggestion {
        reason = format!("{}\n{}", reason, suggestion);
    }

    reason
}

/// Shorten a long command for display
fn shorten_command(command: &str) -> &str {
    if command.len() > 60 {
        &command[..60]
    } else {
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn test_config() -> Config {
        Config::load(Path::new("config.default.toml")).expect("Failed to load test config")
    }

    #[test]
    fn test_simple_allow() {
        let config = test_config();
        let result = analyze_command("ls -la", &config, false, None);
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_pipeline() {
        let config = test_config();
        let result = analyze_command("ls | grep foo", &config, false, None);
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_dangerous_command() {
        let config = test_config();
        let result = analyze_command("rm -rf /", &config, false, None);
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_sudo_wrapper() {
        let config = test_config();
        let result = analyze_command("sudo ls", &config, false, None);
        // sudo unwraps to ls, which is allowed
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sudo_dangerous() {
        let config = test_config();
        let result = analyze_command("sudo rm -rf /", &config, false, None);
        // sudo unwraps to rm -rf /, which passes through
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_chain_with_dangerous() {
        let config = test_config();
        let result = analyze_command("ls && rm -rf /tmp", &config, false, None);
        // Most restrictive should be passthrough
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_env_dangerous() {
        let config = test_config();
        let result = analyze_command("env VAR=1 rm -rf /", &config, false, None);
        // env unwraps to rm -rf /, which passes through
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_var_assignment_safe() {
        let config = test_config();
        let result = analyze_command("VAR=1 ls -la", &config, false, None);
        // ls is allowed even with env var
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_git_suggestion() {
        let config = test_config();
        let result = analyze_command("git checkout main", &config, false, None);
        // Should have a suggestion
        assert!(result.suggestion.is_some());
    }

    #[test]
    fn test_kubectl_exec_safe() {
        let config = test_config();
        let result = analyze_command("kubectl exec mypod -- ls -la", &config, false, None);
        // kubectl exec unwraps to ls -la, which is allowed
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_kubectl_exec_dangerous() {
        let config = test_config();
        let result = analyze_command("kubectl exec -n prod mypod -- rm -rf /", &config, false, None);
        // kubectl exec unwraps to rm -rf /, which passes through
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_kubectl_get_allowed() {
        let config = test_config();
        let result = analyze_command("kubectl get pods", &config, false, None);
        // kubectl get is allowed (not a wrapper, falls through to default)
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sed_allowed() {
        let config = test_config();
        let result = analyze_command("echo test | sed 's/t/x/'", &config, false, None);
        // sed without -i is allowed
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sed_i_asks_without_edit_mode() {
        let config = test_config();
        let result = analyze_command("sed -i 's/foo/bar/' file.txt", &config, false, None);
        // sed -i explicitly asks when not in edit mode (safety feature)
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_sed_i_allowed_with_edit_mode() {
        let config = test_config();
        let result = analyze_command("sed -i 's/foo/bar/' file.txt", &config, true, None);
        // sed -i allowed when in edit mode
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_help_always_allowed() {
        let config = test_config();
        // --help flag
        let result = analyze_command("someunknown --help", &config, false, None);
        assert_eq!(result.permission, Permission::Allow);
        // -h flag
        let result = analyze_command("kubectl delete -h", &config, false, None);
        assert_eq!(result.permission, Permission::Allow);
        // help subcommand
        let result = analyze_command("cargo help build", &config, false, None);
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_version_always_allowed() {
        let config = test_config();
        // --version flag
        let result = analyze_command("someunknown --version", &config, false, None);
        assert_eq!(result.permission, Permission::Allow);
        // -V flag
        let result = analyze_command("rustc -V", &config, false, None);
        assert_eq!(result.permission, Permission::Allow);
        // version subcommand
        let result = analyze_command("docker version", &config, false, None);
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_cwd_propagates_through_wrapper() {
        // Create a config with a cwd-restricted rule and sudo wrapper
        let config_str = r#"
            default = "passthrough"
            [[rules]]
            commands = ["cd"]
            permission = "allow"
            reason = "cd is safe"

            [[rules]]
            commands = ["./target/release/myapp"]
            permission = "allow"
            reason = "project binary"
            cwd = "/home/test/myproject"

            [[wrappers]]
            command = "sudo"
            opts_with_args = ["-g", "-p", "-r", "-t", "-u", "-T", "-C", "-h", "-U"]
        "#;
        let config: Config = toml::from_str(config_str).unwrap();

        // Without cd, should passthrough (no cwd match)
        let result = analyze_command("sudo ./target/release/myapp", &config, false, None);
        assert_eq!(result.permission, Permission::Passthrough);

        // With cd before sudo, should allow (cwd propagates through wrapper)
        let result = analyze_command(
            "cd /home/test/myproject && sudo ./target/release/myapp",
            &config,
            false,
            None,
        );
        assert_eq!(result.permission, Permission::Allow);
    }
}
