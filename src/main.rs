//! Claude Code Bash Permission Hook
//!
//! A PreToolUse hook that analyzes bash commands and provides granular permission control.

mod analyzer;
mod config;
mod sql;
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

    // Only handle Bash tool
    if hook_input.tool_name != "Bash" {
        // Pass through - don't output anything for non-Bash tools
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

    // Analyze the command
    let result = analyze_command(&command, &config, edit_mode);

    // For "ask" permission, don't output anything - let Claude Code's built-in system handle it
    if result.permission == Permission::Ask {
        return;
    }

    // Output the decision for allow/deny
    let output = HookOutput {
        hook_output: HookSpecificOutput {
            event_name: "PreToolUse".to_string(),
            decision: match result.permission {
                Permission::Allow => "allow".to_string(),
                Permission::Ask => unreachable!(),
                Permission::Deny => "deny".to_string(),
            },
            reason: format_reason(&command, &result),
        },
    };

    match serde_json::to_string(&output) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize output: {}", e),
    }
}

/// Analyze a command and return the most restrictive permission
fn analyze_command(command: &str, config: &Config, edit_mode: bool) -> PermissionResult {
    let analysis = analyzer::analyze(command);

    if !analysis.success {
        return PermissionResult {
            permission: Permission::Ask,
            reason: analysis.error.unwrap_or_default(),
            suggestion: None,
        };
    }

    if analysis.commands.is_empty() {
        return PermissionResult {
            permission: Permission::Allow,
            reason: "No commands found".to_string(),
            suggestion: None,
        };
    }

    // Check each command and return the most restrictive result
    let mut most_restrictive = PermissionResult::default();
    most_restrictive.permission = Permission::Allow;

    for cmd in &analysis.commands {
        let result = check_single_command(cmd, config, edit_mode);

        if result.permission > most_restrictive.permission {
            most_restrictive = result;
        }
    }

    most_restrictive
}

/// Check a single command, handling wrappers recursively
fn check_single_command(cmd: &analyzer::Command, config: &Config, edit_mode: bool) -> PermissionResult {
    // Check if this is a wrapper command
    if let Some(unwrap_result) = wrappers::unwrap_command(cmd, config) {
        // If there's an inner command, recursively analyze it
        if let Some(ref inner) = unwrap_result.inner_command {
            let inner_result = analyze_command(inner, config, edit_mode);

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
    if cmd.name == "mysql" || cmd.name == "mariadb" {
        if let Some(result) = sql::check_sql_query(cmd) {
            return result;
        }
    }

    // Regular command - check against rules
    config.check_command(&cmd.name, &cmd.args)
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
        Config::load(Path::new("config.example.toml")).expect("Failed to load test config")
    }

    #[test]
    fn test_simple_allow() {
        let config = test_config();
        let result = analyze_command("ls -la", &config, false);
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_pipeline() {
        let config = test_config();
        let result = analyze_command("ls | grep foo", &config, false);
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_dangerous_command() {
        let config = test_config();
        let result = analyze_command("rm -rf /", &config, false);
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_sudo_wrapper() {
        let config = test_config();
        let result = analyze_command("sudo ls", &config, false);
        // sudo unwraps to ls, which is allowed
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sudo_dangerous() {
        let config = test_config();
        let result = analyze_command("sudo rm -rf /", &config, false);
        // sudo unwraps to rm -rf /, which asks
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_chain_with_dangerous() {
        let config = test_config();
        let result = analyze_command("ls && rm -rf /tmp", &config, false);
        // Most restrictive should be ask
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_env_dangerous() {
        let config = test_config();
        let result = analyze_command("env VAR=1 rm -rf /", &config, false);
        // env unwraps to rm -rf /, which asks
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_var_assignment_safe() {
        let config = test_config();
        let result = analyze_command("VAR=1 ls -la", &config, false);
        // ls is allowed even with env var
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_git_suggestion() {
        let config = test_config();
        let result = analyze_command("git checkout main", &config, false);
        // Should have a suggestion
        assert!(result.suggestion.is_some());
    }

    #[test]
    fn test_kubectl_exec_safe() {
        let config = test_config();
        let result = analyze_command("kubectl exec mypod -- ls -la", &config, false);
        // kubectl exec unwraps to ls -la, which is allowed
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_kubectl_exec_dangerous() {
        let config = test_config();
        let result = analyze_command("kubectl exec -n prod mypod -- rm -rf /", &config, false);
        // kubectl exec unwraps to rm -rf /, which asks
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_kubectl_get_allowed() {
        let config = test_config();
        let result = analyze_command("kubectl get pods", &config, false);
        // kubectl get is allowed (not a wrapper, falls through to default)
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sed_allowed() {
        let config = test_config();
        let result = analyze_command("echo test | sed 's/t/x/'", &config, false);
        // sed without -i is allowed
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sed_i_asks_without_edit_mode() {
        let config = test_config();
        let result = analyze_command("sed -i 's/foo/bar/' file.txt", &config, false);
        // sed -i asks when not in edit mode
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_sed_i_allowed_with_edit_mode() {
        let config = test_config();
        let result = analyze_command("sed -i 's/foo/bar/' file.txt", &config, true);
        // sed -i allowed when in edit mode
        assert_eq!(result.permission, Permission::Allow);
    }
}
