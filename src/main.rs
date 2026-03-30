//! Claude Code Bash Permission Hook
//!
//! A PreToolUse hook that analyzes bash and nushell commands and provides granular permission control.

mod advice;
mod analysis;
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
mod rewrite;
mod rm;
mod scripts;
mod sql;
mod subagent_tracker;
mod tar;
mod tee;
mod tool_handlers;
mod wrappers;

use config::{Config, ExecContext, Permission, PermissionResult};
use log::info;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

#[cfg(test)]
pub(crate) use analysis::analyze_command;

/// Input from Claude Code hook
#[derive(Debug, Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: ToolInput,
    /// Permission mode: "default", "plan", "acceptEdits", "bypassPermissions"
    #[serde(default)]
    permission_mode: Option<String>,
    /// Codex access mode: "full_access", "supervised", etc.
    #[serde(default)]
    access_mode: Option<String>,
    /// Working directory where Claude Code session started
    #[serde(default)]
    cwd: Option<String>,
    /// Session identifier
    #[serde(default)]
    session_id: Option<String>,
    /// Hook event name: "PreToolUse", "SubagentStart", "SubagentStop", etc.
    #[serde(default)]
    hook_event_name: Option<String>,
    /// Newer hook payloads can nest metadata under hook_event
    #[serde(default)]
    hook_event: Option<HookEvent>,
}

#[derive(Debug, Default, Deserialize)]
struct ToolInput {
    command: Option<String>,
    cwd: Option<String>,
    // For Write tool
    file_path: Option<String>,
    // For regex-replace MCP tool
    dry_run: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct HookEvent {
    access_mode: Option<String>,
}

impl HookInput {
    pub(crate) fn access_mode(&self) -> Option<&str> {
        self.access_mode
            .as_deref()
            .or(self.hook_event.as_ref().and_then(|event| event.access_mode.as_deref()))
    }
}

/// Check if edits are allowed based on permission mode
fn edits_allowed(mode: Option<&str>) -> bool {
    matches!(mode, Some("acceptEdits") | Some("bypassPermissions"))
}

pub(crate) fn apply_access_mode_permission(
    permission: Permission,
    access_mode: Option<&str>,
) -> Permission {
    match permission {
        Permission::Deny => Permission::Deny,
        Permission::Ask if matches!(access_mode, Some("full_access")) => Permission::Allow,
        Permission::Passthrough if matches!(access_mode, Some("full_access")) => Permission::Allow,
        Permission::Passthrough if matches!(access_mode, Some("supervised")) => Permission::Ask,
        _ => permission,
    }
}

pub(crate) fn apply_access_mode_result(
    mut result: PermissionResult,
    access_mode: Option<&str>,
) -> PermissionResult {
    let original_permission = result.permission;
    let updated_permission = apply_access_mode_permission(original_permission, access_mode);

    if updated_permission != original_permission
        && let Some(mode) = access_mode
    {
        let reason = access_mode_reason(mode, original_permission, updated_permission);
        if result.reason.is_empty() {
            result.reason = reason;
        } else {
            result.reason = format!("{}; {}", result.reason, reason);
        }
    }

    result.permission = updated_permission;
    result
}

fn access_mode_reason(access_mode: &str, from: Permission, to: Permission) -> String {
    format!(
        "access_mode={} upgraded {} to {}",
        access_mode,
        permission_name(from),
        permission_name(to)
    )
}

pub(crate) fn permission_name(permission: Permission) -> &'static str {
    match permission {
        Permission::Allow => "allow",
        Permission::Passthrough => "passthrough",
        Permission::Ask => "ask",
        Permission::Deny => "deny",
    }
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
    #[serde(rename = "updatedInput", skip_serializing_if = "Option::is_none")]
    updated_input: Option<serde_json::Value>,
}

/// Check if a Write tool path should be blocked
pub(crate) fn check_write_path(path: &str) -> Option<(&'static str, String)> {
    let _ = path;
    None
}

/// Output a hook decision, optionally with a rewritten command
fn output_decision(decision: &str, reason: &str, updated_input: Option<serde_json::Value>) {
    let output = HookOutput {
        hook_output: HookSpecificOutput {
            event_name: "PreToolUse".to_string(),
            decision: decision.to_string(),
            reason: reason.to_string(),
            updated_input,
        },
    };
    if let Ok(json) = serde_json::to_string(&output) {
        println!("{}", json);
    }
}

fn init_logging() {
    if let Ok(logger) = systemd_journal_logger::JournalLog::new() {
        let _ = logger
            .with_syslog_identifier("claude-bash-hook".to_string())
            .install();
    }
    log::set_max_level(log::LevelFilter::Info);
}

fn read_hook_input() -> HookInput {
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Failed to read stdin: {}", e);
        std::process::exit(1);
    }
    match serde_json::from_str(&input) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("Failed to parse input: {}", e);
            std::process::exit(1);
        }
    }
}

fn handle_subagent_event(hook_input: &HookInput) -> bool {
    let Some(ref event) = hook_input.hook_event_name else {
        return false;
    };
    let Some(ref session_id) = hook_input.session_id else {
        return false;
    };
    match event.as_str() {
        "SubagentStart" => {
            subagent_tracker::increment(session_id);
            info!("SubagentStart session={}", session_id);
            true
        }
        "SubagentStop" => {
            subagent_tracker::decrement(session_id);
            info!("SubagentStop session={}", session_id);
            true
        }
        _ => false,
    }
}

/// Resolve passthrough: nushell gets ask, bash returns None to signal early exit
fn resolve_passthrough(result: PermissionResult, is_nushell: bool) -> Option<PermissionResult> {
    if result.permission != Permission::Passthrough {
        return Some(result);
    }
    if is_nushell {
        Some(PermissionResult {
            permission: Permission::Ask,
            reason: result.reason,
            suggestion: result.suggestion,
        })
    } else {
        None // caller should return early (let Claude Code handle)
    }
}

fn build_reason(command: &str, result: &PermissionResult, config: &Config) -> String {
    if config.enable_advice && matches!(result.permission, Permission::Ask | Permission::Deny) {
        let base_reason = output::format_reason(command, result);
        if let Some(adv) = advice::get_advice(command, &result.reason, &result.permission) {
            return format!("{}\n{}", base_reason, adv);
        }
        base_reason
    } else {
        output::format_reason(command, result)
    }
}

fn emit_decision(command: &str, result: &PermissionResult, config: &Config) {
    let reason = build_reason(command, result, config);
    let updated_input = rewrite::maybe_rewrite(command, result, config);
    let decision = match result.permission {
        Permission::Allow => "allow",
        Permission::Ask => "ask",
        Permission::Deny => "deny",
        Permission::Passthrough => unreachable!(),
    };
    output_decision(decision, &reason, updated_input);
}

/// Analyze a bash/nushell command, apply access mode, resolve passthrough.
/// Returns None if passthrough (caller should exit silently).
fn analyze_and_resolve(
    hook_input: &HookInput,
    config: &Config,
    command: &str,
    is_nushell: bool,
) -> Option<PermissionResult> {
    let ctx = ExecContext {
        edit_mode: edits_allowed(hook_input.permission_mode.as_deref()),
        is_subagent: hook_input.session_id.as_deref()
            .is_some_and(|sid| subagent_tracker::has_active_subagents(sid)),
    };
    let access_mode = hook_input.access_mode().map(str::to_string);
    let result = if is_nushell {
        analysis::analyze_nushell_command(command, config, ctx, hook_input.tool_input.cwd.as_deref())
    } else {
        analysis::analyze_command(command, config, ctx, hook_input.cwd.as_deref())
    };
    let result = apply_access_mode_result(result, access_mode.as_deref());
    resolve_passthrough(result, is_nushell)
}

fn main() {
    init_logging();
    let hook_input = read_hook_input();

    if handle_subagent_event(&hook_input) {
        return;
    }

    let is_subagent = hook_input.session_id.as_deref()
        .is_some_and(|sid| subagent_tracker::has_active_subagents(sid));
    let config = Config::load_or_default();

    if tool_handlers::handle_non_bash_tool(&hook_input, &config, is_subagent) {
        return;
    }

    let is_nushell = hook_input.tool_name == "mcp__nushell__execute";
    if hook_input.tool_name != "Bash" && !is_nushell {
        return;
    }

    let Some(ref command) = hook_input.tool_input.command else {
        return;
    };

    let Some(result) = analyze_and_resolve(&hook_input, &config, command, is_nushell) else {
        info!("decision=passthrough session={:?} command={:?}", hook_input.session_id, command);
        return;
    };

    info!(
        "decision={} session={:?} command={:?} reason={:?}",
        permission_name(result.permission), hook_input.session_id, command, result.reason
    );
    emit_decision(command, &result, &config);
}

#[cfg(test)]
mod tests;
