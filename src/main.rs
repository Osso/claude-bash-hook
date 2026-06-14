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
mod host_advice;
mod kill;
mod magick;
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
#[cfg(test)]
mod test_support;
mod tool_handlers;
mod wrappers;

use config::{Config, ExecContext, Permission, PermissionResult};
use log::info;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

const CODEX_ENV_MARKERS: [&str; 2] = ["CODEX_THREAD_ID", "CODEX_CI"];

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
    /// Codex approval policy: "on-request", "never", "auto-approve", etc.
    #[serde(default)]
    approval_policy: Option<String>,
    /// Working directory where Claude Code session started
    #[serde(default)]
    cwd: Option<String>,
    /// Session identifier
    #[serde(default)]
    session_id: Option<String>,
    /// Codex extension: active turn id. Claude Code does not send this today.
    #[serde(default)]
    turn_id: Option<String>,
    /// Current tool-use id. Claude Code also sends this on PreToolUse.
    #[serde(default)]
    tool_use_id: Option<String>,
    /// Codex extension: runtime accepts `hookSpecificOutput.updatedInput`.
    #[serde(default)]
    supports_updated_input: bool,
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
        self.access_mode.as_deref().or(self
            .hook_event
            .as_ref()
            .and_then(|event| event.access_mode.as_deref()))
    }

    pub(crate) fn effective_permission_mode(&self) -> Option<&str> {
        match self.approval_policy.as_deref() {
            Some("auto-approve") | Some("bypass-permissions") => Some("bypassPermissions"),
            Some("never") | Some("no-prompts") => Some("default"),
            _ => self.permission_mode.as_deref(),
        }
    }

    /// Detect Codex from explicit mode fields and Codex-only hook payload fields.
    ///
    /// Older Codex builds omitted `access_mode`; relying only on that field
    /// made us emit Claude-shaped permission output that Codex rejected.
    pub(crate) fn is_codex(&self) -> bool {
        self.access_mode().is_some()
            || self.turn_id.is_some()
            || self.supports_updated_input
            || matches!(self.tool_name.as_str(), "exec_command" | "write_stdin")
    }

    pub(crate) fn is_explicit_claude_payload(&self) -> bool {
        let valid_tool_use_id = self.tool_use_id.as_deref().is_none_or(|id| !id.is_empty());
        self.hook_event_name.is_some()
            && self.permission_mode.is_some()
            && self.access_mode().is_none()
            && self.turn_id.is_none()
            && valid_tool_use_id
            && !self.supports_updated_input
            && matches!(self.tool_name.as_str(), "Bash" | "Write" | "Edit" | "Read")
    }
}

fn has_codex_env(vars: impl IntoIterator<Item = impl AsRef<str>>) -> bool {
    vars.into_iter()
        .any(|name| CODEX_ENV_MARKERS.contains(&name.as_ref()))
}

pub(crate) fn is_codex_runtime_with_env(
    hook_input: &HookInput,
    env_names: impl IntoIterator<Item = impl AsRef<str>>,
) -> bool {
    hook_input.is_codex() || (!hook_input.is_explicit_claude_payload() && has_codex_env(env_names))
}

pub(crate) fn is_codex_runtime(hook_input: &HookInput) -> bool {
    let env_names = std::env::vars_os().filter_map(|(name, _)| name.into_string().ok());
    is_codex_runtime_with_env(hook_input, env_names)
}

/// Check if edits are allowed based on permission mode
fn edits_allowed(mode: Option<&str>) -> bool {
    matches!(mode, Some("acceptEdits") | Some("bypassPermissions"))
}

/// Check if the session is in bypassPermissions ("yolo") mode
fn bypass_mode(mode: Option<&str>) -> bool {
    mode == Some("bypassPermissions")
}

pub(crate) fn apply_access_mode_permission(
    permission: Permission,
    access_mode: Option<&str>,
) -> Permission {
    match permission {
        Permission::Deny => Permission::Deny,
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

/// Codex parses legacy `decision:block` and Claude-shaped
/// `hookSpecificOutput.permissionDecision:ask`. Emit `allow` for Codex too so
/// approved commands auto-pass instead of falling back to a separate approval
/// path.
#[derive(Debug, Serialize)]
struct CodexHookOutput {
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// Check if a Write tool path should be blocked
pub(crate) fn check_write_path(path: &str) -> Option<(&'static str, String)> {
    let _ = path;
    None
}

fn build_hook_output(
    decision: &str,
    reason: &str,
    updated_input: Option<serde_json::Value>,
) -> HookOutput {
    HookOutput {
        hook_output: HookSpecificOutput {
            event_name: "PreToolUse".to_string(),
            decision: decision.to_string(),
            reason: reason.to_string(),
            updated_input,
        },
    }
}

fn serialize_hook_output(
    decision: &str,
    reason: &str,
    updated_input: Option<serde_json::Value>,
) -> Option<String> {
    serde_json::to_string(&build_hook_output(decision, reason, updated_input)).ok()
}

/// Build the codex-shaped output. Codex honors `permissionDecision: allow` to
/// auto-approve (skipping its own approval flow), `ask` to force a prompt, and
/// legacy `block` to deny. `passthrough` and unknown decisions emit nothing so
/// Codex falls back to its own policy.
fn build_codex_hook_output(
    decision: &str,
    reason: &str,
    updated_input: Option<serde_json::Value>,
    supports_updated_input: bool,
) -> Option<serde_json::Value> {
    match decision {
        "deny" => {
            let trimmed = reason.trim();
            let reason = if trimmed.is_empty() {
                "claude-bash-hook denied without a reason".to_string()
            } else {
                reason.to_string()
            };
            serde_json::to_value(CodexHookOutput {
                decision: "block".to_string(),
                reason: Some(reason),
            })
            .ok()
        }
        "ask" => serde_json::to_value(build_hook_output("ask", reason, updated_input)).ok(),
        "allow" => {
            // Emit a positive allow so Codex skips its own approval prompt.
            // Attach the command rewrite only when the runtime advertises
            // updatedInput support; otherwise send a bare allow.
            let rewrite = updated_input.filter(|_| supports_updated_input);
            serde_json::to_value(build_hook_output("allow", reason, rewrite)).ok()
        }
        _ => None,
    }
}

fn serialize_codex_hook_output(
    decision: &str,
    reason: &str,
    updated_input: Option<serde_json::Value>,
    supports_updated_input: bool,
) -> Option<String> {
    serde_json::to_string(&build_codex_hook_output(
        decision,
        reason,
        updated_input,
        supports_updated_input,
    )?)
    .ok()
}

/// Output a hook decision, optionally with a rewritten command. Codex accepts
/// allow (auto-approve), ask (+ optional rewrite), and legacy block (deny);
/// rewrites are attached only when the runtime advertises updatedInput support.
fn output_decision(
    decision: &str,
    reason: &str,
    updated_input: Option<serde_json::Value>,
    is_codex: bool,
    supports_updated_input: bool,
) {
    if is_codex {
        if let Some(json) =
            serialize_codex_hook_output(decision, reason, updated_input, supports_updated_input)
        {
            println!("{}", json);
        }
        return;
    }
    if let Some(json) = serialize_hook_output(decision, reason, updated_input) {
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
    match parse_hook_input(&input) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("Failed to parse input: {}", e);
            std::process::exit(1);
        }
    }
}

fn parse_hook_input(input: &str) -> Result<HookInput, String> {
    serde_json::from_str(input).map_err(|e| e.to_string())
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

fn emit_decision(
    command: &str,
    result: &PermissionResult,
    config: &Config,
    alias_command: Option<&str>,
    is_codex: bool,
    supports_updated_input: bool,
) {
    let reason = output::format_reason(command, result);
    let rewrite_input = rewrite::maybe_rewrite(command, result, config);
    let updated_input = match (alias_command, rewrite_input) {
        (_, Some(rw)) => Some(rw), // rewrite already uses the aliased command string
        (Some(aliased), None) => Some(serde_json::json!({ "command": aliased })),
        (None, None) => None,
    };
    let decision = match result.permission {
        Permission::Allow => "allow",
        Permission::Ask => "ask",
        Permission::Deny => "deny",
        Permission::Passthrough => unreachable!(),
    };
    output_decision(
        decision,
        &reason,
        updated_input,
        is_codex,
        supports_updated_input,
    );
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
        edit_mode: edits_allowed(hook_input.effective_permission_mode()),
        is_subagent: hook_input
            .session_id
            .as_deref()
            .is_some_and(|sid| subagent_tracker::has_active_subagents(sid)),
        bypass: bypass_mode(hook_input.effective_permission_mode()),
    };
    let access_mode = hook_input.access_mode().map(str::to_string);
    let result = if is_nushell {
        analysis::analyze_nushell_command(
            command,
            config,
            ctx,
            hook_input.tool_input.cwd.as_deref(),
        )
    } else {
        analysis::analyze_command(command, config, ctx, hook_input.cwd.as_deref())
    };
    let result = apply_access_mode_result(result, access_mode.as_deref());
    let resolved = resolve_passthrough(result, is_nushell);
    if resolved.is_none() && !is_nushell && config.passthrough_llm {
        return advice::classify_passthrough(command, hook_input.cwd.as_deref());
    }
    resolved
}

fn session_has_subagents(session_id: Option<&str>) -> bool {
    session_id.is_some_and(subagent_tracker::has_active_subagents)
}

fn is_nushell_tool(tool_name: &str) -> bool {
    tool_name == "mcp__nushell__execute"
}

fn is_shell_tool(tool_name: &str) -> bool {
    tool_name == "Bash" || is_nushell_tool(tool_name)
}

fn handle_passthrough_decision(hook_input: &HookInput, command: &str, alias_rewritten: bool) {
    info!(
        "decision=passthrough session={:?} command={:?}",
        hook_input.session_id, command
    );
    // If alias was applied, emit allow with updatedInput so the agent sees the rewritten command.
    if alias_rewritten {
        output_decision(
            "allow",
            "alias rewrite",
            Some(serde_json::json!({ "command": command })),
            is_codex_runtime(hook_input),
            hook_input.supports_updated_input,
        );
    }
}

fn emit_analyzed_decision(
    hook_input: &HookInput,
    command: &str,
    config: &Config,
    alias_rewritten: Option<&str>,
    result: &PermissionResult,
) {
    info!(
        "decision={} session={:?} command={:?} reason={:?}",
        permission_name(result.permission),
        hook_input.session_id,
        command,
        result.reason
    );
    emit_decision(
        command,
        result,
        config,
        alias_rewritten,
        is_codex_runtime(hook_input),
        hook_input.supports_updated_input,
    );
}

fn main() {
    init_logging();
    let hook_input = read_hook_input();
    if handle_subagent_event(&hook_input) {
        return;
    }
    let is_subagent = session_has_subagents(hook_input.session_id.as_deref());
    let config = Config::load_or_default();
    if tool_handlers::handle_non_bash_tool(&hook_input, &config, is_subagent) {
        return;
    }
    if !is_shell_tool(&hook_input.tool_name) {
        return;
    }
    let is_nushell = is_nushell_tool(&hook_input.tool_name);
    let Some(ref original_command) = hook_input.tool_input.command else {
        return;
    };

    // Apply command aliases before analysis
    let alias_rewritten = config.apply_aliases(original_command);
    let command = alias_rewritten.as_deref().unwrap_or(original_command);

    let Some(result) = analyze_and_resolve(&hook_input, &config, command, is_nushell) else {
        handle_passthrough_decision(&hook_input, command, alias_rewritten.is_some());
        return;
    };

    emit_analyzed_decision(
        &hook_input,
        command,
        &config,
        alias_rewritten.as_deref(),
        &result,
    );
}

#[cfg(test)]
mod access_mode_tests;
#[cfg(test)]
mod tests;
