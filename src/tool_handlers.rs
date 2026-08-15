//! Handlers for non-bash tools (Write, Edit, regex-replace)

use crate::config::{Config, ExecContext, Permission, PermissionResult};
use crate::scripts::{node, pyrun};
use crate::{
    Harness, HookInput, apply_access_mode_result, bypass_mode, check_write_path, edits_allowed,
    output_decision, permission_name,
};

/// Handle Write, Edit, Read, and regex-replace tools.
/// Returns true if the tool was handled (caller should return), false otherwise.
pub fn handle_non_bash_tool(
    hook_input: &HookInput,
    config: &Config,
    is_subagent: bool,
    harness: Harness,
) -> bool {
    if hook_input.tool_name == "Write" || hook_input.tool_name == "Edit" {
        handle_write_edit(hook_input, config, is_subagent, harness);
        return true;
    }
    if hook_input.tool_name == "Read" {
        return handle_read(hook_input, config, harness);
    }
    if is_regex_replace_tool(&hook_input.tool_name) {
        handle_regex_replace(hook_input, is_subagent, harness);
        return true;
    }
    if is_hostrun_tool(&hook_input.tool_name) {
        emit_hostrun_eval_decision(hook_input, config, is_subagent, harness);
        return true;
    }
    if is_pyrun_tool(&hook_input.tool_name) {
        emit_pyrun_eval_decision(hook_input, config, is_subagent, harness);
        return true;
    }
    false
}

fn is_regex_replace_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "mcp__regex-replace__regex_replace"
            | "mcp__regex_replace__regex_replace"
            | "regex-replace.regex_replace"
            | "regex_replace.regex_replace"
    )
}

fn is_hostrun_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "mcp__hostrun__hostrun_eval" | "hostrun.hostrun_eval" | "hostrun_eval"
    )
}

fn is_pyrun_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "mcp__pyrun__pyrun_eval" | "pyrun.pyrun_eval" | "pyrun_eval"
    )
}

fn handle_write_edit(hook_input: &HookInput, config: &Config, is_subagent: bool, harness: Harness) {
    let supports_updated_input = hook_input.supports_updated_input;
    if check_main_thread_block(hook_input, config, is_subagent, harness) {
        return;
    }
    if let Some(ref path) = hook_input.tool_input.file_path {
        if let Some(result) = check_write_path(path) {
            output_decision(&result.0, &result.1, None, harness, supports_updated_input);
            return;
        }
        if config.is_write_protected(path) {
            output_decision(
                "ask",
                &format!("{} to protected path {}", hook_input.tool_name, path),
                None,
                harness,
                supports_updated_input,
            );
            return;
        }
        if config.is_write_allowed(path) {
            output_decision(
                "allow",
                &format!("{} to allowed path {}", hook_input.tool_name, path),
                None,
                harness,
                supports_updated_input,
            );
            return;
        }
    }
    let result = apply_access_mode_result(
        PermissionResult {
            permission: Permission::Passthrough,
            reason: format!("{} modifies files", hook_input.tool_name),
            suggestion: None,
        },
        hook_input.access_mode(),
    );
    match result.permission {
        Permission::Allow | Permission::Ask | Permission::Deny => {
            output_decision(
                permission_name(result.permission),
                &result.reason,
                None,
                harness,
                supports_updated_input,
            );
        }
        Permission::Passthrough => {}
    }
}

/// Handle Read tool. Emits a decision when the path is on the ask-list or
/// auto-allow list; otherwise returns true without output so Claude Code's
/// default applies. `ask_paths` wins on overlap.
fn handle_read(hook_input: &HookInput, config: &Config, harness: Harness) -> bool {
    let supports_updated_input = hook_input.supports_updated_input;
    let Some(ref path) = hook_input.tool_input.file_path else {
        return true;
    };
    if config.is_ask_path(path) {
        output_decision(
            "ask",
            &format!("Read from protected path {}", path),
            None,
            harness,
            supports_updated_input,
        );
        return true;
    }
    if config.is_read_allowed(path) {
        output_decision(
            "allow",
            &format!("Read from allowed path {}", path),
            None,
            harness,
            supports_updated_input,
        );
    }
    true
}

fn check_main_thread_block(
    hook_input: &HookInput,
    config: &Config,
    is_subagent: bool,
    harness: Harness,
) -> bool {
    let is_disabled = !is_subagent
        && matches!(
            config.main_thread_default.as_deref(),
            Some("deny") | Some("ask")
        );
    if !is_disabled {
        return false;
    }
    let whitelisted = hook_input
        .tool_input
        .file_path
        .as_deref()
        .is_some_and(|p| config.is_main_thread_write_allowed(p));
    if whitelisted {
        return false;
    }
    output_decision(
        "deny",
        "main thread file writes disabled. Use Task() to delegate to subagents",
        None,
        harness,
        hook_input.supports_updated_input,
    );
    true
}

fn handle_regex_replace(hook_input: &HookInput, is_subagent: bool, harness: Harness) {
    let edit_mode = edits_allowed(hook_input.effective_permission_mode());
    let is_dry_run = hook_input.tool_input.dry_run.unwrap_or(false);
    let reason = regex_replace_reason(edit_mode, is_dry_run, is_subagent);
    let permission = if edit_mode || is_dry_run || is_subagent {
        Permission::Allow
    } else {
        Permission::Ask
    };
    let result = apply_access_mode_result(
        PermissionResult {
            permission,
            reason: reason.to_string(),
            suggestion: None,
        },
        hook_input.access_mode(),
    );
    output_decision(
        permission_name(result.permission),
        &result.reason,
        None,
        harness,
        hook_input.supports_updated_input,
    );
}

fn regex_replace_reason(edit_mode: bool, is_dry_run: bool, is_subagent: bool) -> &'static str {
    if is_dry_run {
        "regex replace (dry run)"
    } else if is_subagent {
        "regex replace (subagent)"
    } else if edit_mode {
        "regex replace (edit mode)"
    } else {
        "regex replace modifies files (not in edit mode)"
    }
}

fn emit_hostrun_eval_decision(
    hook_input: &HookInput,
    config: &Config,
    is_subagent: bool,
    harness: Harness,
) {
    emit_eval_decision(
        hook_input,
        config,
        is_subagent,
        harness,
        "hostrun_eval without code",
        analyze_hostrun_code_with_context,
    );
}

fn emit_pyrun_eval_decision(
    hook_input: &HookInput,
    config: &Config,
    is_subagent: bool,
    harness: Harness,
) {
    emit_eval_decision(
        hook_input,
        config,
        is_subagent,
        harness,
        "pyrun_eval without code",
        analyze_pyrun_code,
    );
}

fn emit_eval_decision(
    hook_input: &HookInput,
    config: &Config,
    is_subagent: bool,
    harness: Harness,
    missing_reason: &str,
    analyze: fn(&str, &Config, Option<&str>, Option<&str>, ExecContext) -> PermissionResult,
) {
    let ctx = ExecContext {
        edit_mode: edits_allowed(hook_input.effective_permission_mode()),
        is_subagent,
        bypass: bypass_mode(hook_input.effective_permission_mode()),
    };
    let result = hook_input.tool_input.code.as_deref().map(|code| {
        analyze(
            code,
            config,
            hook_input.tool_input.cwd.as_deref(),
            hook_input.cwd.as_deref(),
            ctx,
        )
    });
    emit_code_decision(hook_input, harness, missing_reason, result);
}

fn emit_code_decision(
    hook_input: &HookInput,
    harness: Harness,
    missing_reason: &str,
    result: Option<PermissionResult>,
) {
    let Some(result) = result else {
        output_decision(
            "ask",
            missing_reason,
            None,
            harness,
            hook_input.supports_updated_input,
        );
        return;
    };
    let result = apply_access_mode_result(result, hook_input.access_mode());
    output_decision(
        permission_name(result.permission),
        &result.reason,
        None,
        harness,
        hook_input.supports_updated_input,
    );
}

#[cfg(test)]
fn analyze_hostrun_code(code: &str, config: &Config) -> PermissionResult {
    analyze_hostrun_code_with_context(code, config, None, None, ExecContext::default())
}

fn analyze_pyrun_code(
    code: &str,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> PermissionResult {
    pyrun::check_pyrun_code(code, config, virtual_cwd, initial_cwd, ctx)
}

fn analyze_hostrun_code_with_context(
    code: &str,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> PermissionResult {
    node::check_javascript_code(code, config, virtual_cwd, initial_cwd, ctx)
}

#[cfg(test)]
mod tests;
