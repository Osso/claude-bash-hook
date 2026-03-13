//! Handlers for non-bash tools (Write, Edit, regex-replace)

use crate::config::{Config, Permission, PermissionResult};
use crate::{
    HookInput, apply_access_mode_result, check_write_path, edits_allowed, output_decision,
    permission_name,
};

/// Handle Write, Edit, and regex-replace tools.
/// Returns true if the tool was handled (caller should return), false otherwise.
pub fn handle_non_bash_tool(hook_input: &HookInput, config: &Config, is_subagent: bool) -> bool {
    let is_main_thread_disabled = !is_subagent
        && matches!(
            config.main_thread_default.as_deref(),
            Some("deny") | Some("ask")
        );

    if hook_input.tool_name == "Write" || hook_input.tool_name == "Edit" {
        if is_main_thread_disabled {
            let whitelisted = hook_input
                .tool_input
                .file_path
                .as_deref()
                .is_some_and(|p| config.is_main_thread_write_allowed(p));
            if !whitelisted {
                output_decision(
                    "deny",
                    "main thread file writes disabled. Use Task() to delegate to subagents",
                );
                return true;
            }
        }
        if let Some(ref path) = hook_input.tool_input.file_path {
            if let Some(result) = check_write_path(path) {
                output_decision(&result.0, &result.1);
                return true;
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
                output_decision(permission_name(result.permission), &result.reason);
            }
            Permission::Passthrough => {}
        }
        return true;
    }

    if hook_input.tool_name == "mcp__regex-replace__regex_replace" {
        let edit_mode = edits_allowed(hook_input.permission_mode.as_deref());
        let is_dry_run = hook_input.tool_input.dry_run.unwrap_or(false);

        let reason = if is_dry_run {
            "regex replace (dry run)"
        } else if is_subagent {
            "regex replace (subagent)"
        } else if edit_mode {
            "regex replace (edit mode)"
        } else {
            "regex replace modifies files (not in edit mode)"
        };
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

        output_decision(permission_name(result.permission), &result.reason);
        return true;
    }

    false
}
