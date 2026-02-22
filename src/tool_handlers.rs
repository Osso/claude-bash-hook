//! Handlers for non-bash tools (Write, Edit, regex-replace)

use crate::config::Config;
use crate::{HookInput, check_write_path, edits_allowed, output_decision};

/// Handle Write, Edit, and regex-replace tools.
/// Returns true if the tool was handled (caller should return), false otherwise.
pub fn handle_non_bash_tool(hook_input: &HookInput, config: &Config, is_subagent: bool) -> bool {
    let is_main_thread_disabled = !is_subagent && config.main_thread_default.is_some();

    if hook_input.tool_name == "Write" || hook_input.tool_name == "Edit" {
        if is_main_thread_disabled {
            output_decision(
                "deny",
                "main thread file writes disabled. Use Task() to delegate to subagents",
            );
            return true;
        }
        if let Some(ref path) = hook_input.tool_input.file_path {
            if let Some(result) = check_write_path(path) {
                output_decision(&result.0, &result.1);
            }
        }
        return true;
    }

    if hook_input.tool_name == "mcp__regex-replace__regex_replace" {
        let edit_mode = edits_allowed(hook_input.permission_mode.as_deref());
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
        return true;
    }

    false
}
