//! Handlers for non-bash tools (Write, Edit, regex-replace)

use crate::config::{Config, Permission, PermissionResult};
use crate::{
    HookInput, apply_access_mode_result, check_write_path, edits_allowed, is_codex_runtime,
    output_decision, permission_name,
};

/// Handle Write, Edit, Read, and regex-replace tools.
/// Returns true if the tool was handled (caller should return), false otherwise.
pub fn handle_non_bash_tool(hook_input: &HookInput, config: &Config, is_subagent: bool) -> bool {
    let is_codex = is_codex_runtime(hook_input);
    if hook_input.tool_name == "Write" || hook_input.tool_name == "Edit" {
        handle_write_edit(hook_input, config, is_subagent, is_codex);
        return true;
    }
    if hook_input.tool_name == "Read" {
        return handle_read(hook_input, config, is_codex);
    }
    if is_regex_replace_tool(&hook_input.tool_name) {
        handle_regex_replace(hook_input, is_subagent, is_codex);
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

fn handle_write_edit(hook_input: &HookInput, config: &Config, is_subagent: bool, is_codex: bool) {
    if check_main_thread_block(hook_input, config, is_subagent, is_codex) {
        return;
    }
    if let Some(ref path) = hook_input.tool_input.file_path {
        if let Some(result) = check_write_path(path) {
            output_decision(&result.0, &result.1, None, is_codex);
            return;
        }
        if config.is_ask_path(path) {
            output_decision(
                "ask",
                &format!("{} to protected path {}", hook_input.tool_name, path),
                None,
                is_codex,
            );
            return;
        }
        if config.is_write_allowed(path) {
            output_decision(
                "allow",
                &format!("{} to allowed path {}", hook_input.tool_name, path),
                None,
                is_codex,
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
                is_codex,
            );
        }
        Permission::Passthrough => {}
    }
}

/// Handle Read tool. Emits a decision when the path is on the ask-list or
/// auto-allow list; otherwise returns true without output so Claude Code's
/// default applies. `ask_paths` wins on overlap.
fn handle_read(hook_input: &HookInput, config: &Config, is_codex: bool) -> bool {
    let Some(ref path) = hook_input.tool_input.file_path else {
        return true;
    };
    if config.is_ask_path(path) {
        output_decision(
            "ask",
            &format!("Read from protected path {}", path),
            None,
            is_codex,
        );
        return true;
    }
    if config.is_read_allowed(path) {
        output_decision(
            "allow",
            &format!("Read from allowed path {}", path),
            None,
            is_codex,
        );
    }
    true
}

fn check_main_thread_block(
    hook_input: &HookInput,
    config: &Config,
    is_subagent: bool,
    is_codex: bool,
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
        is_codex,
    );
    true
}

fn handle_regex_replace(hook_input: &HookInput, is_subagent: bool, is_codex: bool) {
    let edit_mode = edits_allowed(hook_input.permission_mode.as_deref());
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
        is_codex,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ToolInput;

    fn hook_input(tool_name: &str) -> HookInput {
        HookInput {
            tool_name: tool_name.to_string(),
            ..Default::default()
        }
    }

    fn config_with_main_thread_default(permission: &str) -> Config {
        toml::from_str(&format!(r#"main_thread_default = "{}""#, permission)).expect("config")
    }

    impl Default for HookInput {
        fn default() -> Self {
            HookInput {
                tool_name: String::new(),
                tool_input: ToolInput::default(),
                permission_mode: None,
                access_mode: None,
                cwd: None,
                session_id: None,
                turn_id: None,
                tool_use_id: None,
                hook_event_name: None,
                hook_event: None,
            }
        }
    }

    #[test]
    fn test_handle_non_bash_tool_returns_false_for_other_tools() {
        let handled = handle_non_bash_tool(&hook_input("Bash"), &Config::default(), false);
        assert!(!handled);
    }

    #[test]
    fn test_handle_non_bash_tool_handles_regex_replace() {
        let mut input = hook_input("mcp__regex-replace__regex_replace");
        input.tool_input.dry_run = Some(true);
        assert!(handle_non_bash_tool(&input, &Config::default(), false));
    }

    #[test]
    fn test_handle_non_bash_tool_handles_codex_regex_replace_name() {
        let mut input = hook_input("regex-replace.regex_replace");
        input.tool_input.dry_run = Some(true);
        assert!(handle_non_bash_tool(&input, &Config::default(), false));
    }

    #[test]
    fn test_handle_non_bash_tool_handles_write_edit() {
        let mut input = hook_input("Write");
        input.tool_input.file_path = Some("/tmp/test.txt".to_string());
        assert!(handle_non_bash_tool(&input, &Config::default(), false));
    }

    #[test]
    fn test_check_main_thread_block_denies_when_disabled() {
        let mut input = hook_input("Write");
        input.tool_input.file_path = Some("/tmp/test.txt".to_string());
        let config = config_with_main_thread_default("deny");
        assert!(check_main_thread_block(&input, &config, false, false));
    }

    #[test]
    fn test_check_main_thread_block_allows_whitelisted_path() {
        let mut input = hook_input("Write");
        input.tool_input.file_path = Some("/tmp/allowed/file.txt".to_string());
        let config: Config = toml::from_str(
            r#"
            main_thread_default = "deny"
            main_thread_write_allow = ["/tmp/allowed/*"]
        "#,
        )
        .expect("config");
        assert!(!check_main_thread_block(&input, &config, false, false));
    }

    #[test]
    fn test_check_main_thread_block_skips_for_subagent() {
        let mut input = hook_input("Write");
        input.tool_input.file_path = Some("/tmp/test.txt".to_string());
        let config = config_with_main_thread_default("deny");
        assert!(!check_main_thread_block(&input, &config, true, false));
    }

    #[test]
    fn test_check_main_thread_block_skips_when_default_not_restrictive() {
        let mut input = hook_input("Write");
        input.tool_input.file_path = Some("/tmp/test.txt".to_string());
        let config = config_with_main_thread_default("allow");
        assert!(!check_main_thread_block(&input, &config, false, false));
    }

    #[test]
    fn test_regex_replace_reason_variants() {
        assert_eq!(
            regex_replace_reason(false, true, false),
            "regex replace (dry run)"
        );
        assert_eq!(
            regex_replace_reason(false, false, true),
            "regex replace (subagent)"
        );
        assert_eq!(
            regex_replace_reason(true, false, false),
            "regex replace (edit mode)"
        );
        assert_eq!(
            regex_replace_reason(false, false, false),
            "regex replace modifies files (not in edit mode)"
        );
    }

    #[test]
    fn test_handle_regex_replace_ask_path() {
        let input = hook_input("mcp__regex-replace__regex_replace");
        assert!(handle_non_bash_tool(&input, &Config::default(), false));
    }

    fn ask_paths_config(pattern: &str) -> Config {
        toml::from_str(&format!(r#"ask_paths = ["{}"]"#, pattern)).expect("config")
    }

    #[test]
    fn test_handle_non_bash_tool_handles_read() {
        let mut input = hook_input("Read");
        input.tool_input.file_path = Some("/home/user/.config/kitty.conf".to_string());
        let config = ask_paths_config("/home/user/.config/*");
        assert!(handle_non_bash_tool(&input, &config, false));
    }

    #[test]
    fn test_handle_non_bash_tool_read_no_match_still_handled() {
        let mut input = hook_input("Read");
        input.tool_input.file_path = Some("/tmp/file.txt".to_string());
        assert!(handle_non_bash_tool(&input, &Config::default(), false));
    }

    #[test]
    fn test_read_allow_paths_match() {
        let mut input = hook_input("Read");
        input.tool_input.file_path = Some("/home/user/Repos/foo.rs".to_string());
        let config: Config =
            toml::from_str(r#"read_allow_paths = ["/home/user/Repos/*"]"#).expect("config");
        assert!(handle_non_bash_tool(&input, &config, false));
    }

    #[test]
    fn test_ask_paths_beats_read_allow_paths() {
        let mut input = hook_input("Read");
        input.tool_input.file_path = Some("/home/user/.config/secret".to_string());
        let config: Config = toml::from_str(
            r#"
            ask_paths = ["/home/user/.config/*"]
            read_allow_paths = ["/home/user/*"]
        "#,
        )
        .expect("config");
        assert!(handle_non_bash_tool(&input, &config, false));
    }

    #[test]
    fn test_write_allow_paths_match() {
        let mut input = hook_input("Write");
        input.tool_input.file_path = Some("/tmp/mcp_probe.py".to_string());
        let config: Config = toml::from_str(r#"write_allow_paths = ["/tmp/*"]"#).expect("config");
        assert!(handle_non_bash_tool(&input, &config, false));
    }

    #[test]
    fn test_ask_paths_beats_write_allow_paths() {
        let mut input = hook_input("Write");
        input.tool_input.file_path = Some("/home/user/.config/secret".to_string());
        let config: Config = toml::from_str(
            r#"
            ask_paths = ["/home/user/.config/*"]
            write_allow_paths = ["/home/user/*"]
        "#,
        )
        .expect("config");
        assert!(handle_non_bash_tool(&input, &config, false));
    }
}
