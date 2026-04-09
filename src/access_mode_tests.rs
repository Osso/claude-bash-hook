use crate::config::{Config, Permission};
use crate::{
    HookInput, analyze_and_resolve, apply_access_mode_permission, apply_access_mode_result,
    build_reason, edits_allowed, handle_subagent_event, permission_name, resolve_passthrough,
};
use serde_json::json;
use std::path::Path;

fn test_config() -> Config {
    Config::load(Path::new("config.default.toml")).expect("Failed to load test config")
}

#[test]
fn test_hook_input_reads_access_mode_from_codex_hook_event() {
    let input: HookInput = serde_json::from_value(json!({
        "tool_name": "Bash",
        "tool_input": { "command": "ls -la" },
        "hook_event": {
            "event_type": "pre_tool_use",
            "access_mode": "full_access"
        }
    }))
    .expect("codex hook payload should deserialize");

    assert_eq!(input.access_mode(), Some("full_access"));
}

#[test]
fn test_hook_input_prefers_top_level_access_mode() {
    let input: HookInput = serde_json::from_value(json!({
        "tool_name": "Bash",
        "tool_input": { "command": "ls -la" },
        "access_mode": "supervised",
        "hook_event": {
            "access_mode": "full_access"
        }
    }))
    .expect("hook input should deserialize");

    assert_eq!(input.access_mode(), Some("supervised"));
}

#[test]
fn test_full_access_upgrades_ask_to_allow() {
    assert_eq!(
        apply_access_mode_permission(Permission::Ask, Some("full_access")),
        Permission::Allow
    );
}

#[test]
fn test_supervised_upgrades_passthrough_to_ask() {
    assert_eq!(
        apply_access_mode_permission(Permission::Passthrough, Some("supervised")),
        Permission::Ask
    );
}

#[test]
fn test_full_access_upgrades_passthrough_to_allow() {
    assert_eq!(
        apply_access_mode_permission(Permission::Passthrough, Some("full_access")),
        Permission::Allow
    );
}

#[test]
fn test_deny_is_never_upgraded() {
    assert_eq!(
        apply_access_mode_permission(Permission::Deny, Some("full_access")),
        Permission::Deny
    );
}

#[test]
fn test_edits_allowed_modes() {
    assert!(edits_allowed(Some("acceptEdits")));
    assert!(edits_allowed(Some("bypassPermissions")));
    assert!(!edits_allowed(Some("default")));
    assert!(!edits_allowed(None));
}

#[test]
fn test_apply_access_mode_result_appends_reason() {
    let result = apply_access_mode_result(
        crate::config::PermissionResult {
            permission: Permission::Ask,
            reason: "needs review".to_string(),
            suggestion: None,
        },
        Some("full_access"),
    );
    assert_eq!(result.permission, Permission::Allow);
    assert!(result.reason.contains("needs review"));
    assert!(
        result
            .reason
            .contains("access_mode=full_access upgraded ask to allow")
    );
}

#[test]
fn test_apply_access_mode_result_fills_empty_reason() {
    let result = apply_access_mode_result(
        crate::config::PermissionResult {
            permission: Permission::Passthrough,
            reason: String::new(),
            suggestion: None,
        },
        Some("supervised"),
    );
    assert_eq!(result.permission, Permission::Ask);
    assert_eq!(
        result.reason,
        "access_mode=supervised upgraded passthrough to ask"
    );
}

#[test]
fn test_permission_name_all_variants() {
    assert_eq!(permission_name(Permission::Allow), "allow");
    assert_eq!(permission_name(Permission::Passthrough), "passthrough");
    assert_eq!(permission_name(Permission::Ask), "ask");
    assert_eq!(permission_name(Permission::Deny), "deny");
}

#[test]
fn test_resolve_passthrough_behavior() {
    let result = crate::config::PermissionResult {
        permission: Permission::Passthrough,
        reason: "unknown".to_string(),
        suggestion: Some("use config".to_string()),
    };
    assert!(resolve_passthrough(result, false).is_none());

    let result = crate::config::PermissionResult {
        permission: Permission::Passthrough,
        reason: "unknown".to_string(),
        suggestion: Some("use config".to_string()),
    };
    let resolved = resolve_passthrough(result, true).expect("nushell ask");
    assert_eq!(resolved.permission, Permission::Ask);
    assert_eq!(resolved.reason, "unknown");
}

#[test]
fn test_resolve_passthrough_keeps_non_passthrough() {
    let result = crate::config::PermissionResult {
        permission: Permission::Allow,
        reason: "safe".to_string(),
        suggestion: None,
    };
    let resolved = resolve_passthrough(result, false).expect("resolved");
    assert_eq!(resolved.permission, Permission::Allow);
    assert_eq!(resolved.reason, "safe");
}

#[test]
fn test_build_reason_without_advice_uses_formatter() {
    let config: Config = toml::from_str(r#"enable_advice = false"#).unwrap();
    let result = crate::config::PermissionResult {
        permission: Permission::Ask,
        reason: "why".to_string(),
        suggestion: Some("suggestion".to_string()),
    };
    assert_eq!(
        build_reason("git status", &result, &config),
        "git status: why\nsuggestion"
    );
}

#[test]
fn test_handle_subagent_event_start_and_stop() {
    let session_id = format!("test-session-{}", std::process::id());
    let start = HookInput {
        hook_event_name: Some("SubagentStart".to_string()),
        session_id: Some(session_id.clone()),
        ..serde_json::from_value(json!({
            "tool_name": "",
            "tool_input": {}
        }))
        .unwrap()
    };
    assert!(handle_subagent_event(&start));
    assert!(crate::subagent_tracker::has_active_subagents(&session_id));

    let stop = HookInput {
        hook_event_name: Some("SubagentStop".to_string()),
        session_id: Some(session_id.clone()),
        ..serde_json::from_value(json!({
            "tool_name": "",
            "tool_input": {}
        }))
        .unwrap()
    };
    assert!(handle_subagent_event(&stop));
    assert!(!crate::subagent_tracker::has_active_subagents(&session_id));
}

#[test]
fn test_handle_subagent_event_requires_event_and_session() {
    let missing_event = HookInput {
        session_id: Some("missing-event".to_string()),
        ..serde_json::from_value(json!({
            "tool_name": "",
            "tool_input": {}
        }))
        .unwrap()
    };
    assert!(!handle_subagent_event(&missing_event));

    let missing_session = HookInput {
        hook_event_name: Some("SubagentStart".to_string()),
        ..serde_json::from_value(json!({
            "tool_name": "",
            "tool_input": {}
        }))
        .unwrap()
    };
    assert!(!handle_subagent_event(&missing_session));
}

#[test]
fn test_handle_subagent_event_ignores_unknown_event() {
    let input = HookInput {
        hook_event_name: Some("PreToolUse".to_string()),
        session_id: Some(format!("unknown-event-{}", std::process::id())),
        ..serde_json::from_value(json!({
            "tool_name": "",
            "tool_input": {}
        }))
        .unwrap()
    };
    assert!(!handle_subagent_event(&input));
}

#[test]
fn test_analyze_and_resolve_upgrades_passthrough_in_nushell() {
    let config = test_config();
    let hook_input: HookInput = serde_json::from_value(json!({
        "tool_name": "mcp__nushell__execute",
        "tool_input": { "command": "rm -rf /" }
    }))
    .expect("hook input");

    let result =
        analyze_and_resolve(&hook_input, &config, "rm -rf /", true).expect("nushell result");
    assert_eq!(result.permission, Permission::Ask);
}
