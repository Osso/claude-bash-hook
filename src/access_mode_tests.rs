use crate::config::{Config, Permission};
use crate::{
    HookInput, analyze_and_resolve, apply_access_mode_permission, apply_access_mode_result,
    build_codex_hook_output, build_hook_output, edits_allowed, handle_subagent_event,
    has_codex_env, parse_hook_input, permission_name, resolve_passthrough,
    serialize_codex_hook_output, serialize_hook_output,
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

#[test]
fn test_parse_hook_input_success() {
    let input = parse_hook_input(r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#)
        .expect("hook input");
    assert_eq!(input.tool_name, "Bash");
    assert_eq!(input.tool_input.command.as_deref(), Some("ls -la"));
}

#[test]
fn test_parse_hook_input_reports_json_error() {
    let error = parse_hook_input("{not json").expect_err("invalid json should fail");
    assert!(error.contains("key"));
}

#[test]
fn test_build_hook_output_uses_expected_shape() {
    let output = build_hook_output("allow", "safe", Some(json!({"command": "rtk git status"})));
    assert_eq!(output.hook_output.event_name, "PreToolUse");
    assert_eq!(output.hook_output.decision, "allow");
    assert_eq!(output.hook_output.reason, "safe");
    assert_eq!(
        output.hook_output.updated_input,
        Some(json!({"command": "rtk git status"}))
    );
}

#[test]
fn test_serialize_hook_output_includes_updated_input() {
    let json = serialize_hook_output(
        "ask",
        "needs review",
        Some(json!({"command": "rtk git status"})),
    )
    .expect("json");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid output json");
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "ask");
    assert_eq!(
        value["hookSpecificOutput"]["updatedInput"]["command"],
        "rtk git status"
    );
}

#[test]
fn test_is_codex_true_when_access_mode_present() {
    let input: HookInput = serde_json::from_value(json!({
        "tool_name": "Bash",
        "tool_input": { "command": "ls" },
        "access_mode": "supervised"
    }))
    .expect("hook input");
    assert!(input.is_codex());
}

#[test]
fn test_is_codex_true_when_nested_under_hook_event() {
    let input: HookInput = serde_json::from_value(json!({
        "tool_name": "Bash",
        "tool_input": { "command": "ls" },
        "hook_event": { "access_mode": "full_access" }
    }))
    .expect("hook input");
    assert!(input.is_codex());
}

#[test]
fn test_is_codex_runtime_uses_codex_env_marker() {
    let input: HookInput = serde_json::from_value(json!({
        "tool_name": "Bash",
        "tool_input": { "command": "ls" }
    }))
    .expect("hook input");

    assert!(crate::is_codex_runtime_with_env(
        &input,
        ["CODEX_THREAD_ID"]
    ));
}

#[test]
fn test_is_codex_false_for_claude_payload() {
    let input: HookInput = serde_json::from_value(json!({
        "tool_name": "Bash",
        "tool_input": { "command": "ls" },
        "permission_mode": "default"
    }))
    .expect("hook input");
    assert!(!input.is_codex());
}

#[test]
fn test_has_codex_env_detects_codex_markers() {
    assert!(has_codex_env(["CODEX_THREAD_ID"]));
    assert!(has_codex_env(["PATH", "CODEX_CI"]));
    assert!(!has_codex_env(["PATH", "HOME"]));
}

#[test]
fn test_build_codex_hook_output_deny_shape_matches_codex_schema() {
    let output =
        build_codex_hook_output("deny", "git push origin master: blocks force pushes", None)
            .expect("deny should build a codex output");
    let value = serde_json::to_value(output).expect("serializable");
    assert_eq!(value["decision"], "block");
    assert_eq!(
        value["reason"],
        "git push origin master: blocks force pushes"
    );
    assert!(value.get("updatedInput").is_none());
}

#[test]
fn test_build_codex_hook_output_returns_none_for_bare_allow() {
    let output = build_codex_hook_output("allow", "safe command", None)
        .expect("allow should build for codex");
    let value = serde_json::to_value(output).expect("serializable");
    assert_eq!(value["decision"], "approve");
    assert!(value.get("reason").is_none());
}

#[test]
fn test_build_codex_hook_output_returns_none_for_ask() {
    assert!(build_codex_hook_output("ask", "needs review", None).is_none());
}

#[test]
fn test_build_codex_hook_output_substitutes_reason_when_blank() {
    let output = build_codex_hook_output("deny", "   ", None).expect("deny should build");
    assert!(
        !serde_json::to_value(output)
            .expect("serializable")
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .is_empty(),
        "codex requires non-empty reason on deny"
    );
}

#[test]
fn test_build_codex_hook_output_drops_updated_input_on_allow() {
    let output = build_codex_hook_output(
        "allow",
        "alias rewrite",
        Some(json!({ "command": "rtk git status" })),
    )
    .expect("allow should build a codex output");
    let value = serde_json::to_value(output).expect("serializable");
    assert_eq!(value["decision"], "approve");
    assert!(value.get("updatedInput").is_none());
}

#[test]
fn test_serialize_codex_hook_output_deny_only_emits_supported_fields() {
    let json = serialize_codex_hook_output("deny", "rm -rf /: filesystem nuke", None)
        .expect("deny should serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid output json");
    assert_eq!(value["decision"], "block");
    assert_eq!(value["reason"], "rm -rf /: filesystem nuke");
    assert!(value.get("updatedInput").is_none());
}

#[test]
fn test_serialize_codex_hook_output_allow_with_rewrite_omits_updated_input() {
    let json = serialize_codex_hook_output(
        "allow",
        "alias rewrite",
        Some(json!({ "command": "rtk git status" })),
    )
    .expect("allow should serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid output json");
    assert_eq!(value["decision"], "approve");
    assert!(value.get("updatedInput").is_none());
}

#[test]
fn test_serialize_codex_hook_output_returns_none_for_bare_allow_or_ask() {
    let json = serialize_codex_hook_output("allow", "safe", None)
        .expect("allow should serialize for codex");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid output json");
    assert_eq!(value["decision"], "approve");
    assert!(serialize_codex_hook_output("ask", "needs review", None).is_none());
}
