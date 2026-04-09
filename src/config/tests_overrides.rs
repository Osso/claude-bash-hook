//! Tests for context-based permission overrides (edit mode, subagent, main thread)

use super::*;

const MAGICK_CROP_SIZE: &str = "100x100+0+0";

#[test]
fn test_edit_mode_permission() {
    let toml = r#"
        default = "ask"
        [[rules]]
        commands = ["magick"]
        permission = "ask"
        edit_mode_permission = "allow"
        reason = "image manipulation"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Without edit mode - ask
    let result = config.check_command_with_cwd(
        "magick",
        &[
            "input.webp".into(),
            "-crop".into(),
            MAGICK_CROP_SIZE.into(),
            "output.png".into(),
        ],
        None,
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);

    // With edit mode - allow
    let result = config.check_command_with_cwd(
        "magick",
        &[
            "input.webp".into(),
            "-crop".into(),
            MAGICK_CROP_SIZE.into(),
            "output.png".into(),
        ],
        None,
        ExecContext {
            edit_mode: true,
            ..Default::default()
        },
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_edit_mode_permission_not_set() {
    // When edit_mode_permission is not set, edit_mode has no effect
    let toml = r#"
        default = "ask"
        [[rules]]
        commands = ["somecmd"]
        permission = "ask"
        reason = "test"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    let result = config.check_command_with_cwd("somecmd", &[], None, ExecContext::default());
    assert_eq!(result.permission, Permission::Ask);

    let result = config.check_command_with_cwd(
        "somecmd",
        &[],
        None,
        ExecContext {
            edit_mode: true,
            ..Default::default()
        },
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_subagent_permission_overrides_base() {
    let toml = r#"
        default = "ask"
        [[rules]]
        commands = ["docker run"]
        permission = "ask"
        subagent_permission = "allow"
        reason = "docker run"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Without subagent - ask
    let result =
        config.check_command_with_cwd("docker", &["run".into()], None, ExecContext::default());
    assert_eq!(result.permission, Permission::Ask);

    // With subagent - allow
    let result = config.check_command_with_cwd(
        "docker",
        &["run".into()],
        None,
        ExecContext {
            is_subagent: true,
            ..Default::default()
        },
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_subagent_permission_priority_over_edit_mode() {
    // subagent_permission takes priority over edit_mode_permission
    let toml = r#"
        default = "ask"
        [[rules]]
        commands = ["mycmd"]
        permission = "deny"
        edit_mode_permission = "ask"
        subagent_permission = "allow"
        reason = "test priority"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Subagent + edit mode: subagent_permission wins
    let result = config.check_command_with_cwd(
        "mycmd",
        &[],
        None,
        ExecContext {
            edit_mode: true,
            is_subagent: true,
        },
    );
    assert_eq!(result.permission, Permission::Allow);

    // Edit mode only: edit_mode_permission applies
    let result = config.check_command_with_cwd(
        "mycmd",
        &[],
        None,
        ExecContext {
            edit_mode: true,
            ..Default::default()
        },
    );
    assert_eq!(result.permission, Permission::Ask);

    // Neither: base permission
    let result = config.check_command_with_cwd("mycmd", &[], None, ExecContext::default());
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_subagent_default_applies_when_no_rule_matches() {
    let toml = r#"
        default = "ask"
        subagent_default = "allow"
        [[rules]]
        commands = ["ls"]
        permission = "allow"
        reason = "read-only"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Unknown command, not subagent: uses default (ask)
    let result = config.check_command_with_cwd("unknown_cmd", &[], None, ExecContext::default());
    assert_eq!(result.permission, Permission::Ask);

    // Unknown command, subagent: uses subagent_default (allow)
    let result = config.check_command_with_cwd(
        "unknown_cmd",
        &[],
        None,
        ExecContext {
            is_subagent: true,
            ..Default::default()
        },
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_subagent_default_not_set_falls_back() {
    let toml = r#"
        default = "passthrough"
        [[rules]]
        commands = ["ls"]
        permission = "allow"
        reason = "read-only"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Subagent without subagent_default: uses regular default
    let result = config.check_command_with_cwd(
        "unknown_cmd",
        &[],
        None,
        ExecContext {
            is_subagent: true,
            ..Default::default()
        },
    );
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_main_thread_default_denies_all() {
    let toml = r#"
        default = "allow"
        main_thread_default = "deny"
        [[rules]]
        commands = ["ls"]
        permission = "allow"
        reason = "read-only"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Main thread: ls matches a rule but has no main_thread_permission → deny
    let result = config.check_command_with_cwd("ls", &[], None, ExecContext::default());
    assert_eq!(result.permission, Permission::Deny);
    assert!(result.suggestion.unwrap().contains("Task()"));

    // Subagent: unaffected, uses normal rule permission
    let result = config.check_command_with_cwd(
        "ls",
        &[],
        None,
        ExecContext {
            is_subagent: true,
            ..Default::default()
        },
    );
    assert_eq!(result.permission, Permission::Allow);
    assert!(result.suggestion.is_none());
}

#[test]
fn test_main_thread_permission_overrides_default() {
    let toml = r#"
        default = "allow"
        main_thread_default = "deny"
        [[rules]]
        commands = ["git status"]
        permission = "allow"
        main_thread_permission = "allow"
        reason = "git read-only"

        [[rules]]
        commands = ["ls"]
        permission = "allow"
        reason = "read-only"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Main thread: git status has main_thread_permission = allow → allow
    let result =
        config.check_command_with_cwd("git", &["status".into()], None, ExecContext::default());
    assert_eq!(result.permission, Permission::Allow);

    // Main thread: ls has no main_thread_permission → deny
    let result = config.check_command_with_cwd("ls", &[], None, ExecContext::default());
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_main_thread_default_no_rule_match() {
    let toml = r#"
        default = "passthrough"
        main_thread_default = "deny"
        [[rules]]
        commands = ["ls"]
        permission = "allow"
        reason = "read-only"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Main thread: unknown command, no rule → uses main_thread_default (deny)
    let result = config.check_command_with_cwd("unknown_cmd", &[], None, ExecContext::default());
    assert_eq!(result.permission, Permission::Deny);
    assert!(result.suggestion.unwrap().contains("Task()"));

    // Subagent: unknown command → uses regular default (passthrough)
    let result = config.check_command_with_cwd(
        "unknown_cmd",
        &[],
        None,
        ExecContext {
            is_subagent: true,
            ..Default::default()
        },
    );
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_main_thread_default_not_set_no_effect() {
    let toml = r#"
        default = "allow"
        [[rules]]
        commands = ["ls"]
        permission = "allow"
        reason = "read-only"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Without main_thread_default, main thread uses normal rules
    let result = config.check_command_with_cwd("ls", &[], None, ExecContext::default());
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_main_thread_default_with_host_rules() {
    let toml = r#"
        default = "allow"
        main_thread_default = "deny"
        [[rules]]
        commands = ["ssh"]
        permission = "check_host"
        main_thread_permission = "check_host"
        reason = "remote connection"
        host_rules = [
            { pattern = "*.internal.com", permission = "allow" },
            { pattern = "*", permission = "ask" },
        ]
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Main thread: ssh with main_thread_permission → check_host works
    let result = config.check_command_with_host(
        "ssh",
        &["server.internal.com".into()],
        Some("server.internal.com"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);
}
