use super::*;
use std::path::Path;

/// Test helper trait to add convenience methods
trait ConfigTestExt {
    fn check_command(&self, name: &str, args: &[String]) -> PermissionResult;
}

impl ConfigTestExt for Config {
    fn check_command(&self, name: &str, args: &[String]) -> PermissionResult {
        self.check_command_with_cwd(name, args, None, ExecContext::default())
    }
}

fn test_config() -> Config {
    Config::load(Path::new("config.default.toml")).expect("Failed to load test config")
}

#[test]
fn test_simple_match() {
    let config = test_config();
    let result = config.check_command("ls", &["-la".into()]);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_subcommand_match() {
    let config = test_config();
    let result = config.check_command("git", &["status".into()]);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_flag_match() {
    let config = test_config();
    let result = config.check_command("rm", &["-rf".into(), "/tmp/foo".into()]);
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_combined_flags() {
    let config = test_config();
    // rm -rf should match "rm -r" rule
    let result = config.check_command("rm", &["-rf".into(), "/tmp".into()]);
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_suggestion() {
    let config = test_config();
    let result = config.check_command("git", &["checkout".into(), "main".into()]);
    assert!(result.suggestion.is_some());
    assert!(result.suggestion.unwrap().contains("git switch"));
}

#[test]
fn test_unknown_command() {
    let config = test_config();
    let result = config.check_command("unknown_cmd", &[]);
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_git_with_path_flag() {
    let config = test_config();
    // git -C path describe should match "git describe" rule
    let result = config.check_command(
        "git",
        &["-C".into(), "~/Projects/sentry".into(), "describe".into()],
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_kubectl_with_namespace() {
    let config = test_config();
    // kubectl -n namespace get pods should match "kubectl get"
    let result = config.check_command(
        "kubectl",
        &["-n".into(), "prod".into(), "get".into(), "pods".into()],
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_default_config_allows_ls() {
    let config = Config::default();
    let result = config.check_command("ls", &[]);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_default_config_passthrough_unknown() {
    let config = Config::default();
    let result = config.check_command("unknown_dangerous_cmd", &[]);
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_full_path_matches_basename() {
    let config = test_config();
    // /usr/bin/ls should match "ls" rule
    let result = config.check_command("/usr/bin/ls", &["-la".into()]);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_full_path_with_subcommand() {
    let config = test_config();
    // /usr/bin/git status should match "git status" rule
    let result = config.check_command("/usr/bin/git", &["status".into()]);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_dotslash_normalization() {
    // Test that ./path and path are treated equivalently
    let toml = r#"
        [[rules]]
        commands = ["target/release/foo"]
        permission = "allow"
        reason = "test"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // ./target/release/foo should match "target/release/foo" rule
    let result = config.check_command("./target/release/foo", &[]);
    assert_eq!(result.permission, Permission::Allow);

    // target/release/foo should also match
    let result = config.check_command("target/release/foo", &[]);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_dotslash_pattern_matches_without_dotslash() {
    // Pattern has ./, command doesn't
    let toml = r#"
        [[rules]]
        commands = ["./target/release/bar"]
        permission = "allow"
        reason = "test"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Both should match
    let result = config.check_command("./target/release/bar", &[]);
    assert_eq!(result.permission, Permission::Allow);

    let result = config.check_command("target/release/bar", &[]);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_absolute_path_matches_relative_pattern_with_cwd() {
    // Pattern is relative, command is absolute, should match when cwd aligns
    let toml = r#"
        [[rules]]
        commands = ["target/release/myapp"]
        permission = "allow"
        reason = "test"
        cwd = "/home/user/project"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Absolute path matching relative pattern with cwd
    let result = config.check_command_with_cwd(
        "/home/user/project/target/release/myapp",
        &[],
        Some("/home/user/project"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);

    // Should NOT match with different cwd (default is Ask when no rule matches)
    let result = config.check_command_with_cwd(
        "/home/user/project/target/release/myapp",
        &[],
        Some("/home/other/project"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_cwd_matches_subdirectories() {
    // For cwd-constrained rules, cwd + cmd must resolve to rule_cwd + pattern
    let toml = r#"
        [[rules]]
        commands = ["run-tests.sh"]
        permission = "allow"
        reason = "test"
        cwd = "/home/user/project"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Exact cwd match - run-tests.sh at /home/user/project/run-tests.sh
    let result = config.check_command_with_cwd(
        "run-tests.sh",
        &[],
        Some("/home/user/project"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);

    // Subdirectory matches for bare commands (no path separator in pattern or command)
    // Bare commands are on PATH, cwd only restricts which project tree can use them
    let result = config.check_command_with_cwd(
        "run-tests.sh",
        &[],
        Some("/home/user/project/src"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);

    // Should NOT match sibling directory
    let result = config.check_command_with_cwd(
        "run-tests.sh",
        &[],
        Some("/home/user/project2"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);

    // Should NOT match parent directory
    let result = config.check_command_with_cwd(
        "run-tests.sh",
        &[],
        Some("/home/user"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_cwd_with_glob_suffix() {
    // cwd pattern with /** suffix - glob suffix is stripped for base path matching
    let toml = r#"
        [[rules]]
        commands = ["run-tests.sh"]
        permission = "allow"
        reason = "test"
        cwd = "/home/user/project/**"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Exact match (without the /**)
    let result = config.check_command_with_cwd(
        "run-tests.sh",
        &[],
        Some("/home/user/project"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);

    // Subdirectory matches for bare commands (no path separator)
    let result = config.check_command_with_cwd(
        "run-tests.sh",
        &[],
        Some("/home/user/project/src"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_cwd_path_resolution() {
    // cwd + cmd must resolve to rule_cwd + pattern
    let toml = r#"
        [[rules]]
        commands = ["bin/custom-cli"]
        permission = "allow"
        reason = "my project"
        cwd = "/home/user/project"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Case 1: exact cwd, exact cmd -> allow
    let result = config.check_command_with_cwd(
        "bin/custom-cli",
        &[],
        Some("/home/user/project"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);

    // Case 2: exact cwd, ./bin/custom-cli -> allow (normalized)
    let result = config.check_command_with_cwd(
        "./bin/custom-cli",
        &[],
        Some("/home/user/project"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);

    // Case 3: cwd is subdirectory (bin), cmd is ./custom-cli
    // Resolves to /home/user/project/bin/custom-cli == /home/user/project/bin/custom-cli -> allow
    let result = config.check_command_with_cwd(
        "./custom-cli",
        &[],
        Some("/home/user/project/bin"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);

    // Case 4: exact cwd, cmd is ./custom-cli (wrong path)
    // Resolves to /home/user/project/custom-cli != /home/user/project/bin/custom-cli -> no match
    let result = config.check_command_with_cwd(
        "./custom-cli",
        &[],
        Some("/home/user/project"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);

    // Case 5: parent cwd (not under rule_cwd) -> no match
    let result = config.check_command_with_cwd(
        "bin/custom-cli",
        &[],
        Some("/home/user"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);

    // Case 6: cwd is /project/other, cmd is bin/custom-cli
    // Resolves to /home/user/project/other/bin/custom-cli != /home/user/project/bin/custom-cli -> no match
    let result = config.check_command_with_cwd(
        "bin/custom-cli",
        &[],
        Some("/home/user/project/other"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_cwd_bare_command_matches_subdirectories() {
    // Bare commands (no path separators) with cwd constraint should match
    // in subdirectories too - they're global commands on PATH, not local scripts
    let toml = r#"
        default = "ask"
        [[rules]]
        commands = ["browser-cli"]
        permission = "allow"
        reason = "browser automation"
        cwd = "/home/user/project"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Exact cwd match
    let result = config.check_command_with_cwd(
        "browser-cli",
        &[],
        Some("/home/user/project"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);

    // Subdirectory should also match (browser-cli is on PATH, not a local script)
    let result = config.check_command_with_cwd(
        "browser-cli",
        &[],
        Some("/home/user/project/frontend"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);

    // Parent directory should NOT match
    let result = config.check_command_with_cwd(
        "browser-cli",
        &[],
        Some("/home/user"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);

    // Sibling directory should NOT match
    let result = config.check_command_with_cwd(
        "browser-cli",
        &[],
        Some("/home/user/other"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);

    // With subcommands
    let result = config.check_command_with_cwd(
        "browser-cli",
        &["eval".into(), "document.title".into()],
        Some("/home/user/project/frontend"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_rule_opts_with_args() {
    // Rule-specific opts_with_args should be used for subcommand detection
    let toml = r#"
        default = "ask"
        [[rules]]
        commands = ["mycli projects", "mycli issues"]
        permission = "allow"
        reason = "mycli read-only"
        opts_with_args = ["-s", "--slug"]
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Without the -s flag, "gc" would be the first subcommand
    let result = config.check_command("mycli", &["gc".into(), "projects".into()]);
    assert_eq!(result.permission, Permission::Ask); // gc != projects

    // With -s flag, "gc" is consumed as argument, "projects" is first subcommand
    let result = config.check_command("mycli", &["-s".into(), "gc".into(), "projects".into()]);
    assert_eq!(result.permission, Permission::Allow);

    // Same with long form
    let result = config.check_command("mycli", &["--slug".into(), "gc".into(), "issues".into()]);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_sentry_with_slug_flag() {
    // Sentry has hardcoded -s/--slug in find_subcommands
    let toml = r#"
        default = "ask"
        [[rules]]
        commands = ["sentry projects", "sentry issues"]
        permission = "allow"
        reason = "sentry read-only"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // sentry -s gc projects should match "sentry projects"
    let result = config.check_command("sentry", &["-s".into(), "gc".into(), "projects".into()]);
    assert_eq!(result.permission, Permission::Allow);
}

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
            "100x100+0+0".into(),
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
            "100x100+0+0".into(),
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
fn test_git_worktree_with_c_flag() {
    let config = test_config();
    // git -C /path worktree add /tmp/claude/wow-mid a0374cc
    let result = config.check_command(
        "git",
        &[
            "-C".into(),
            "/syncthing/Sync/Projects/wow/wow-ui-sim".into(),
            "worktree".into(),
            "add".into(),
            "/tmp/claude/wow-mid".into(),
            "a0374cc".into(),
        ],
    );
    assert_eq!(result.permission, Permission::Allow);
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
