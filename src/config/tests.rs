use super::*;
use std::fs;
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
fn test_load_reads_network_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let network_path = dir.path().join("network.toml");

    fs::write(&config_path, r#"default = "passthrough""#).unwrap();
    fs::write(
        network_path,
        r#"
            [[hosts]]
            pattern = "api.example.com"
            permission = "allow"

            [[hosts]]
            pattern = "*"
            permission = "ask"
        "#,
    )
    .unwrap();

    let config = Config::load(&config_path).unwrap();
    let (result, wildcard_matched) =
        config.check_network_host_flagged(Some("api.example.com"), ExecContext::default());

    assert_eq!(result.permission, Permission::Allow);
    assert!(!wildcard_matched);

    let (result, wildcard_matched) =
        config.check_network_host_flagged(Some("unknown.example"), ExecContext::default());

    assert_eq!(result.permission, Permission::Ask);
    assert!(wildcard_matched);
}

#[test]
fn test_load_reads_hostrun_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let hostrun_path = dir.path().join("hostrun.toml");

    fs::write(&config_path, r#"default = "passthrough""#).unwrap();
    fs::write(
        hostrun_path,
        r#"
            [[rules]]
            operation = "fs.read"
            path = "/home/osso/Repos/**"
            permission = "allow"
        "#,
    )
    .unwrap();

    let config = Config::load(&config_path).unwrap();

    assert_eq!(config.hostrun.rules.len(), 1);
    assert_eq!(config.hostrun.rules[0].operation, "fs.read");
    assert_eq!(
        config.hostrun.rules[0].path.as_deref(),
        Some("/home/osso/Repos/**")
    );
    assert_eq!(config.hostrun.rules[0].permission, "allow");
}

#[test]
fn test_hostrun_fs_rule_requires_path() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let hostrun_path = dir.path().join("hostrun.toml");

    fs::write(&config_path, r#"default = "passthrough""#).unwrap();
    fs::write(
        hostrun_path,
        r#"
            [[rules]]
            operation = "fs.read"
            permission = "allow"
        "#,
    )
    .unwrap();

    let err = Config::load(&config_path).unwrap_err();

    assert!(err.contains("fs.read"));
    assert!(err.contains("path"));
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

fn unique_temp_dir(name: &str) -> String {
    let path = std::env::temp_dir().join(format!(
        "claude-bash-hook-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&path).expect("create temp dir");
    path.to_string_lossy().to_string()
}

#[test]
fn test_rewrite_command_uses_longest_matching_prefix() {
    let config: Config = toml::from_str(
        r#"
        [rewrite]
        enabled = true
        binary = "rtk"
        prefixes = ["git", "git status"]
    "#,
    )
    .unwrap();

    assert_eq!(
        config.rewrite_command("git status --short"),
        Some("rtk git status --short".to_string())
    );
}

#[test]
fn test_rewrite_command_skips_compound_and_already_rewritten() {
    let config: Config = toml::from_str(
        r#"
        [rewrite]
        enabled = true
        binary = "rtk"
        prefixes = ["git"]
    "#,
    )
    .unwrap();

    assert_eq!(config.rewrite_command("git status && git diff"), None);
    assert_eq!(config.rewrite_command("rtk git status"), None);
}

#[test]
fn test_is_main_thread_write_allowed_exact_and_child_match() {
    let config: Config = toml::from_str(
        r#"
        main_thread_write_allow = ["/tmp/exact.txt", "/tmp/dir/*"]
    "#,
    )
    .unwrap();

    assert!(config.is_main_thread_write_allowed("/tmp/exact.txt"));
    assert!(config.is_main_thread_write_allowed("/tmp/dir/file.txt"));
    assert!(config.is_main_thread_write_allowed("/tmp/dir/nested/file.txt"));
    assert!(!config.is_main_thread_write_allowed("/tmp/other.txt"));
}

#[test]
fn test_is_main_thread_write_allowed_expands_home() {
    let home = std::env::var("HOME").expect("home");
    let config: Config = toml::from_str(r#"main_thread_write_allow = ["~/allowed/*"]"#).unwrap();
    assert!(config.is_main_thread_write_allowed(&format!("{}/allowed/file.txt", home)));
}

#[test]
fn test_is_master_push_allowed_for_exact_and_subdir() {
    let root = unique_temp_dir("master-push");
    let subdir = format!("{}/nested", root);
    fs::create_dir_all(&subdir).unwrap();

    let config: Config = toml::from_str(&format!(r#"master_push_allowed = ["{}"]"#, root)).unwrap();

    assert!(config.is_master_push_allowed(Some(&root)));
    assert!(config.is_master_push_allowed(Some(&subdir)));
    assert!(!config.is_master_push_allowed(Some("/tmp/somewhere-else")));
}

#[test]
fn test_load_invalid_config_returns_error() {
    let dir = unique_temp_dir("invalid-config");
    let path = Path::new(&dir).join("config.toml");
    fs::write(&path, "not = [valid").unwrap();

    let error = Config::load(&path).expect_err("invalid TOML should fail");
    assert!(error.contains("Failed to parse config"));
}

#[test]
fn test_rule_effective_permission_prefers_context_specific_overrides() {
    let rule: Rule = toml::from_str(
        r#"
        commands = ["git status"]
        permission = "ask"
        edit_mode_permission = "allow"
        subagent_permission = "deny"
    "#,
    )
    .unwrap();

    assert_eq!(
        rule.effective_permission(ExecContext {
            edit_mode: false,
            is_subagent: false,
            ..Default::default()
        }),
        "ask"
    );
    assert_eq!(
        rule.effective_permission(ExecContext {
            edit_mode: true,
            is_subagent: false,
            ..Default::default()
        }),
        "allow"
    );
    assert_eq!(
        rule.effective_permission(ExecContext {
            edit_mode: true,
            is_subagent: true,
            ..Default::default()
        }),
        "deny"
    );
}

#[test]
fn test_config_helpers_cover_wrappers_aliases_and_paths() {
    let config: Config = toml::from_str(
        r#"
        mysql_aliases = ["mysql", "mydb"]
        positional_sql_commands = ["gc sql"]

        [[wrappers]]
        command = "sudo"
        opts_with_args = ["-u"]
    "#,
    )
    .unwrap();

    let wrapper = config.get_wrapper("sudo").expect("wrapper");
    assert_eq!(wrapper.command, "sudo");
    assert_eq!(wrapper.opts_with_args, vec!["-u".to_string()]);
    assert!(config.is_mysql_alias("mydb"));
    assert!(!config.is_mysql_alias("psql"));
    assert!(config.is_positional_sql_command("gc", "sql"));
    assert!(!config.is_positional_sql_command("gc", "other"));
    assert_eq!(path_prefix("/tmp/path"), "/tmp/path/");
    assert_eq!(path_prefix("/tmp/path/"), "/tmp/path/");
    assert!(is_same_or_child_path("/tmp/path/nested", "/tmp/path"));
    assert!(!is_same_or_child_path("/tmp/other", "/tmp/path"));
}

#[test]
fn test_expand_home_and_canonicalize_helpers() {
    let home = std::env::var("HOME").expect("home");
    assert_eq!(expand_home("~/project"), format!("{}/project", home));
    assert_eq!(expand_home("/tmp/project"), "/tmp/project");

    let dir = unique_temp_dir("canonicalize");
    assert_eq!(canonicalize_for_match(&dir), Some(dir));
    assert_eq!(
        canonicalize_for_match("/path/that/should/not/exist"),
        Some("/path/that/should/not/exist".to_string())
    );
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
