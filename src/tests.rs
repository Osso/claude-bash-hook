use crate::config::{Config, ExecContext, Permission};
use crate::{analyze_command, check_write_path, serialize_hook_output};
use std::io::Write;
use std::path::Path;

fn test_config() -> Config {
    Config::load(Path::new("config.default.toml")).expect("Failed to load test config")
}

#[test]
fn test_simple_allow() {
    let config = test_config();
    let result = analyze_command("ls -la", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pipeline() {
    let config = test_config();
    let result = analyze_command("ls | grep foo", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_dangerous_command() {
    let config = test_config();
    let result = analyze_command("rm -rf /", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_sudo_wrapper() {
    let config = test_config();
    let result = analyze_command("sudo ls", &config, ExecContext::default(), None);
    // sudo unwraps to ls, which is allowed
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_stdbuf_wrapper() {
    let config = test_config();
    // stdbuf unwraps to ls, which is allowed
    let result = analyze_command("stdbuf -oL ls -la", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Allow);
    // stdbuf wrapping a denied command
    let result = analyze_command(
        "stdbuf -oL sed -i 's/a/b/' file.txt",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_sudo_dangerous() {
    let config = test_config();
    let result = analyze_command("sudo rm -rf /", &config, ExecContext::default(), None);
    // sudo unwraps to rm -rf /, which passes through
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_chain_with_dangerous() {
    let config = test_config();
    let result = analyze_command("ls && rm -rf /tmp", &config, ExecContext::default(), None);
    // Most restrictive should be passthrough
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_env_dangerous() {
    let config = test_config();
    let result = analyze_command("env VAR=1 rm -rf /", &config, ExecContext::default(), None);
    // env unwraps to rm -rf /, which passes through
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_var_assignment_safe() {
    let config = test_config();
    let result = analyze_command("VAR=1 ls -la", &config, ExecContext::default(), None);
    // ls is allowed even with env var
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_git_suggestion() {
    let config = test_config();
    let result = analyze_command("git checkout main", &config, ExecContext::default(), None);
    // Should have a suggestion
    assert!(result.suggestion.is_some());
}

#[test]
fn test_kubectl_exec_safe() {
    let config = test_config();
    let result = analyze_command(
        "kubectl exec mypod -- ls -la",
        &config,
        ExecContext::default(),
        None,
    );
    // kubectl exec unwraps to ls -la, which is allowed
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_kubectl_exec_dangerous() {
    let config = test_config();
    let result = analyze_command(
        "kubectl exec -n prod mypod -- rm -rf /",
        &config,
        ExecContext::default(),
        None,
    );
    // kubectl exec unwraps to rm -rf /, which passes through
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_kubectl_namespace_before_exec_env() {
    let config = test_config();
    // Test the exact problematic command: -n comes before exec
    let result = analyze_command(
        "kubectl -n external2-env exec deploy/api -- env 2>/dev/null | grep -i openai",
        &config,
        ExecContext::default(),
        None,
    );
    // kubectl exec unwraps to env, which is allowed; grep is also allowed
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_kubectl_get_allowed() {
    let config = test_config();
    let result = analyze_command("kubectl get pods", &config, ExecContext::default(), None);
    // kubectl get is allowed (not a wrapper, falls through to default)
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_sed_inline_allowed() {
    let config = test_config();
    let result = analyze_command(
        "echo test | sed 's/t/x/'",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_sed_n_inline_allowed() {
    let config = test_config();
    let result = analyze_command(
        "sed -n '5p' file.txt",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_sed_i_denied() {
    let config = test_config();
    let result = analyze_command(
        "sed -i 's/foo/bar/' file.txt",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_sed_i_suffix_denied() {
    let config = test_config();
    // sed -i.bak is also in-place
    let result = analyze_command(
        "sed -i.bak 's/foo/bar/' file.txt",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_awk_inline_allowed() {
    let config = test_config();
    let result = analyze_command(
        "awk '{print $1}' file.txt",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_perl_inline_allowed() {
    let config = test_config();
    // perl -pe without -i is just a pipeline filter
    let result = analyze_command(
        "echo test | perl -pe 's/foo/bar/'",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_perl_i_denied() {
    let config = test_config();
    let result = analyze_command(
        "perl -i -pe 's/foo/bar/' file.txt",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_perl_pi_denied() {
    let config = test_config();
    // -pi combines -p and -i flags
    let result = analyze_command(
        "perl -pi -e 's/foo/bar/' file.txt",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_perl_pie_denied() {
    let config = test_config();
    // -pie combines -p, -i, -e flags
    let result = analyze_command(
        "perl -pie 's/foo/bar/' file.txt",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_help_always_allowed() {
    let config = test_config();
    // --help flag
    let result = analyze_command("someunknown --help", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Allow);
    // -h flag
    let result = analyze_command("kubectl delete -h", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Allow);
    // help subcommand
    let result = analyze_command("cargo help build", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_version_always_allowed() {
    let config = test_config();
    // --version flag
    let result = analyze_command(
        "someunknown --version",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
    // -V flag
    let result = analyze_command("rustc -V", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Allow);
    // version subcommand
    let result = analyze_command("docker version", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_cwd_propagates_through_wrapper() {
    // Create a config with a cwd-restricted rule and sudo wrapper
    let config_str = r#"
        default = "passthrough"
        [[rules]]
        commands = ["cd"]
        permission = "allow"
        reason = "cd is safe"

        [[rules]]
        commands = ["./target/release/myapp"]
        permission = "allow"
        reason = "project binary"
        cwd = "/home/test/myproject"

        [[wrappers]]
        command = "sudo"
        opts_with_args = ["-g", "-p", "-r", "-t", "-u", "-T", "-C", "-h", "-U"]
    "#;
    let config: Config = toml::from_str(config_str).unwrap();

    // Without cd, should passthrough (no cwd match)
    let result = analyze_command(
        "sudo ./target/release/myapp",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Passthrough);

    // With cd before sudo, should allow (cwd propagates through wrapper)
    let result = analyze_command(
        "cd /home/test/myproject && sudo ./target/release/myapp",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

// Write path tests
#[test]
fn test_write_tmp_allowed() {
    let result = check_write_path("/tmp/test.txt");
    assert!(result.is_none());
}

#[test]
fn test_write_tmp_subdir_allowed() {
    let result = check_write_path("/tmp/foo/bar.txt");
    assert!(result.is_none());
}

#[test]
fn test_write_tmp_claude_allowed() {
    let result = check_write_path("/tmp/claude/test.txt");
    assert!(result.is_none()); // None = pass through = allowed
}

#[test]
fn test_write_tmp_claude_subdir_allowed() {
    let result = check_write_path("/tmp/claude/foo/bar.txt");
    assert!(result.is_none());
}

#[test]
fn test_write_home_allowed() {
    let result = check_write_path("/home/user/file.txt");
    assert!(result.is_none());
}

#[test]
fn test_write_project_allowed() {
    let result = check_write_path("/syncthing/Sync/Projects/test.rs");
    assert!(result.is_none());
}

// rm with cd tests (virtual cwd)

#[test]
fn test_cd_tmp_claude_then_rm_allowed() {
    // From cwd /, "cd /tmp/claude && rm test" should be allowed
    let config = test_config();
    let result = analyze_command(
        "cd /tmp/claude && rm test",
        &config,
        ExecContext::default(),
        Some("/"),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_cd_root_then_rm_not_allowed() {
    // From cwd /tmp/claude, "cd / && rm test" should NOT be allowed
    let config = test_config();
    let result = analyze_command(
        "cd / && rm test",
        &config,
        ExecContext::default(),
        Some("/tmp/claude"),
    );
    // Should passthrough (not allowed) because /test is not under /tmp/ or project
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_rm_absolute_path_ignores_cd() {
    // From cwd /, "cd / && rm /tmp/test" should be allowed (absolute path)
    let config = test_config();
    let result = analyze_command(
        "cd / && rm /tmp/test",
        &config,
        ExecContext::default(),
        Some("/"),
    );
    assert_eq!(result.permission, Permission::Allow);
}

// Piped query tests (echo 'SQL' | mysql)

#[test]
fn test_piped_select_allowed() {
    let config = test_config();
    let result = analyze_command(
        "echo 'SELECT * FROM users' | mysql",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_piped_insert_asks() {
    let config = test_config();
    let result = analyze_command(
        "echo 'INSERT INTO users VALUES (1)' | mysql",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_piped_show_allowed() {
    let config = test_config();
    let result = analyze_command(
        "echo 'SHOW DATABASES' | mariadb",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

// Positional SQL command tests (e.g., groundcover-cli sql-clickhouse "SELECT ...")

#[test]
fn test_positional_sql_select_allowed() {
    let toml = r#"
        positional_sql_commands = ["groundcover-cli sql-clickhouse"]
    "#;
    let config: Config = toml::from_str(toml).unwrap();
    let result = analyze_command(
        r#"groundcover-cli sql-clickhouse "SELECT count(*) FROM logs""#,
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_positional_sql_insert_asks() {
    let toml = r#"
        positional_sql_commands = ["groundcover-cli sql-clickhouse"]
    "#;
    let config: Config = toml::from_str(toml).unwrap();
    let result = analyze_command(
        r#"groundcover-cli sql-clickhouse "INSERT INTO logs VALUES (1)""#,
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_positional_sql_piped_allowed() {
    let toml = r#"
        positional_sql_commands = ["groundcover-cli sql-clickhouse"]
        [[rules]]
        commands = ["head"]
        permission = "allow"
        reason = "read-only"
    "#;
    let config: Config = toml::from_str(toml).unwrap();
    let result = analyze_command(
        r#"groundcover-cli sql-clickhouse "SELECT toStartOfMinute(Timestamp) as minute, count(*) FROM logs GROUP BY minute" | head -30"#,
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_piped_through_ssh_select_allowed() {
    let config = test_config();
    // Piped query through ssh wrapper
    let result = analyze_command(
        "echo 'SELECT 1' | ssh host 'mariadb -u user db'",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_piped_through_docker_exec_select_allowed() {
    let config = test_config();
    // Piped query through docker exec wrapper
    let result = analyze_command(
        "echo 'SELECT 1' | docker exec -i container mariadb",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_piped_through_ssh_docker_select_allowed() {
    let config = test_config();
    // Piped query through nested wrappers: ssh -> docker exec -> mariadb
    let result = analyze_command(
        "echo 'SELECT 1' | ssh host 'docker exec -i container mariadb'",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_piped_through_ssh_insert_asks() {
    let config = test_config();
    // Piped write query through ssh should ask
    let result = analyze_command(
        "echo 'INSERT INTO t VALUES (1)' | ssh host 'mariadb db'",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Ask);
}

// nu -c wrapper tests (uses nushell parser for inner command)

#[test]
fn test_nu_c_builtin_allowed() {
    let config = test_config();
    // nu -c with nushell builtins should be allowed
    let result = analyze_command(
        "nu -c 'open /tmp/claude/test.json | get items | to json'",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_nu_c_external_command() {
    let config = test_config();
    // nu -c with external command should check against rules
    let result = analyze_command("nu -c 'ls -la'", &config, ExecContext::default(), None);
    // ls is allowed by config
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_nu_c_dangerous_builtin() {
    let config = test_config();
    // nu -c with rm should check against rules
    let result = analyze_command(
        "nu -c 'rm ~/Documents/important.txt'",
        &config,
        ExecContext::default(),
        None,
    );
    // rm outside /tmp is dangerous
    assert_eq!(result.permission, Permission::Passthrough);
}

// docker compose exec tests (local vs remote)

#[test]
fn test_docker_compose_exec_local_allowed() {
    let config = test_config();
    let result = analyze_command(
        "docker compose exec web bash",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_docker_compose_exec_through_ssh() {
    let config = test_config();
    // Through SSH, should fall through to wrapper analysis
    // Inner command "bash" is not in allowed list, so passthrough
    let result = analyze_command(
        "ssh host 'docker compose exec web bash'",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_docker_compose_exec_through_ssh_safe_inner() {
    let config = test_config();
    // Through SSH with a safe inner command - still analyzed via wrapper
    let result = analyze_command(
        "ssh host 'docker compose exec web ls -la'",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_subagent_context_allows_unmatched_commands() {
    let toml = r#"
        default = "ask"
        subagent_default = "allow"
        [[rules]]
        commands = ["ls"]
        permission = "allow"
        reason = "read-only"
    "#;
    let config: Config = toml::from_str(toml).unwrap();

    // Main thread: unknown command uses default (ask)
    let result = analyze_command("some_tool --flag", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Ask);

    // Subagent: unknown command uses subagent_default (allow)
    let result = analyze_command(
        "some_tool --flag",
        &config,
        ExecContext {
            is_subagent: true,
            ..Default::default()
        },
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_alias_rewrite_produces_updated_input() {
    // Config with an alias: fdfind -> fd, and fd is allowed
    let config: Config = toml::from_str(
        r#"
        default = "passthrough"
        [[aliases]]
        from = "fdfind"
        to = "fd"
        [[rules]]
        commands = ["fd"]
        permission = "allow"
        reason = "file finder"
    "#,
    )
    .unwrap();

    // apply_aliases should rewrite "fdfind ." to "fd ."
    let rewritten = config.apply_aliases("fdfind .");
    assert_eq!(rewritten, Some("fd .".to_string()));

    // The rewritten command should be allowed
    let result = analyze_command("fd .", &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Allow);

    // emit_decision path: serialize_hook_output with updatedInput
    let json = serialize_hook_output(
        "allow",
        "file finder",
        Some(serde_json::json!({ "command": "fd ." })),
    )
    .expect("serialized");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["hookSpecificOutput"]["updatedInput"]["command"], "fd .");
}

#[test]
fn test_is_subagent_from_counter() {
    use crate::subagent_tracker;

    let session = "test-is-subagent-detection";
    let _ = std::fs::remove_file(format!("/tmp/claude/subagents/{}.count", session));

    // No active subagents → main thread
    assert!(!subagent_tracker::has_active_subagents(session));

    // Active subagent → subagent context
    subagent_tracker::increment(session);
    assert!(subagent_tracker::has_active_subagents(session));

    // Cleanup
    subagent_tracker::decrement(session);
    assert!(!subagent_tracker::has_active_subagents(session));
}

// source / . builtin integration tests

#[test]
fn test_source_allowed_file() {
    let config = test_config();
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "ls -la").unwrap();
    let path = f.path().to_str().unwrap().to_string();

    let cmd = format!("source {}", path);
    let result = analyze_command(&cmd, &config, ExecContext::default(), None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_source_dangerous_file() {
    let config = test_config();
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "rm -rf /").unwrap();
    let path = f.path().to_str().unwrap().to_string();

    let cmd = format!("source {}", path);
    let result = analyze_command(&cmd, &config, ExecContext::default(), None);
    // rm -rf / falls through to passthrough (not in allow list)
    assert!(matches!(
        result.permission,
        Permission::Ask | Permission::Deny | Permission::Passthrough
    ));
    assert_ne!(result.permission, Permission::Allow);
}
