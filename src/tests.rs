use crate::config::{Config, Permission};
use crate::{analyze_command, check_write_path};
use std::path::Path;

fn test_config() -> Config {
    Config::load(Path::new("config.default.toml")).expect("Failed to load test config")
}

#[test]
fn test_simple_allow() {
    let config = test_config();
    let result = analyze_command("ls -la", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pipeline() {
    let config = test_config();
    let result = analyze_command("ls | grep foo", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_dangerous_command() {
    let config = test_config();
    let result = analyze_command("rm -rf /", &config, false, None);
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_sudo_wrapper() {
    let config = test_config();
    let result = analyze_command("sudo ls", &config, false, None);
    // sudo unwraps to ls, which is allowed
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_stdbuf_wrapper() {
    let config = test_config();
    // stdbuf unwraps to ls, which is allowed
    let result = analyze_command("stdbuf -oL ls -la", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
    // stdbuf wrapping a denied command
    let result = analyze_command("stdbuf -oL sed -i 's/a/b/' file.txt", &config, false, None);
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_sudo_dangerous() {
    let config = test_config();
    let result = analyze_command("sudo rm -rf /", &config, false, None);
    // sudo unwraps to rm -rf /, which passes through
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_chain_with_dangerous() {
    let config = test_config();
    let result = analyze_command("ls && rm -rf /tmp", &config, false, None);
    // Most restrictive should be passthrough
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_env_dangerous() {
    let config = test_config();
    let result = analyze_command("env VAR=1 rm -rf /", &config, false, None);
    // env unwraps to rm -rf /, which passes through
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_var_assignment_safe() {
    let config = test_config();
    let result = analyze_command("VAR=1 ls -la", &config, false, None);
    // ls is allowed even with env var
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_git_suggestion() {
    let config = test_config();
    let result = analyze_command("git checkout main", &config, false, None);
    // Should have a suggestion
    assert!(result.suggestion.is_some());
}

#[test]
fn test_kubectl_exec_safe() {
    let config = test_config();
    let result = analyze_command("kubectl exec mypod -- ls -la", &config, false, None);
    // kubectl exec unwraps to ls -la, which is allowed
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_kubectl_exec_dangerous() {
    let config = test_config();
    let result = analyze_command(
        "kubectl exec -n prod mypod -- rm -rf /",
        &config,
        false,
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
        false,
        None,
    );
    // kubectl exec unwraps to env, which is allowed; grep is also allowed
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_kubectl_get_allowed() {
    let config = test_config();
    let result = analyze_command("kubectl get pods", &config, false, None);
    // kubectl get is allowed (not a wrapper, falls through to default)
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_sed_inline_allowed() {
    let config = test_config();
    let result = analyze_command("echo test | sed 's/t/x/'", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_sed_n_inline_allowed() {
    let config = test_config();
    let result = analyze_command("sed -n '5p' file.txt", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_sed_i_denied() {
    let config = test_config();
    let result = analyze_command("sed -i 's/foo/bar/' file.txt", &config, false, None);
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_sed_i_suffix_denied() {
    let config = test_config();
    // sed -i.bak is also in-place
    let result = analyze_command("sed -i.bak 's/foo/bar/' file.txt", &config, false, None);
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_awk_inline_allowed() {
    let config = test_config();
    let result = analyze_command("awk '{print $1}' file.txt", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_perl_inline_allowed() {
    let config = test_config();
    // perl -pe without -i is just a pipeline filter
    let result = analyze_command("echo test | perl -pe 's/foo/bar/'", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_perl_i_denied() {
    let config = test_config();
    let result = analyze_command("perl -i -pe 's/foo/bar/' file.txt", &config, false, None);
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_perl_pi_denied() {
    let config = test_config();
    // -pi combines -p and -i flags
    let result = analyze_command("perl -pi -e 's/foo/bar/' file.txt", &config, false, None);
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_perl_pie_denied() {
    let config = test_config();
    // -pie combines -p, -i, -e flags
    let result = analyze_command("perl -pie 's/foo/bar/' file.txt", &config, false, None);
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_help_always_allowed() {
    let config = test_config();
    // --help flag
    let result = analyze_command("someunknown --help", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
    // -h flag
    let result = analyze_command("kubectl delete -h", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
    // help subcommand
    let result = analyze_command("cargo help build", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_version_always_allowed() {
    let config = test_config();
    // --version flag
    let result = analyze_command("someunknown --version", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
    // -V flag
    let result = analyze_command("rustc -V", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
    // version subcommand
    let result = analyze_command("docker version", &config, false, None);
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
    let result = analyze_command("sudo ./target/release/myapp", &config, false, None);
    assert_eq!(result.permission, Permission::Passthrough);

    // With cd before sudo, should allow (cwd propagates through wrapper)
    let result = analyze_command(
        "cd /home/test/myproject && sudo ./target/release/myapp",
        &config,
        false,
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

// Write path tests
#[test]
fn test_write_tmp_blocked() {
    let result = check_write_path("/tmp/test.txt");
    assert!(result.is_some());
    let (decision, _) = result.unwrap();
    assert_eq!(decision, "block");
}

#[test]
fn test_write_tmp_subdir_blocked() {
    let result = check_write_path("/tmp/foo/bar.txt");
    assert!(result.is_some());
    let (decision, _) = result.unwrap();
    assert_eq!(decision, "block");
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
    let result = analyze_command("cd /tmp/claude && rm test", &config, false, Some("/"));
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_cd_root_then_rm_not_allowed() {
    // From cwd /tmp/claude, "cd / && rm test" should NOT be allowed
    let config = test_config();
    let result = analyze_command("cd / && rm test", &config, false, Some("/tmp/claude"));
    // Should passthrough (not allowed) because /test is not under /tmp/ or project
    assert_eq!(result.permission, Permission::Passthrough);
}

#[test]
fn test_rm_absolute_path_ignores_cd() {
    // From cwd /, "cd / && rm /tmp/test" should be allowed (absolute path)
    let config = test_config();
    let result = analyze_command("cd / && rm /tmp/test", &config, false, Some("/"));
    assert_eq!(result.permission, Permission::Allow);
}

// Piped query tests (echo 'SQL' | mysql)

#[test]
fn test_piped_select_allowed() {
    let config = test_config();
    let result = analyze_command("echo 'SELECT * FROM users' | mysql", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_piped_insert_asks() {
    let config = test_config();
    let result = analyze_command(
        "echo 'INSERT INTO users VALUES (1)' | mysql",
        &config,
        false,
        None,
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_piped_show_allowed() {
    let config = test_config();
    let result = analyze_command("echo 'SHOW DATABASES' | mariadb", &config, false, None);
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_piped_through_ssh_select_allowed() {
    let config = test_config();
    // Piped query through ssh wrapper
    let result = analyze_command(
        "echo 'SELECT 1' | ssh host 'mariadb -u user db'",
        &config,
        false,
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
        false,
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
        false,
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
        false,
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
        false,
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_nu_c_external_command() {
    let config = test_config();
    // nu -c with external command should check against rules
    let result = analyze_command("nu -c 'ls -la'", &config, false, None);
    // ls is allowed by config
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_nu_c_dangerous_builtin() {
    let config = test_config();
    // nu -c with rm should check against rules
    let result = analyze_command("nu -c 'rm ~/Documents/important.txt'", &config, false, None);
    // rm outside /tmp is dangerous
    assert_eq!(result.permission, Permission::Passthrough);
}

// docker compose exec tests (local vs remote)

#[test]
fn test_docker_compose_exec_local_allowed() {
    let config = test_config();
    let result = analyze_command("docker compose exec web bash", &config, false, None);
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
        false,
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
        false,
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}
