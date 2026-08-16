use super::*;

fn pyrun_result(code: &str, config: &Config) -> PermissionResult {
    analyze_pyrun_code(code, config, None, None, ExecContext::default())
}

fn pyrun_result_at(code: &str, config: &Config, cwd: &str, ctx: ExecContext) -> PermissionResult {
    analyze_pyrun_code(code, config, Some(cwd), Some(cwd), ctx)
}

fn pyrun_result_with_cwds(
    code: &str,
    config: &Config,
    virtual_cwd: &str,
    initial_cwd: &str,
) -> PermissionResult {
    analyze_pyrun_code(
        code,
        config,
        Some(virtual_cwd),
        Some(initial_cwd),
        ExecContext::default(),
    )
}

#[test]
fn test_handle_non_bash_tool_handles_claude_pyrun_eval() {
    let mut input = hook_input("mcp__pyrun__pyrun_eval");
    input.tool_input.code = Some("print(1 + 1)".to_string());
    assert!(handle_tool(&input, &Config::default(), false));
}

#[test]
fn test_pyrun_eval_read_only_code_is_allowed() {
    let result = pyrun_result("print(1 + 1)", &Config::default());
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_subprocess_asks() {
    let result = pyrun_result(
        "import subprocess; subprocess.run(['rm', '-rf', '/tmp/x'])",
        &Config::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_syntax_error_denies() {
    let result = pyrun_result("run.git(\"diff\"", &Config::default());
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_pyrun_eval_run_git_diff_allows() {
    let result = pyrun_result("run.git(\"diff\")", &Config::default());
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_run_rm_etc_asks() {
    let result = pyrun_result("run.rm(\"-rf\", \"/etc\")", &Config::default());
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_literal_run_command_allows() {
    let result = pyrun_result("run.command(\"git\", \"diff\")", &Config::default());
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_dynamic_command_asks() {
    let result = pyrun_result("run.command(program, \"diff\")", &Config::default());
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_unknown_command_asks() {
    let result = pyrun_result("run.not_a_real_command(\"value\")", &Config::default());
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_host_cd_invalidates_relative_path_context() {
    let result = pyrun_result_at(
        "host.cd(\"/etc\"); fs.write(\"passwd\", \"x\")",
        &Config::default(),
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_cli_relative_cwd_resolves_from_session_cwd() {
    let config: Config = toml::from_str(
        r#"
        default = "ask"
        ask_write_paths = ["/etc/*"]
        [[rules]]
        commands = ["rm"]
        permission = "allow"
        "#,
    )
    .expect("config");
    let result = pyrun_result_at(
        "cli.rm(\"passwd\").cwd(\"../../etc\").run()",
        &config,
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_cli_literal_cwd_reanalyzes_relative_command() {
    let result = pyrun_result_at(
        "cli.rm(\"passwd\").cwd(\"/etc\").run()",
        &Config::default(),
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_cli_literal_cwd_keeps_read_only_command_allowed() {
    let result = pyrun_result_at(
        "cli.git(\"diff\").cwd(\"/etc\").run()",
        &Config::default(),
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_cli_dynamic_cwd_asks() {
    let result = pyrun_result_at(
        "cli.rm(\"passwd\").cwd(directory).run()",
        &Config::default(),
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_cli_dynamic_in_cwd_asks() {
    let result = pyrun_result_at(
        "cli.rm(\"passwd\").in_(directory).run()",
        &Config::default(),
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_relative_builder_cwd_uses_virtual_session_cwd() {
    let config: Config = toml::from_str(
        r#"
        default = "ask"
        [[rules]]
        commands = ["rm"]
        permission = "allow"
        cwd = "/home/project/one/two"
        "#,
    )
    .expect("config");
    let result = pyrun_result_with_cwds(
        "cli.rm(\"passwd\").cwd(\"two\").run()",
        &config,
        "/home/project/one",
        "/home/project",
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_parent_dir_paths_ask() {
    let config: Config = toml::from_str(r#"default = "allow""#).expect("config");
    for code in [
        "fs.read(\"../result.txt\")",
        "fs.write(\"../result.txt\", \"x\")",
        "fs.remove(\"../result.txt\")",
        "cli.git(\"diff\").output(\"../result.txt\")",
        "cli.git(\"diff\").cwd(\"..\").run()",
    ] {
        let result = pyrun_result_at(code, &config, "/home/project", ExecContext::default());
        assert_eq!(result.permission, Permission::Ask, "{code}");
    }
}

#[test]
fn test_pyrun_eval_tilde_remove_asks() {
    let config: Config = toml::from_str(r#"default = "allow""#).expect("config");
    let result = pyrun_result_at(
        "fs.remove(\"~/.config/file\")",
        &config,
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[cfg(unix)]
#[test]
fn test_pyrun_eval_broken_symlink_paths_ask_without_mutation() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("tempdir");
    let project = root.path().join("project");
    std::fs::create_dir(&project).expect("project");
    let broken = project.join("broken");
    symlink("missing-target", &broken).expect("broken symlink");

    let child = broken.join("result.txt");
    let child_text = child.to_string_lossy();
    let broken_text = broken.to_string_lossy();
    let codes = [
        format!("fs.read({child_text:?})"),
        format!("fs.write({child_text:?}, \"x\")"),
        format!("fs.remove({child_text:?})"),
        format!("cli.git(\"diff\").output({child_text:?})"),
        format!("cli.git(\"diff\").cwd({broken_text:?}).run()"),
    ];
    for code in codes {
        let result = pyrun_result_at(
            &code,
            &Config::default(),
            project.to_str().expect("project path"),
            ExecContext::default(),
        );
        assert_eq!(result.permission, Permission::Ask, "{code}");
    }
    assert!(!project.join("result.txt").exists());
    assert!(!project.join("missing-target").join("result.txt").exists());
}

#[test]
fn test_pyrun_eval_dynamic_reserved_helper_access_asks() {
    for code in [
        "getattr(run, \"rm\")",
        "setattr(run, \"rm\", None)",
        "delattr(run, \"rm\")",
        "alias = run",
        "alias = run.rm",
    ] {
        let result = pyrun_result(code, &Config::default());
        assert_eq!(result.permission, Permission::Ask, "{code}");
    }
}

#[test]
fn test_pyrun_eval_command_result_assignment_stays_allowed() {
    let result = pyrun_result("result = run.git(\"diff\")", &Config::default());
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_reserved_helper_method_allowlist() {
    for code in [
        "rg(\"TODO\", \".\")",
        "rg.search(\"TODO\", \".\")",
        "rg.files(\"TODO\", \".\")",
        "rg.matches(\"TODO\", \".\")",
        "fd.find(\"*.rs\", \".\")",
        "fd.files(\".\")",
        "fd.dirs(\".\")",
        "text.replace_text(\"a\", \"a\", \"b\")",
        "seq.map([1, 2], lambda value: value)",
        "obj.get({}, \"key\")",
        "hr()",
    ] {
        let result = pyrun_result(code, &Config::default());
        assert_eq!(result.permission, Permission::Allow, "{code}");
    }

    for code in ["rg.remove(\"TODO\")", "fd.remove(\"*.rs\")", "hr.now()"] {
        let result = pyrun_result(code, &Config::default());
        assert_eq!(result.permission, Permission::Ask, "{code}");
    }
}

#[test]
fn test_pyrun_eval_normalizes_relative_write_paths() {
    let result = pyrun_result_at(
        "fs.write(\"../../etc/passwd\", \"x\")",
        &Config::default(),
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_output_uses_session_cwd_not_builder_cwd() {
    let config: Config = toml::from_str(
        r#"
        default = "allow"
        ask_write_paths = ["/home/project/*"]
        "#,
    )
    .expect("config");
    let result = pyrun_result_at(
        "cli.echo(\"x\").cwd(\"/tmp\").output(\"result.txt\").run()",
        &config,
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_tmp_parent_escape_is_not_auto_allowed() {
    let result = pyrun_result(
        "fs.write(\"/tmp/../home/outside.txt\", \"x\")",
        &Config::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_nonexistent_project_write_stays_allowed() {
    let result = pyrun_result_at(
        "fs.write(\"new/result.txt\", \"x\")",
        &Config::default(),
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_rebinding_reserved_helper_target_asks() {
    for code in [
        "rg = action; rg()",
        "fs.write = action",
        "obj = action; obj.get({}, \"key\")",
    ] {
        let result = pyrun_result(code, &Config::default());
        assert_eq!(result.permission, Permission::Ask, "{code}");
    }
}

#[test]
fn test_pyrun_eval_json_loaded_obj_shadow_allows_reported_read_only_shape() {
    let result = pyrun_result(
        r#"
import json
from pathlib import Path
root = Path("/tmp/example")
obj = json.loads(root.read_text())
args = obj.get("args", [])
output = obj.get("artifacts", {}).get("outputPath")
print(args, output)
"#,
        &Config::default(),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_json_loaded_obj_shadow_is_scope_and_order_aware() {
    let safe_then_unsafe = pyrun_result(
        r#"
import json
obj = json.loads("{}")
obj = action
obj.get("args")
"#,
        &Config::default(),
    );
    assert_eq!(safe_then_unsafe.permission, Permission::Ask);

    let safe_in_function = pyrun_result(
        r#"
import json
obj = json.loads("{}")
def inspect():
    obj.get("args").get("value")
inspect()
"#,
        &Config::default(),
    );
    assert_eq!(safe_in_function.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_unshadowed_obj_namespace_stays_allowed() {
    let result = pyrun_result("obj.get({}, \"key\")", &Config::default());
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_tilde_paths_ask() {
    for code in [
        "fs.read(\"~/.config/file\")",
        "fs.read(\"~user/file\")",
        "fs.write(\"~/.config/file\", \"x\")",
        "fs.write(\"~user/file\", \"x\")",
        "cli.git(\"diff\").output(\"~/.config/file\")",
        "cli.rm(\"passwd\").cwd(\"~\").run()",
        "cli.rm(\"passwd\").cwd(\"~user\").run()",
    ] {
        let result = pyrun_result_at(
            code,
            &Config::default(),
            "/home/project",
            ExecContext::default(),
        );
        assert_eq!(result.permission, Permission::Ask, "{code}");
    }
}

#[cfg(unix)]
#[test]
fn test_pyrun_eval_project_symlink_to_outside_does_not_auto_allow_write() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir_in("/var/tmp").expect("tempdir");
    let project = root.path().join("project");
    let outside = root.path().join("outside");
    std::fs::create_dir_all(&project).expect("project");
    std::fs::create_dir_all(&outside).expect("outside");
    symlink(&outside, project.join("link")).expect("symlink");

    let target = project.join("link").join("result.txt");
    let code = format!("fs.write({:?}, \"x\")", target.to_string_lossy());
    let result = pyrun_result_at(
        &code,
        &Config::default(),
        project.to_str().expect("project path"),
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_fs_write_respects_touch_command_policy() {
    let config: Config = toml::from_str(
        r#"
        default = "ask"
        [[rules]]
        commands = ["touch"]
        permission = "deny"
        "#,
    )
    .expect("config");
    let result = pyrun_result_at(
        "fs.write(\"result.txt\", \"x\")",
        &config,
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_pyrun_eval_output_path_respects_lexical_escape() {
    let config: Config = toml::from_str(r#"ask_write_paths = ["/etc/*"]"#).expect("config");
    let result = pyrun_result_at(
        "cli.git(\"diff\").output(\"../../etc/result.txt\")",
        &config,
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_run_command_honors_main_thread_default() {
    let config = config_with_main_thread_default("deny");
    let result = pyrun_result("run.git(\"diff\")", &config);
    assert_eq!(result.permission, Permission::Deny);
}

#[test]
fn test_pyrun_eval_dynamic_argument_asks() {
    let result = pyrun_result("run.git(argument)", &Config::default());
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_dynamic_attribute_asks() {
    let result = pyrun_result("run[program](\"diff\")", &Config::default());
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_known_builder_methods_preserve_command_allow() {
    let result = pyrun_result("cli.git(\"diff\").capture().run()", &Config::default());
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_tmp_write_allows() {
    let result = pyrun_result("fs.write(\"/tmp/result.txt\", \"ok\")", &Config::default());
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_protected_write_asks() {
    let config = ask_paths_config("/etc/*");
    let result = pyrun_result("fs.write(\"/etc/passwd\", \"x\")", &config);
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_protected_remove_asks() {
    let config = ask_paths_config("/etc/*");
    let result = pyrun_result("fs.remove(\"/etc/passwd\")", &config);
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_unknown_filesystem_method_asks() {
    let result = pyrun_result("fs.chmod(\"/tmp/file\", \"755\")", &Config::default());
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_safe_fs_read_allows() {
    let result = pyrun_result_at(
        "fs.read(\"README.md\")",
        &Config::default(),
        "/home/project",
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_pyrun_eval_protected_fs_read_asks() {
    let config = ask_paths_config("/etc/*");
    let result = pyrun_result("fs.read(\"/etc/passwd\")", &config);
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_cli_output_protected_path_asks() {
    let config: Config = toml::from_str(r#"ask_write_paths = ["/etc/*"]"#).expect("config");
    let result = pyrun_result("cli.git(\"diff\").output(\"/etc/result.txt\")", &config);
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_http_asks() {
    let result = pyrun_result("http.post(\"https://example.com\", {})", &Config::default());
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_tools_asks() {
    let result = pyrun_result("tools.ssh(\"host\", \"user\")", &Config::default());
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_pi_bridge_asks() {
    let result = pyrun_result("pi.tools.call(\"Bash\", {})", &Config::default());
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_selects_most_restrictive_call() {
    let config = ask_paths_config("/etc/*");
    let result = pyrun_result(
        "run.git(\"diff\"); http.post(\"https://example.com\", {}); fs.write(\"/etc/passwd\", \"x\")",
        &config,
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_deny_wins_over_ask() {
    let config: Config = toml::from_str(
        r#"
        default = "ask"
        [[rules]]
        commands = ["touch"]
        permission = "deny"
        "#,
    )
    .expect("config");
    let result = pyrun_result(
        "http.post(\"https://example.com\", {}); fs.write(\"/tmp/result\", \"x\")",
        &config,
    );
    assert_eq!(result.permission, Permission::Deny);
}
