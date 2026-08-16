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
fn test_pyrun_eval_reported_static_variable_cwd_allows() {
    let code = "repo='/syncthing/Sync/Projects/globalcomix/cdc-mysql8'\nr=cli.cargo('test','--locked','child_run_id_bounds_the_failed_resync_table_without_losing_determinism').cwd(repo).capture().run()\nprint('exit',r.exit_code)\nprint(r.stdout[-12000:])\nprint(r.stderr[-12000:])";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Allow, "{}", result.reason);
}

#[test]
fn test_pyrun_eval_reassigned_static_variable_cwd_asks() {
    let code = "repo='/tmp/project'\nrepo=choose_repo()\ncli.git('diff').cwd(repo).run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_static_variable_cwd_alias_asks() {
    let code = "repo='/tmp/project'\nalias=repo\ncli.git('diff').cwd(alias).run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_static_variable_in_cwd_allows() {
    let code =
        "repo='/syncthing/Sync/Projects/claude/claude-bash-hook'\ncli.git('diff').in_(repo).run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Allow, "{}", result.reason);
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
fn test_pyrun_eval_reported_local_text_shadow_allows_read_only_scan() {
    let code = r#"
import json
from pathlib import Path
roots=[
Path('/home/osso/.config/pi/agent/detached-jobs/2026-08-15T19-25-34-015Z_01a006e2-fbbf-7ebf-9240-16bc85b4173a'),
Path('/home/osso/.config/pi/agent/sessions/--syncthing-Sync-Projects-globalcomix-cdc-mysql8--/detached-jobs/2026-08-15T19-25-34-015Z_01a006e2-fbbf-7ebf-9240-16bc85b4173a')]
for root in roots:
 if not root.exists(): continue
 for p in root.rglob('launch.json'):
  try: obj=json.loads(p.read_text())
  except: continue
  args=obj.get('args',[]); text=' '.join(map(str,args))
  if 'deploy.sh' in text and ('IMAGE_REPO' in text or text.strip().endswith('deploy.sh')):
   print(p); print(args); print(obj.get('cwd'))
"#;

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Allow, "{}", result.reason);
}

#[test]
fn test_pyrun_eval_local_text_shadow_remains_fail_closed() {
    for code in [
        "text = build_text()\ntext.strip()",
        "text = ' '.join(['safe'])\ntext = action\ntext.strip()",
        "text = ' '.join(['safe'])\ntext.__class__.__subclasses__()",
        "text = other\ntext.endswith('safe')",
    ] {
        let result = pyrun_result(code, &Config::default());
        assert_eq!(result.permission, Permission::Ask, "{code}");
    }
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
fn test_pyrun_eval_reported_static_mysql_query_variable_allows() {
    let code = r#"import json
job='mariadb-mysql-cdc-resync-stream-20260813'
r=cli.kubectl('get','job',job,'-n','ops','-o','json').capture().run(); d=json.loads(r.stdout); print(json.dumps({'active':d.get('status',{}).get('active',0),'succeeded':d.get('status',{}).get('succeeded',0),'failed':d.get('status',{}).get('failed',0),'conditions':d.get('status',{}).get('conditions',[])},indent=2))
q="SELECT status,COUNT(*) FROM cdc.table_sync_runs WHERE run_id LIKE 'resync-stream:globalcomix-prod-mariadb-resync-2026-08-13-%' GROUP BY status ORDER BY status; SELECT run_id,table_name,status,rows_scanned,total_rows,inserts_applied,updates_applied,extra_target_rows,last_primary_key_json,LEFT(last_error, 200),updated_at FROM cdc.table_sync_runs WHERE run_id LIKE 'resync-stream:globalcomix-prod-mariadb-resync-2026-08-13-%' AND status <> 'complete' ORDER BY updated_at DESC,table_name;"
r=cli.command('/home/osso/.cargo/bin/mysql-gc','-s','do-managed','-N','-B','-e',q).capture().run(); print(r.stdout); print(r.stderr)"#;

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Allow, "{}", result.reason);
}

#[test]
fn test_pyrun_eval_reported_kubectl_resource_name_flow_allows() {
    let code = r#"pod=cli.kubectl('get','pods','-n','ops','-l','job-name=mariadb-mysql-cdc-resync-stream-20260813','-o','jsonpath={.items[0].metadata.name}').capture().run().stdout.strip()
r=cli.kubectl('logs','-n','ops',pod,'--since=15m','--timestamps=true').capture().run(); print('\n'.join(r.stdout.splitlines()[-120:])); print(r.stderr)
r=cli.kubectl('top','pod','-n','ops',pod).capture().run(); print(r.stdout); print(r.stderr)"#;

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Allow, "{}", result.reason);
}

#[test]
fn test_pyrun_eval_reported_kubectl_wait_allows() {
    let code = "r=cli.kubectl('wait','--for=condition=complete','job/mariadb-mysql-cdc-resync-stream-20260813','-n','ops','--timeout=480s').capture().run()\nprint('exit',r.exit_code)\nprint(r.stdout)\nprint(r.stderr)";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Allow, "{}", result.reason);
}

#[test]
fn test_pyrun_eval_reported_literal_loop_command_splat_allows() {
    let code = r#"for args in [
 ('describe','job','mariadb-mysql-cdc-resync-stream-20260813','-n','ops'),
 ('get','events','-n','ops','--field-selector','involvedObject.name=mariadb-mysql-cdc-resync-stream-20260813','--sort-by=.lastTimestamp'),
 ('get','pods','-n','ops','-l','job-name=mariadb-mysql-cdc-resync-stream-20260813','-o','json'),
]:
 r=cli.kubectl(*args).capture().run(); print('\n===',' '.join(args),'===\n',r.stdout,r.stderr)"#;

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Allow, "{}", result.reason);
}

#[test]
fn test_pyrun_eval_reported_static_loop_collection_allows() {
    let code = r#"import json
cmds=[
 ('get','kustomization','infra-ops','-n','flux-system','-o','json'),
 ('get','deployment','mariadb-mysql-cdc-stream','-n','ops','-o','json'),
 ('get','job','mariadb-mysql-cdc-resync-stream-20260813','-n','ops','-o','json'),
 ('get','pods','-n','ops','-l','app in (mariadb-mysql-cdc-stream,mariadb-mysql-cdc-resync-stream)','-o','json'),
]
for args in cmds:
 r=cli.kubectl(*args).capture().run(); print('CMD',args,'RC',r.returncode); print(r.stdout[:12000]); print(r.stderr[:2000])"#;

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Allow, "{}", result.reason);
}

#[test]
fn test_pyrun_eval_static_loop_collection_remains_fail_closed() {
    for code in [
        "cmds = command_arguments()\nfor args in cmds:\n    cli.kubectl(*args).run()",
        "cmds = [('get', 'pods')]\ncmds = command_arguments()\nfor args in cmds:\n    cli.kubectl(*args).run()",
        "cmds = [('get', 'pods')]\ncmds = [('get', 'deployments')]\nfor args in cmds:\n    cli.kubectl(*args).run()",
        "cmds = [('get', 'pods')]\ncmds += [('get', 'deployments')]\nfor args in cmds:\n    cli.kubectl(*args).run()",
        "cmds = [('get', 'pods')]\nalias = cmds\nfor args in alias:\n    cli.kubectl(*args).run()",
        "cmds = [('get', resource)]\nfor args in cmds:\n    cli.kubectl(*args).run()",
    ] {
        let result = pyrun_result(code, &Config::default());
        assert_eq!(result.permission, Permission::Ask, "{code}");
    }
}

#[test]
fn test_pyrun_eval_static_loop_collection_mutation_asks() {
    for code in [
        "cmds = [('get', 'pods')]\ncmds.append(('delete', 'pod', 'target'))\nfor args in cmds:\n    cli.kubectl(*args).run()",
        "cmds = [('get', 'pods')]\ncmds[0] = ('delete', 'pod', 'target')\nfor args in cmds:\n    cli.kubectl(*args).run()",
        "cmds = [('get', 'pods')]\nmutate(cmds)\nfor args in cmds:\n    cli.kubectl(*args).run()",
        "cmds = [('get', 'pods')]\nfor args in cmds:\n    cmds.append(('delete', 'pod', 'target'))\n    cli.kubectl(*args).run()",
    ] {
        let result = pyrun_result(code, &Config::default());
        assert_eq!(result.permission, Permission::Ask, "{code}");
    }
}

#[test]
fn test_pyrun_eval_static_loop_collection_preserves_command_policy() {
    let code = "cmds = [('get', 'pods'), ('delete', 'pod', 'target')]\nfor args in cmds:\n    cli.kubectl(*args).run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_static_loop_collection_limits_ask() {
    let commands = (0..33)
        .map(|index| format!("('get', 'pod', 'pod-{index}')"))
        .collect::<Vec<_>>()
        .join(",\n");
    let too_many_iterations =
        format!("cmds = [{commands}]\nfor args in cmds:\n    cli.kubectl(*args).run()");

    let mut arguments = vec!["'get'".to_string()];
    arguments.extend((0..64).map(|index| format!("'value-{index}'")));
    let arguments = arguments.join(", ");
    let too_many_arguments =
        format!("cmds = [({arguments})]\nfor args in cmds:\n    cli.kubectl(*args).run()");

    for code in [too_many_iterations, too_many_arguments] {
        let result = pyrun_result(&code, &Config::default());
        assert_eq!(result.permission, Permission::Ask, "{code}");
    }
}

#[test]
fn test_pyrun_eval_unknown_loop_command_splat_asks() {
    let code = "for args in command_arguments():\n    cli.kubectl(*args).run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_reported_static_command_name_with_loop_splat_allows() {
    let config: Config = toml::from_str(
        r#"
        default = "ask"
        [[rules]]
        commands = ["groundcover-cli logs", "groundcover-cli events", "groundcover-cli issues"]
        permission = "allow"
        "#,
    )
    .expect("config");
    let code = r#"cmd='/home/osso/.cargo/bin/groundcover-cli'
for args in [
 ('logs','-s','30m','--namespace','ops','-w','mariadb-mysql-cdc-resync-stream-20260813','-n','200'),
 ('events','-s','30m','--namespace','ops','-n','100'),
 ('issues','-s','30m','-w','mariadb-mysql-cdc-resync-stream-20260813','-n','100')]:
 r=cli.command(cmd,*args).capture().run(); print('\n===',' '.join(args),'exit',r.exit_code,'===\n',r.stdout[-30000:],r.stderr[-2000:])"#;

    let result = pyrun_result(code, &config);

    assert_eq!(result.permission, Permission::Allow, "{}", result.reason);
}

#[test]
fn test_pyrun_eval_reassigned_static_command_name_asks() {
    let code = "cmd = 'git'\ncmd = choose_command()\ncli.command(cmd, 'diff').run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_static_command_name_alias_asks() {
    let code = "cmd = 'git'\nalias = cmd\ncli.command(alias, 'diff').run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_static_command_name_preserves_command_policy() {
    let code = "cmd = 'rm'\ncli.command(cmd, '-rf', '/etc').run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_computed_literal_loop_member_asks() {
    let code = "for args in [('get', resource)]:\n    cli.kubectl(*args).run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_literal_loop_splat_preserves_command_policy() {
    let code =
        "for args in [('get', 'pods'), ('delete', 'pod', 'target')]:\n    cli.kubectl(*args).run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_mixed_literal_and_splat_arguments_ask() {
    let code = "for args in [('pods',)]:\n    cli.kubectl('get', *args).run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_reassigned_literal_loop_splat_asks() {
    let code = "for args in [('get', 'pods')]:\n    args = command_arguments()\n    cli.kubectl(*args).run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_static_prod_rw_select_variable_allows() {
    let code =
        "q = 'SELECT 1'\nr = cli.command('mysql-gc', '-s', 'prod-rw', '-e', q).capture().run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Allow, "{}", result.reason);
}

#[test]
fn test_pyrun_eval_reassigned_static_prod_rw_query_asks() {
    let code = "q = 'SELECT 1'\nq = build_query()\nr = cli.command('mysql-gc', '-s', 'prod-rw', '-e', q).capture().run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_static_prod_rw_write_variable_asks() {
    let code = "q = 'DELETE FROM users'\nr = cli.command('mysql-gc', '-s', 'prod-rw', '-e', q).capture().run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_conditional_reassignment_invalidates_static_argument() {
    let code = "q = 'SELECT 1'\nif should_write:\n    q = 'DELETE FROM users'\nr = cli.command('mysql-gc', '-s', 'prod-rw', '-e', q).capture().run()";

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_untrusted_kubectl_resource_name_asks() {
    let result = pyrun_result("cli.kubectl('logs', pod).run()", &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_kubectl_resource_name_cannot_select_subcommand() {
    let code = r#"pod=cli.kubectl('get','pods','-o','jsonpath={.items[0].metadata.name}').capture().run().stdout.strip()
cli.kubectl(pod, 'pods').run()"#;

    let result = pyrun_result(code, &Config::default());

    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn test_pyrun_eval_reassigned_kubectl_resource_name_asks() {
    let code = r#"pod=cli.kubectl('get','pods','-o','jsonpath={.items[0].metadata.name}').capture().run().stdout.strip()
pod=choose_pod()
cli.kubectl('logs', pod).run()"#;

    let result = pyrun_result(code, &Config::default());

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
