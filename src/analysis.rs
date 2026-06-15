//! Command analysis — parse and evaluate bash/nushell commands against permission rules.

use crate::analyzer;
use crate::cargo;
use crate::config::{Config, ExecContext, Permission, PermissionResult};
use crate::curl;
use crate::docker;
use crate::git;
use crate::kill;
use crate::magick;
use crate::nushell;
use crate::redis;
use crate::rm;
use crate::scripts;
use crate::sql;
use crate::tar;
use crate::tee;
use crate::wrappers;

/// Analyze a command and return the most restrictive permission
pub fn analyze_command(
    command: &str,
    config: &Config,
    ctx: ExecContext,
    initial_cwd: Option<&str>,
) -> PermissionResult {
    analyze_with_piped_query(command, config, ctx, initial_cwd, None, false, 0)
}

/// Analyze a bash command with optional piped query context
pub fn analyze_with_piped_query(
    command: &str,
    config: &Config,
    ctx: ExecContext,
    initial_cwd: Option<&str>,
    outer_piped_query: Option<&str>,
    is_remote: bool,
    depth: u32,
) -> PermissionResult {
    let analysis = analyzer::analyze(command);
    if let Some(result) = check_analysis_errors(&analysis) {
        return result;
    }

    let has_uncertain_flow = detect_uncertain_flow(command);
    let mut virtual_cwd: Option<String> = initial_cwd.map(String::from);
    let mut most_restrictive: Option<PermissionResult> = None;
    let mut prev_cmd: Option<&analyzer::Command> = None;

    for cmd in &analysis.commands {
        let local_piped_query = extract_piped_query(prev_cmd);
        let piped_query = local_piped_query.as_deref().or(outer_piped_query);
        let result = check_single_command(
            cmd,
            config,
            ctx,
            virtual_cwd.as_deref(),
            initial_cwd,
            has_uncertain_flow,
            piped_query,
            Some(command),
            is_remote,
            depth,
        );
        most_restrictive = Some(merge_restrictive(most_restrictive, result));
        update_virtual_cwd(&mut virtual_cwd, cmd, has_uncertain_flow);
        prev_cmd = Some(cmd);
    }

    allow_in_bypass(most_restrictive.unwrap_or_else(default_allow), ctx)
}

/// Analyze a nushell command and return the most restrictive permission
pub fn analyze_nushell_command(
    command: &str,
    config: &Config,
    ctx: ExecContext,
    cwd: Option<&str>,
) -> PermissionResult {
    let analysis = nushell::analyze(command);

    if !analysis.success {
        return PermissionResult {
            permission: Permission::Deny,
            reason: format!(
                "Nushell syntax error: {}",
                analysis.error.unwrap_or_default()
            ),
            suggestion: Some("Fix the syntax error and try again".to_string()),
        };
    }

    if analysis.commands.is_empty() {
        return PermissionResult {
            permission: Permission::Allow,
            reason: "Nushell builtins only".to_string(),
            suggestion: None,
        };
    }

    let mut most_restrictive: Option<PermissionResult> = None;
    for cmd in &analysis.commands {
        let result = check_single_command(cmd, config, ctx, cwd, cwd, false, None, None, false, 0);
        most_restrictive = Some(merge_restrictive(most_restrictive, result));
    }

    allow_in_bypass(most_restrictive.unwrap_or_else(default_allow), ctx)
}

fn check_analysis_errors(analysis: &analyzer::AnalysisResult) -> Option<PermissionResult> {
    if !analysis.success {
        return Some(PermissionResult {
            permission: Permission::Deny,
            reason: format!(
                "Bash syntax error: {}",
                analysis.error.as_deref().unwrap_or_default()
            ),
            suggestion: Some("Fix the syntax error and try again".to_string()),
        });
    }
    if analysis.commands.is_empty() {
        return Some(PermissionResult {
            permission: Permission::Allow,
            reason: "No commands found".to_string(),
            suggestion: None,
        });
    }
    None
}

fn default_allow() -> PermissionResult {
    PermissionResult {
        permission: Permission::Allow,
        reason: String::new(),
        suggestion: None,
    }
}

fn detect_uncertain_flow(command: &str) -> bool {
    command.contains(" || ")
        || command.contains("if ")
        || command.contains("case ")
        || command.contains("while ")
        || command.contains("for ")
        || command.contains("until ")
}

fn merge_restrictive(prev: Option<PermissionResult>, result: PermissionResult) -> PermissionResult {
    match prev {
        None => result,
        Some(prev) if result.permission > prev.permission => result,
        Some(prev) => prev,
    }
}

fn update_virtual_cwd(
    virtual_cwd: &mut Option<String>,
    cmd: &analyzer::Command,
    has_uncertain_flow: bool,
) {
    if !has_uncertain_flow && cmd.name == "cd" {
        if let Some(dir) = cmd.args.first() {
            *virtual_cwd = Some(dir.clone());
        }
    }
}

fn extract_piped_query(prev_cmd: Option<&analyzer::Command>) -> Option<String> {
    let prev = prev_cmd?;
    if prev.name != "echo" && prev.name != "printf" {
        return None;
    }
    if prev.args.is_empty() {
        return None;
    }
    Some(prev.args.join(" "))
}

/// Check a single command, handling wrappers recursively
fn check_single_command(
    cmd: &analyzer::Command,
    config: &Config,
    ctx: ExecContext,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    has_uncertain_flow: bool,
    piped_query: Option<&str>,
    full_command: Option<&str>,
    is_remote: bool,
    depth: u32,
) -> PermissionResult {
    if let Some(result) = check_docker_compose(cmd, is_remote) {
        return result;
    }
    if let Some(result) =
        check_wrapper(cmd, config, ctx, virtual_cwd, piped_query, is_remote, depth)
    {
        return result;
    }
    if !is_remote && let Some(result) = check_inplace_edit(cmd) {
        return result;
    }
    if let Some(result) = check_cwd_rules(cmd, config, ctx, virtual_cwd, initial_cwd, is_remote) {
        return result;
    }
    if let Some(result) = check_database(cmd, config, piped_query) {
        return result;
    }
    if let Some(result) = check_scripting(cmd, config, ctx, virtual_cwd, initial_cwd, full_command)
    {
        return result;
    }
    if let Some(result) = check_git_special(cmd, config, initial_cwd) {
        return result;
    }
    if let Some(result) =
        check_filesystem(cmd, config, virtual_cwd, initial_cwd, has_uncertain_flow)
    {
        return result;
    }
    if let Some(result) = check_misc(cmd, config, ctx, virtual_cwd, initial_cwd) {
        return result;
    }
    config.check_command_with_cwd(&cmd.name, &cmd.args, initial_cwd, ctx)
}

fn check_docker_compose(cmd: &analyzer::Command, is_remote: bool) -> Option<PermissionResult> {
    if cmd.name != "docker" || cmd.args.first().map(|s| s.as_str()) != Some("compose") {
        return None;
    }
    if let Some(result) = docker::check_docker_compose_exec(cmd, is_remote) {
        return Some(result);
    }
    docker::check_docker_compose_run(cmd)
}

fn check_wrapper(
    cmd: &analyzer::Command,
    config: &Config,
    ctx: ExecContext,
    virtual_cwd: Option<&str>,
    piped_query: Option<&str>,
    is_remote: bool,
    depth: u32,
) -> Option<PermissionResult> {
    let unwrap_result = wrappers::unwrap_command(cmd, config, depth)?;
    let host = unwrap_result.host.as_deref();

    if let Some(inner) = unwrap_result.inner_command.as_deref() {
        return Some(check_wrapper_inner_command(
            cmd,
            config,
            ctx,
            virtual_cwd,
            piped_query,
            is_remote,
            depth,
            inner,
            &unwrap_result.wrapper,
            host,
        ));
    }

    host.map(|_| wrapper_host_result(cmd, config, host, ctx))
}

fn check_wrapper_inner_command(
    cmd: &analyzer::Command,
    config: &Config,
    ctx: ExecContext,
    virtual_cwd: Option<&str>,
    piped_query: Option<&str>,
    is_remote: bool,
    depth: u32,
    inner: &str,
    wrapper: &str,
    host: Option<&str>,
) -> PermissionResult {
    if let Some(host) = host {
        if config.host_skips_inner(&cmd.name, &cmd.args, host) {
            return wrapper_host_result(cmd, config, Some(host), ctx);
        }
    }
    let inner_result = analyze_wrapper_inner(
        inner,
        wrapper,
        config,
        ctx,
        virtual_cwd,
        piped_query,
        is_remote,
        host.is_some(),
        depth,
    );
    let Some(_) = host else {
        return inner_result;
    };
    let host_result = wrapper_host_result(cmd, config, host, ctx);
    more_restrictive_result(inner_result, host_result)
}

fn analyze_wrapper_inner(
    inner: &str,
    wrapper: &str,
    config: &Config,
    ctx: ExecContext,
    virtual_cwd: Option<&str>,
    piped_query: Option<&str>,
    is_remote: bool,
    has_host: bool,
    depth: u32,
) -> PermissionResult {
    if wrapper == "nu" {
        return analyze_nushell_command(inner, config, ctx, virtual_cwd);
    }
    analyze_with_piped_query(
        inner,
        config,
        ctx,
        virtual_cwd,
        piped_query,
        is_remote || has_host,
        wrapper_depth(wrapper, depth),
    )
}

fn wrapper_depth(wrapper: &str, depth: u32) -> u32 {
    if matches!(wrapper, "source" | ".") {
        // Increment depth when re-analyzing sourced file contents to prevent recursion
        return depth + 1;
    }
    depth
}

fn wrapper_host_result(
    cmd: &analyzer::Command,
    config: &Config,
    host: Option<&str>,
    ctx: ExecContext,
) -> PermissionResult {
    config.check_command_with_host(&cmd.name, &cmd.args, host, ctx)
}

fn more_restrictive_result(
    inner_result: PermissionResult,
    host_result: PermissionResult,
) -> PermissionResult {
    if host_result.permission > inner_result.permission {
        host_result
    } else {
        inner_result
    }
}

fn check_inplace_edit(cmd: &analyzer::Command) -> Option<PermissionResult> {
    if cmd.name == "sed" && cmd.args.iter().any(|a| a == "-i" || a.starts_with("-i")) {
        return Some(PermissionResult {
            permission: Permission::Deny,
            reason: "sed -i modifies files; use Edit tool or mcp__regex-replace__regex_replace"
                .to_string(),
            suggestion: None,
        });
    }
    if cmd.name == "perl"
        && cmd
            .args
            .iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('i'))
    {
        return Some(PermissionResult {
            permission: Permission::Deny,
            reason: "perl -i modifies files; use Edit tool or mcp__regex-replace__regex_replace"
                .to_string(),
            suggestion: None,
        });
    }
    None
}

fn check_cwd_rules(
    cmd: &analyzer::Command,
    config: &Config,
    ctx: ExecContext,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    is_remote: bool,
) -> Option<PermissionResult> {
    if is_remote {
        return None;
    }
    let cwd_result = config.check_command_with_cwd(&cmd.name, &cmd.args, virtual_cwd, ctx);
    if cwd_result.permission == Permission::Allow {
        return Some(cwd_result);
    }
    if initial_cwd != virtual_cwd {
        let cwd_result = config.check_command_with_cwd(&cmd.name, &cmd.args, initial_cwd, ctx);
        if cwd_result.permission == Permission::Allow {
            return Some(cwd_result);
        }
    }
    None
}

fn check_database(
    cmd: &analyzer::Command,
    config: &Config,
    piped_query: Option<&str>,
) -> Option<PermissionResult> {
    if config.is_mysql_alias(&cmd.name) {
        return check_database_query(sql::check_mysql_query(cmd), piped_query);
    }
    if cmd.name == "sqlite3" {
        return check_database_query(sql::check_sqlite3_query(cmd), piped_query);
    }
    if cmd.name == "clickhouse-client" {
        return check_database_query(sql::check_clickhouse_query(cmd), piped_query);
    }
    if cmd
        .args
        .first()
        .is_some_and(|sub| config.is_positional_sql_command(&cmd.name, sub))
    {
        return check_database_query(sql::check_positional_sql_query(cmd), piped_query);
    }
    if cmd.name == "redis-cli" || cmd.name == "valkey-cli" {
        return redis::check_redis_cli(cmd);
    }
    None
}

fn check_scripting(
    cmd: &analyzer::Command,
    config: &Config,
    ctx: ExecContext,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    full_command: Option<&str>,
) -> Option<PermissionResult> {
    let result = check_scripting_inner(cmd, config, ctx, virtual_cwd, initial_cwd, full_command)?;
    Some(result)
}

/// In bypass mode, downgrade any ask/deny verdict to allow.
fn allow_in_bypass(mut result: PermissionResult, ctx: ExecContext) -> PermissionResult {
    if ctx.bypass && result.permission != Permission::Allow {
        result.permission = Permission::Allow;
        result.reason = format!("bypassPermissions: {}", result.reason);
    }
    result
}

fn check_scripting_inner(
    cmd: &analyzer::Command,
    config: &Config,
    ctx: ExecContext,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    full_command: Option<&str>,
) -> Option<PermissionResult> {
    if cmd.name == "php" {
        if let Some(result) = scripts::php::check_php_script(cmd) {
            return Some(result);
        }
    }
    if cmd.name == "lua" || cmd.name == "luajit" {
        if let Some(result) = scripts::lua::check_lua_script(cmd) {
            return Some(result);
        }
    }
    if cmd.name.starts_with("python") {
        if let Some(result) = scripts::python::check_python_script(cmd, full_command, initial_cwd) {
            return Some(result);
        }
        if let Some(result) =
            scripts::check_interpreter_script(cmd, config, virtual_cwd, initial_cwd, ctx)
        {
            return Some(result);
        }
    }
    None
}

fn check_git_special(
    cmd: &analyzer::Command,
    config: &Config,
    initial_cwd: Option<&str>,
) -> Option<PermissionResult> {
    if cmd.name != "git" {
        return None;
    }
    if let Some(result) = git::check_git_dangling_config(cmd) {
        return Some(result);
    }
    let subcmd = cmd.args.first().map(|s| s.as_str())?;
    match subcmd {
        "push" => git::check_git_push(cmd, config, initial_cwd),
        "checkout" => git::check_git_checkout(cmd),
        "reset" => git::check_git_reset(cmd),
        _ => None,
    }
}

fn check_filesystem(
    cmd: &analyzer::Command,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    has_uncertain_flow: bool,
) -> Option<PermissionResult> {
    if cmd.name == "docker" && cmd.args.first().map(|s| s.as_str()) == Some("run") {
        return docker::check_docker_run(cmd);
    }
    if cmd.name == "rm" {
        return rm::check_rm(cmd, config, virtual_cwd, initial_cwd);
    }
    if cmd.name == "kill" {
        return kill::check_kill(cmd);
    }
    if cmd.name == "tee" {
        return tee::check_tee(cmd, initial_cwd);
    }
    if cmd.name == "tar" {
        return tar::check_tar(cmd, virtual_cwd, has_uncertain_flow);
    }
    None
}

fn check_misc(
    cmd: &analyzer::Command,
    config: &Config,
    ctx: ExecContext,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
) -> Option<PermissionResult> {
    allow_magick_info(cmd)
        .or_else(|| magick::check_magick(cmd))
        .or_else(|| allow_curl(cmd, config, ctx))
        .or_else(|| allow_help_request(cmd))
        .or_else(|| allow_version_request(cmd))
        .or_else(|| allow_tmp_script(cmd))
        .or_else(|| cargo::check_target_binary(cmd, virtual_cwd, initial_cwd))
        .or_else(|| allow_virtual_cwd_match(cmd, config, ctx, virtual_cwd, initial_cwd))
}

fn check_database_query(
    direct_result: Option<PermissionResult>,
    piped_query: Option<&str>,
) -> Option<PermissionResult> {
    direct_result.or_else(|| piped_query.map(sql::check_piped_query))
}

fn allow_magick_info(cmd: &analyzer::Command) -> Option<PermissionResult> {
    (cmd.name == "magick" && cmd.args.last().is_some_and(|arg| arg == "info:"))
        .then(|| allow_reason("magick with info: output"))
}

fn allow_curl(
    cmd: &analyzer::Command,
    config: &Config,
    ctx: ExecContext,
) -> Option<PermissionResult> {
    (cmd.name == "curl")
        .then(|| curl::check_curl(cmd, config, ctx))
        .flatten()
}

fn allow_help_request(cmd: &analyzer::Command) -> Option<PermissionResult> {
    has_any_arg(cmd, &["--help", "-h", "help"]).then(|| allow_reason("help request"))
}

fn allow_version_request(cmd: &analyzer::Command) -> Option<PermissionResult> {
    has_any_arg(cmd, &["--version", "-V", "version"]).then(|| allow_reason("version check"))
}

fn allow_tmp_script(cmd: &analyzer::Command) -> Option<PermissionResult> {
    cmd.name
        .starts_with("/tmp/")
        .then(|| allow_reason("script in /tmp"))
}

fn allow_virtual_cwd_match(
    cmd: &analyzer::Command,
    config: &Config,
    ctx: ExecContext,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
) -> Option<PermissionResult> {
    let cwd = virtual_cwd?;
    if Some(cwd) == initial_cwd {
        return None;
    }

    let result = config.check_command_with_cwd(&cmd.name, &cmd.args, Some(cwd), ctx);
    (result.permission == Permission::Allow).then_some(result)
}

fn has_any_arg(cmd: &analyzer::Command, needles: &[&str]) -> bool {
    cmd.args
        .iter()
        .any(|arg| needles.iter().any(|needle| arg == needle))
}

fn allow_reason(reason: &str) -> PermissionResult {
    PermissionResult {
        permission: Permission::Allow,
        reason: reason.to_string(),
        suggestion: None,
    }
}
