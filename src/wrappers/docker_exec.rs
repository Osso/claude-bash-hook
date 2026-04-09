//! docker exec, docker compose exec, and docker compose run wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap docker exec, docker compose exec, or docker compose run command
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    if cmd.args.first().map(|s| s.as_str()) == Some("exec") {
        return unwrap_exec(&cmd.args[1..], "docker exec");
    }

    let compose_index = compose_subcommand_index(&cmd.args)?;
    match cmd.args.get(compose_index).map(|arg| arg.as_str()) {
        Some("exec") => unwrap_exec(&cmd.args[compose_index + 1..], "docker compose exec"),
        Some("run") => unwrap_compose_run(&cmd.args[compose_index + 1..]),
        _ => None,
    }
}

/// Unwrap exec-style commands: [OPTIONS] CONTAINER/SERVICE COMMAND [ARG...]
fn unwrap_exec(args: &[String], wrapper_name: &str) -> Option<UnwrapResult> {
    unwrap_after_target(
        args,
        &[
            "-e",
            "--env",
            "-u",
            "--user",
            "-w",
            "--workdir",
            "--env-file",
            "--index",
        ],
        wrapper_name,
    )
}

/// Unwrap docker compose run: [OPTIONS] SERVICE [COMMAND] [ARG...]
fn unwrap_compose_run(args: &[String]) -> Option<UnwrapResult> {
    unwrap_after_target(
        args,
        &[
            "-e",
            "--env",
            "-u",
            "--user",
            "-w",
            "--workdir",
            "--entrypoint",
            "-v",
            "--volume",
            "-p",
            "--publish",
            "--name",
            "-l",
            "--label",
        ],
        "docker compose run",
    )
}

fn compose_subcommand_index(args: &[String]) -> Option<usize> {
    if args.first().map(|arg| arg.as_str()) != Some("compose") {
        return None;
    }

    let mut index = 1;
    while index < args.len() && is_compose_option(&args[index]) {
        index += compose_option_step(&args[index]);
    }
    Some(index)
}

fn is_compose_option(arg: &str) -> bool {
    arg.starts_with('-')
}

fn compose_option_step(arg: &str) -> usize {
    if arg.contains('=') {
        1
    } else if matches!(
        arg,
        "-f" | "--file" | "-p" | "--project-name" | "--env-file"
    ) {
        2
    } else {
        1
    }
}

fn unwrap_after_target(
    args: &[String],
    opts_with_args: &[&str],
    wrapper_name: &str,
) -> Option<UnwrapResult> {
    let target_index = first_positional_index(args, opts_with_args)?;
    let inner_command = join_inner_command(&args[target_index + 1..]);

    Some(UnwrapResult {
        inner_command,
        host: None,
        wrapper: wrapper_name.to_string(),
    })
}

fn first_positional_index(args: &[String], opts_with_args: &[&str]) -> Option<usize> {
    let mut skip_next = false;

    for (index, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.contains('=') {
            continue;
        }
        if opts_with_args.iter().any(|opt| *opt == arg) {
            skip_next = true;
            continue;
        }
        if !arg.starts_with('-') {
            return Some(index);
        }
    }

    None
}

fn join_inner_command(args: &[String]) -> Option<String> {
    (!args.is_empty()).then(|| args.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_command;

    fn make_cmd(args: &[&str]) -> Command {
        make_command("docker", args)
    }

    // docker exec tests
    #[test]
    fn test_docker_exec_simple() {
        let cmd = make_cmd(&["exec", "mycontainer", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
        assert_eq!(result.wrapper, "docker exec");
    }

    #[test]
    fn test_docker_exec_with_options() {
        let cmd = make_cmd(&["exec", "-it", "-u", "root", "mycontainer", "bash"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("bash".to_string()));
    }

    #[test]
    fn test_docker_exec_with_env() {
        let cmd = make_cmd(&[
            "exec",
            "-e",
            "FOO=bar",
            "mycontainer",
            "cat",
            "/etc/nginx/nginx.conf",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(
            result.inner_command,
            Some("cat /etc/nginx/nginx.conf".to_string())
        );
    }

    #[test]
    fn test_docker_exec_with_workdir() {
        let cmd = make_cmd(&["exec", "-w", "/app", "mycontainer", "pwd"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("pwd".to_string()));
    }

    #[test]
    fn test_docker_exec_no_command() {
        let cmd = make_cmd(&["exec", "mycontainer"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, None);
    }

    // docker compose exec tests
    #[test]
    fn test_docker_compose_exec_simple() {
        let cmd = make_cmd(&["compose", "exec", "web", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
        assert_eq!(result.wrapper, "docker compose exec");
    }

    #[test]
    fn test_docker_compose_exec_with_options() {
        let cmd = make_cmd(&["compose", "exec", "-u", "root", "web", "bash"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("bash".to_string()));
    }

    // docker compose run tests
    #[test]
    fn test_docker_compose_run_simple() {
        let cmd = make_cmd(&["compose", "run", "web", "python", "manage.py", "migrate"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(
            result.inner_command,
            Some("python manage.py migrate".to_string())
        );
        assert_eq!(result.wrapper, "docker compose run");
    }

    #[test]
    fn test_docker_compose_run_with_file_flag() {
        let cmd = make_cmd(&[
            "compose",
            "-f",
            "docker-compose.test.yml",
            "run",
            "--rm",
            "test",
        ]);
        let result = unwrap(&cmd).unwrap();
        // No inner command - just runs the service's default command
        assert_eq!(result.inner_command, None);
        assert_eq!(result.wrapper, "docker compose run");
    }

    #[test]
    fn test_docker_compose_run_with_options() {
        let cmd = make_cmd(&["compose", "run", "--rm", "-e", "DEBUG=1", "web", "pytest"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("pytest".to_string()));
    }

    #[test]
    fn test_docker_compose_run_no_command() {
        let cmd = make_cmd(&["compose", "run", "web"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, None);
    }

    // Not a wrapper tests
    #[test]
    fn test_docker_run_not_wrapper() {
        let cmd = make_cmd(&["run", "ubuntu", "ls"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_docker_ps_not_wrapper() {
        let cmd = make_cmd(&["ps"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_docker_compose_ps_not_wrapper() {
        let cmd = make_cmd(&["compose", "ps"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }
}
