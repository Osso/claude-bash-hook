//! xargs wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap xargs command
/// xargs [options] [command [args...]]
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let opts_with_args = [
        "-I",
        "--replace",
        "-n",
        "--max-args",
        "-P",
        "--max-procs",
        "-L",
        "--max-lines",
        "-s",
        "--max-chars",
        "-d",
        "--delimiter",
        "-a",
        "--arg-file",
        "-E",
    ];
    let inner_parts = collect_xargs_command(&cmd.args, &opts_with_args);
    if inner_parts.is_empty() {
        return Some(UnwrapResult {
            inner_command: Some("echo".to_string()),
            host: None,
            wrapper: "xargs".to_string(),
        });
    }

    Some(UnwrapResult {
        inner_command: Some(inner_parts.join(" ")),
        host: None,
        wrapper: "xargs".to_string(),
    })
}

fn collect_xargs_command(args: &[String], opts_with_args: &[&str]) -> Vec<String> {
    let mut skip_next = false;
    let mut inner_parts = Vec::new();

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if !inner_parts.is_empty() {
            inner_parts.push(arg.clone());
            continue;
        }
        if arg.contains('=') {
            continue;
        }
        if opts_with_args.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        inner_parts.push(arg.clone());
    }

    inner_parts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "xargs".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_xargs_simple() {
        let cmd = make_cmd(&["grep", "-l", "pattern"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("grep -l pattern".to_string()));
    }

    #[test]
    fn test_xargs_with_replace() {
        let cmd = make_cmd(&["-I{}", "cp", "{}", "/tmp/"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("cp {} /tmp/".to_string()));
    }

    #[test]
    fn test_xargs_with_max_args() {
        let cmd = make_cmd(&["-n", "1", "rm"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm".to_string()));
    }

    #[test]
    fn test_xargs_no_command() {
        let cmd = make_cmd(&["-n", "1"]);
        let result = unwrap(&cmd).unwrap();
        // xargs defaults to echo when no command specified
        assert_eq!(result.inner_command, Some("echo".to_string()));
    }

    #[test]
    fn test_xargs_with_parallel() {
        let cmd = make_cmd(&["-P", "4", "-I{}", "convert", "{}", "{}.png"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("convert {} {}.png".to_string()));
    }

    #[test]
    fn test_xargs_dangerous_command() {
        let cmd = make_cmd(&["rm", "-rf"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf".to_string()));
    }
}
