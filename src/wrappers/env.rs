//! env wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap env command
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_command = false;

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if found_command {
            inner_parts.push(arg.clone());
            continue;
        }

        if matches!(
            arg.as_str(),
            "-u" | "--unset" | "-C" | "--chdir" | "-S" | "--split-string"
        ) {
            skip_next = true;
            continue;
        }

        if arg.starts_with('-') {
            continue;
        }

        // Skip VAR=value assignments
        if arg.contains('=') && !arg.starts_with('=') {
            continue;
        }

        found_command = true;
        inner_parts.push(arg.clone());
    }

    if inner_parts.is_empty() {
        return None;
    }

    Some(UnwrapResult {
        inner_command: Some(inner_parts.join(" ")),
        host: None,
        wrapper: "env".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "env".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_env_simple() {
        let cmd = make_cmd(&["VAR=value", "ls"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls".to_string()));
    }

    #[test]
    fn test_env_with_flags() {
        let cmd = make_cmd(&["VAR=1", "rm", "-rf", "/tmp"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf /tmp".to_string()));
    }

    #[test]
    fn test_env_multiple_vars() {
        let cmd = make_cmd(&["FOO=1", "BAR=2", "echo", "hello"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("echo hello".to_string()));
    }

    #[test]
    fn test_env_with_unset() {
        let cmd = make_cmd(&["-u", "PATH", "ls"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls".to_string()));
    }
}
