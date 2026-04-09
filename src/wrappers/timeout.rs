//! timeout wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap timeout command
/// timeout [options] DURATION COMMAND [args...]
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let opts_with_args = ["-k", "--kill-after", "-s", "--signal"];
    let inner_parts = collect_timeout_command(&cmd.args, &opts_with_args)?;

    Some(UnwrapResult {
        inner_command: Some(inner_parts.join(" ")),
        host: None,
        wrapper: "timeout".to_string(),
    })
}

fn collect_timeout_command(args: &[String], opts_with_args: &[&str]) -> Option<Vec<String>> {
    let mut skip_next = false;
    let mut saw_duration = false;
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
        if !saw_duration {
            saw_duration = true;
            continue;
        }
        inner_parts.push(arg.clone());
    }

    (!inner_parts.is_empty()).then_some(inner_parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "timeout".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_timeout_simple() {
        let cmd = make_cmd(&["30", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_timeout_with_options() {
        let cmd = make_cmd(&["-k", "10", "30s", "rm", "-rf", "/tmp"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf /tmp".to_string()));
    }

    #[test]
    fn test_timeout_with_signal() {
        let cmd = make_cmd(&["-s", "KILL", "5", "sleep", "100"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("sleep 100".to_string()));
    }
}
