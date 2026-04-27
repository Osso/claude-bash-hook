//! `command` builtin handling
//!
//! `command CMD ARGS` runs CMD bypassing functions/aliases — treat as a wrapper
//! and unwrap to the inner command. `command -v` / `command -V` only print a
//! lookup and do not execute the target, so leave them for rule matching
//! (the read-only `command -v` rule).

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let mut inner_parts = Vec::new();
    let mut found_command = false;

    for arg in &cmd.args {
        if found_command {
            inner_parts.push(arg.clone());
            continue;
        }

        // -v / -V are lookup-only modes; let rule matching handle them.
        if matches!(arg.as_str(), "-v" | "-V") {
            return None;
        }

        // -p (use default PATH), -- (end of options), or any other -flag: skip.
        if arg.starts_with('-') {
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
        wrapper: "command".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "command".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_command_simple() {
        let cmd = make_cmd(&["find", "src", "-name", "items*"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(
            result.inner_command,
            Some("find src -name items*".to_string())
        );
    }

    #[test]
    fn test_command_with_p_flag() {
        let cmd = make_cmd(&["-p", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_command_with_double_dash() {
        let cmd = make_cmd(&["--", "rm", "-rf", "/tmp/foo"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf /tmp/foo".to_string()));
    }

    #[test]
    fn test_command_v_lookup_not_unwrapped() {
        let cmd = make_cmd(&["-v", "rm"]);
        assert!(unwrap(&cmd).is_none());
    }

    #[test]
    fn test_command_capital_v_lookup_not_unwrapped() {
        let cmd = make_cmd(&["-V", "ls"]);
        assert!(unwrap(&cmd).is_none());
    }

    #[test]
    fn test_command_no_args() {
        let cmd = make_cmd(&[]);
        assert!(unwrap(&cmd).is_none());
    }

    #[test]
    fn test_command_only_flags() {
        let cmd = make_cmd(&["-p"]);
        assert!(unwrap(&cmd).is_none());
    }
}
