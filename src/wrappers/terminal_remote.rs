//! kitty-remote/wezterm-remote wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap kitty-remote/wezterm-remote commands
/// Only the "run" subcommand wraps another command
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let opts_with_args = [
        "-m",
        "-t",
        "-i",
        "-p",
        "-T",
        "-w",
        "--match",
        "--pane-id",
        "--tab-id",
        "--window-id",
        "--title",
    ];
    let inner_parts = collect_run_subcommand(&cmd.args, &opts_with_args)?;

    Some(UnwrapResult {
        inner_command: Some(inner_parts.join(" ")),
        host: None,
        wrapper: cmd.name.clone(),
    })
}

fn collect_run_subcommand(args: &[String], opts_with_args: &[&str]) -> Option<Vec<String>> {
    let mut skip_next = false;
    let mut found_run = false;
    let mut inner_parts = Vec::new();

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if found_run {
            inner_parts.push(arg.clone());
            continue;
        }
        if arg.starts_with('-') {
            skip_next = opts_with_args.contains(&arg.as_str());
            continue;
        }
        if arg != "run" {
            return None;
        }
        found_run = true;
    }

    (!inner_parts.is_empty()).then_some(inner_parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        Command {
            name: name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_kitty_remote_run() {
        let cmd = make_cmd("kitty-remote", &["run", "htop"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("htop".to_string()));
    }

    #[test]
    fn test_kitty_remote_run_with_options() {
        let cmd = make_cmd("kitty-remote", &["-t", "build", "run", "make", "-j4"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("make -j4".to_string()));
    }

    #[test]
    fn test_kitty_remote_ls_not_wrapper() {
        let cmd = make_cmd("kitty-remote", &["ls"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_wezterm_remote_run() {
        let cmd = make_cmd("wezterm-remote", &["run", "npm", "run", "dev"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("npm run dev".to_string()));
    }

    #[test]
    fn test_wezterm_remote_send_text_not_wrapper() {
        let cmd = make_cmd("wezterm-remote", &["-p", "0", "send-text", "hello"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }
}
