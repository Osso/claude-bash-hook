//! bwrap (bubblewrap) wrapper handling
//!
//! bwrap takes many --option [args...] pairs before the inner command.
//! Some options take 0, 1, or 2 arguments.
//! The inner command starts after `--` or after all options are consumed.

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Options that take TWO arguments (e.g., --bind SRC DEST)
const OPTS_WITH_TWO_ARGS: &[&str] = &[
    "--bind",
    "--dev-bind",
    "--ro-bind",
    "--symlink",
    "--bind-try",
    "--dev-bind-try",
    "--ro-bind-try",
    "--ro-bind-data",
    "--bind-data",
    "--file",
    "--overlay-src",
    "--setenv", // VAR VALUE
    "--chmod",  // OCTET PATH
];

/// Options that take ONE argument
const OPTS_WITH_ONE_ARG: &[&str] = &[
    "--tmpfs",
    "--proc",
    "--dev",
    "--dir",
    "--lock-file",
    "--sync-fd",
    "--chdir",
    "--unsetenv",
    "--uid",
    "--gid",
    "--hostname",
    "--remount-ro",
    "--exec-label",
    "--file-label",
    "--seccomp",
    "--block-fd",
    "--userns-block-fd",
    "--info-fd",
    "--json-status-fd",
    "--userns",
    "--userns2",
    "--pidns",
    "--cap-add",
    "--cap-drop",
    "--perms",
    "--size",
];

/// Unwrap bwrap command to extract the inner command
///
/// Syntax: bwrap [OPTIONS] [--] COMMAND [ARGS...]
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let mut i = 0;
    let args = &cmd.args;

    while i < args.len() {
        let arg = &args[i];

        // Explicit end of options: everything after -- is the command
        if arg == "--" {
            i += 1;
            break;
        }

        if !arg.starts_with('-') {
            // First non-option positional argument is the command
            break;
        }

        // Handle --opt=value format (counts as one-arg consumed inline)
        if arg.contains('=') {
            i += 1;
            continue;
        }

        if OPTS_WITH_TWO_ARGS.iter().any(|o| *o == arg) {
            // Skip this option and its two arguments
            i += 3;
        } else if OPTS_WITH_ONE_ARG.iter().any(|o| *o == arg) {
            // Skip this option and its one argument
            i += 2;
        } else {
            // Flag with no argument (e.g., --unshare-all, --die-with-parent)
            i += 1;
        }
    }

    if i >= args.len() {
        return None;
    }

    let inner_command = args[i..].join(" ");

    Some(UnwrapResult {
        inner_command: Some(inner_command),
        host: None,
        wrapper: "bwrap".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "bwrap".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("bwrap {}", args.join(" ")),
        }
    }

    #[test]
    fn test_bwrap_simple() {
        let cmd = make_cmd(&["--unshare-all", "--", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
        assert_eq!(result.wrapper, "bwrap");
    }

    #[test]
    fn test_bwrap_with_bind_mounts() {
        let cmd = make_cmd(&[
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--unshare-all",
            "--",
            "bash",
            "-c",
            "echo hello",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("bash -c echo hello".to_string()));
    }

    #[test]
    fn test_bwrap_without_double_dash() {
        // Inner command starts after options without explicit --
        let cmd = make_cmd(&[
            "--unshare-net",
            "--unshare-pid",
            "--ro-bind",
            "/usr",
            "/usr",
            "ls",
            "-la",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_bwrap_with_chdir() {
        let cmd = make_cmd(&[
            "--ro-bind",
            "/",
            "/",
            "--chdir",
            "/tmp",
            "--unshare-all",
            "--",
            "pwd",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("pwd".to_string()));
    }

    #[test]
    fn test_bwrap_with_setenv() {
        let cmd = make_cmd(&[
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--ro-bind",
            "/usr",
            "/usr",
            "--",
            "cat",
            "/etc/hostname",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("cat /etc/hostname".to_string()));
    }

    #[test]
    fn test_bwrap_with_uid_gid() {
        let cmd = make_cmd(&[
            "--uid",
            "1000",
            "--gid",
            "1000",
            "--unshare-user",
            "--ro-bind",
            "/usr",
            "/usr",
            "--",
            "id",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("id".to_string()));
    }

    #[test]
    fn test_bwrap_no_inner_command() {
        let cmd = make_cmd(&["--unshare-all", "--ro-bind", "/usr", "/usr"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_bwrap_opt_equals_format() {
        // --chdir=/tmp style (no separate value token)
        let cmd = make_cmd(&["--unshare-all", "--chdir=/tmp", "--", "pwd"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("pwd".to_string()));
    }
}
