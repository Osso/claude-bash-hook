//! Wrapper command handling (sudo, ssh, env, etc.)
//!
//! Unwraps wrapper commands to analyze the inner command.

use crate::analyzer::Command;

/// Result of unwrapping a wrapper command
#[derive(Debug)]
pub struct UnwrapResult {
    /// The inner command after unwrapping
    pub inner_command: Option<String>,
    /// For SSH/SCP: the extracted host
    pub host: Option<String>,
    /// The wrapper that was unwrapped
    pub wrapper: String,
}

/// Check if a command is a wrapper and unwrap it
pub fn unwrap_command(cmd: &Command) -> Option<UnwrapResult> {
    match cmd.name.as_str() {
        "sudo" => unwrap_sudo(cmd),
        "ssh" => unwrap_ssh(cmd),
        "scp" => unwrap_scp(cmd),
        "rsync" => unwrap_rsync(cmd),
        "env" => unwrap_env(cmd),
        "kubectl" => unwrap_kubectl(cmd),
        "nice" | "nohup" | "time" | "strace" | "ltrace" => unwrap_simple_wrapper(cmd),
        _ => None,
    }
}

/// Unwrap sudo command
/// sudo [-AbEHnPS] [-g group] [-p prompt] [-r role] [-t type] [-u user] [-T timeout] command [args...]
fn unwrap_sudo(cmd: &Command) -> Option<UnwrapResult> {
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_command = false;

    // Options that take an argument
    let opts_with_args = [
        "-g", "-p", "-r", "-t", "-u", "-T", "-C", "-h", "-U",
        "--group", "--prompt", "--role", "--type", "--user",
        "--other-user", "--timeout", "--close-from", "--host",
    ];

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        // Once we've found the command, everything after is part of it
        if found_command {
            inner_parts.push(arg.clone());
            continue;
        }

        // Check for options that take an argument
        if opts_with_args.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }

        // Skip flags
        if arg.starts_with('-') {
            // Check if it's a combined flag with an arg-taking option at the end
            if arg.len() > 2 && !arg.starts_with("--") {
                let last_char = arg.chars().last().unwrap();
                if matches!(last_char, 'g' | 'p' | 'r' | 't' | 'u' | 'T' | 'C' | 'h' | 'U') {
                    // Option takes inline arg or next arg
                    // e.g., -Au means next arg is the user
                    skip_next = true;
                }
            }
            continue;
        }

        // This is the command - everything from here is the inner command
        found_command = true;
        inner_parts.push(arg.clone());
    }

    if inner_parts.is_empty() {
        return None;
    }

    Some(UnwrapResult {
        inner_command: Some(inner_parts.join(" ")),
        host: None,
        wrapper: "sudo".to_string(),
    })
}

/// Unwrap ssh command
/// ssh [options] [user@]hostname [command]
fn unwrap_ssh(cmd: &Command) -> Option<UnwrapResult> {
    let mut host = None;
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_host = false;

    // Options that take an argument
    let opts_with_args = [
        "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p",
        "-Q", "-R", "-S", "-W", "-w",
    ];

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if !found_host {
            // Still looking for the host
            if arg.starts_with('-') {
                // Check if this option takes an argument
                let opt = if arg.len() > 2 {
                    &arg[0..2]
                } else {
                    arg.as_str()
                };
                if opts_with_args.contains(&opt) {
                    if arg.len() == 2 {
                        // Argument is next word
                        skip_next = true;
                    }
                    // else argument is inline like -p22
                }
                continue;
            }

            // This should be the host
            found_host = true;
            // Extract host from user@host format
            let h = if let Some(at_pos) = arg.find('@') {
                &arg[at_pos + 1..]
            } else {
                arg.as_str()
            };
            host = Some(h.to_string());
            continue;
        }

        // Everything after the host is the remote command
        inner_parts.push(arg.clone());
    }

    Some(UnwrapResult {
        inner_command: if inner_parts.is_empty() {
            None
        } else {
            Some(inner_parts.join(" "))
        },
        host,
        wrapper: "ssh".to_string(),
    })
}

/// Unwrap scp command - extract destination host
/// scp [options] source ... target
fn unwrap_scp(cmd: &Command) -> Option<UnwrapResult> {
    // For scp, we look for host: in the arguments
    let mut host = None;

    for arg in &cmd.args {
        if arg.starts_with('-') {
            continue;
        }
        // Look for user@host:path or host:path patterns
        if let Some(colon_pos) = arg.find(':') {
            let before_colon = &arg[..colon_pos];
            let h = if let Some(at_pos) = before_colon.find('@') {
                &before_colon[at_pos + 1..]
            } else {
                before_colon
            };
            // Make sure it's not a local path like /path/to:file
            if !h.starts_with('/') && !h.starts_with('.') {
                host = Some(h.to_string());
                break;
            }
        }
    }

    Some(UnwrapResult {
        inner_command: None, // scp doesn't have an inner command
        host,
        wrapper: "scp".to_string(),
    })
}

/// Unwrap rsync command - extract destination host
fn unwrap_rsync(cmd: &Command) -> Option<UnwrapResult> {
    // Similar to scp
    let mut host = None;

    for arg in &cmd.args {
        if arg.starts_with('-') {
            continue;
        }
        // Look for host: pattern (can also be user@host:)
        if let Some(colon_pos) = arg.find(':') {
            let before_colon = &arg[..colon_pos];
            // Skip if it looks like a local path
            if before_colon.starts_with('/') || before_colon.starts_with('.') {
                continue;
            }
            let h = if let Some(at_pos) = before_colon.find('@') {
                &before_colon[at_pos + 1..]
            } else {
                before_colon
            };
            host = Some(h.to_string());
            break;
        }
    }

    Some(UnwrapResult {
        inner_command: None,
        host,
        wrapper: "rsync".to_string(),
    })
}

/// Unwrap kubectl exec command
/// kubectl exec [options] POD -- COMMAND [args...]
/// Only handles "exec" subcommand - other kubectl commands are not wrappers
fn unwrap_kubectl(cmd: &Command) -> Option<UnwrapResult> {
    // Only handle kubectl exec
    if cmd.args.first().map(|s| s.as_str()) != Some("exec") {
        return None;
    }

    // Find the -- separator
    let separator_pos = cmd.args.iter().position(|arg| arg == "--");

    let inner_command = match separator_pos {
        Some(pos) => {
            let inner_parts: Vec<_> = cmd.args[pos + 1..].to_vec();
            if inner_parts.is_empty() {
                None
            } else {
                Some(inner_parts.join(" "))
            }
        }
        None => None,
    };

    Some(UnwrapResult {
        inner_command,
        host: None,
        wrapper: "kubectl exec".to_string(),
    })
}

/// Unwrap env command
/// env [OPTION]... [-] [NAME=VALUE]... [COMMAND [ARG]...]
fn unwrap_env(cmd: &Command) -> Option<UnwrapResult> {
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_command = false;

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        // Once we've found the command, everything after is part of it
        if found_command {
            inner_parts.push(arg.clone());
            continue;
        }

        // Options that take an argument
        if matches!(arg.as_str(), "-u" | "--unset" | "-C" | "--chdir" | "-S" | "--split-string") {
            skip_next = true;
            continue;
        }

        // Skip flags
        if arg.starts_with('-') {
            continue;
        }

        // Skip VAR=value assignments
        if arg.contains('=') && !arg.starts_with('=') {
            continue;
        }

        // This is the command - everything from here is the inner command
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

/// Unwrap simple wrappers (nice, nohup, time, etc.)
fn unwrap_simple_wrapper(cmd: &Command) -> Option<UnwrapResult> {
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_command = false;

    // Options that take arguments for each wrapper
    let opts_with_args: &[&str] = match cmd.name.as_str() {
        "nice" => &["-n", "--adjustment"],
        "time" => &["-o", "-f", "--output", "--format"],
        "strace" => &["-e", "-o", "-p", "-s", "-u", "-E"],
        "ltrace" => &["-e", "-o", "-p", "-s", "-u", "-n"],
        _ => &[],
    };

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        // Once we've found the command, everything after is part of it
        if found_command {
            inner_parts.push(arg.clone());
            continue;
        }

        if arg.starts_with('-') {
            let opt = if arg.contains('=') {
                arg.split('=').next().unwrap_or(arg)
            } else {
                arg.as_str()
            };
            if opts_with_args.contains(&opt) && !arg.contains('=') {
                skip_next = true;
            }
            continue;
        }

        // This is the command - everything from here is the inner command
        found_command = true;
        inner_parts.push(arg.clone());
    }

    if inner_parts.is_empty() {
        return None;
    }

    Some(UnwrapResult {
        inner_command: Some(inner_parts.join(" ")),
        host: None,
        wrapper: cmd.name.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        Command {
            name: name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("{} {}", name, args.join(" ")),
        }
    }

    #[test]
    fn test_sudo_simple() {
        let cmd = make_cmd("sudo", &["ls", "-la"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_sudo_with_options() {
        let cmd = make_cmd("sudo", &["-A", "-u", "root", "ls"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls".to_string()));
    }

    #[test]
    fn test_ssh_with_command() {
        let cmd = make_cmd("ssh", &["user@host", "ls", "-la"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_ssh_with_options() {
        let cmd = make_cmd("ssh", &["-p", "22", "-i", "key.pem", "host", "whoami"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
        assert_eq!(result.inner_command, Some("whoami".to_string()));
    }

    #[test]
    fn test_scp() {
        let cmd = make_cmd("scp", &["file.txt", "user@host:/path/"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
    }

    #[test]
    fn test_env() {
        let cmd = make_cmd("env", &["VAR=value", "ls"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls".to_string()));
    }

    #[test]
    fn test_env_with_flags() {
        let cmd = make_cmd("env", &["VAR=1", "rm", "-rf", "/tmp"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf /tmp".to_string()));
    }

    #[test]
    fn test_nice_with_flags() {
        let cmd = make_cmd("nice", &["-n", "10", "ls", "-la"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_kubectl_exec_simple() {
        let cmd = make_cmd("kubectl", &["exec", "mypod", "--", "ls", "-la"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
        assert_eq!(result.wrapper, "kubectl exec");
    }

    #[test]
    fn test_kubectl_exec_with_options() {
        let cmd = make_cmd("kubectl", &["exec", "-it", "mypod", "-c", "mycontainer", "--", "/bin/bash"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("/bin/bash".to_string()));
    }

    #[test]
    fn test_kubectl_exec_with_namespace() {
        let cmd = make_cmd("kubectl", &["exec", "-n", "prod", "mypod", "--", "rm", "-rf", "/tmp"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf /tmp".to_string()));
    }

    #[test]
    fn test_kubectl_get_not_wrapper() {
        let cmd = make_cmd("kubectl", &["get", "pods"]);
        let result = unwrap_command(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_kubectl_exec_no_separator() {
        // kubectl exec without -- has no inner command to analyze
        let cmd = make_cmd("kubectl", &["exec", "mypod"]);
        let result = unwrap_command(&cmd).unwrap();
        assert_eq!(result.inner_command, None);
    }
}
