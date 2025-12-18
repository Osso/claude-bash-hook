//! Wrapper command handling (sudo, ssh, env, etc.)
//!
//! Unwraps wrapper commands to analyze the inner command.
//! Simple wrappers are config-driven, complex ones have special handling.

use crate::analyzer::Command;
use crate::config::{Config, WrapperConfig};

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
pub fn unwrap_command(cmd: &Command, config: &Config) -> Option<UnwrapResult> {
    // Special handlers for complex wrappers
    match cmd.name.as_str() {
        "ssh" => return unwrap_ssh(cmd),
        "scp" => return unwrap_scp(cmd),
        "rsync" => return unwrap_rsync(cmd),
        "env" => return unwrap_env(cmd),
        "kubectl" => return unwrap_kubectl(cmd),
        "timeout" => return unwrap_timeout(cmd),
        "kitty-remote" | "wezterm-remote" => return unwrap_terminal_remote(cmd),
        _ => {}
    }

    // Check if it's a config-driven simple wrapper
    if let Some(wrapper_config) = config.get_wrapper(&cmd.name) {
        return unwrap_generic(cmd, wrapper_config);
    }

    None
}

/// Generic wrapper unwrapping using config
fn unwrap_generic(cmd: &Command, config: &WrapperConfig) -> Option<UnwrapResult> {
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

        if arg.starts_with('-') {
            // Check if this option takes an argument
            let opt = if arg.contains('=') {
                // --flag=value format, no need to skip next
                continue;
            } else {
                arg.as_str()
            };

            if config.opts_with_args.iter().any(|o| o == opt) {
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

/// Unwrap timeout command
/// timeout [options] DURATION COMMAND [args...]
fn unwrap_timeout(cmd: &Command) -> Option<UnwrapResult> {
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_duration = false;
    let mut found_command = false;

    let opts_with_args = ["-k", "--kill-after", "-s", "--signal"];

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if found_command {
            inner_parts.push(arg.clone());
            continue;
        }

        if arg.starts_with('-') {
            let opt = if arg.contains('=') {
                continue;
            } else {
                arg.as_str()
            };
            if opts_with_args.contains(&opt) {
                skip_next = true;
            }
            continue;
        }

        if !found_duration {
            // First positional arg is duration, skip it
            found_duration = true;
            continue;
        }

        // This is the command
        found_command = true;
        inner_parts.push(arg.clone());
    }

    if inner_parts.is_empty() {
        return None;
    }

    Some(UnwrapResult {
        inner_command: Some(inner_parts.join(" ")),
        host: None,
        wrapper: "timeout".to_string(),
    })
}

/// Unwrap ssh command
/// ssh [options] [user@]hostname [command]
fn unwrap_ssh(cmd: &Command) -> Option<UnwrapResult> {
    let mut host = None;
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_host = false;

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
            if arg.starts_with('-') {
                let opt = if arg.len() > 2 { &arg[0..2] } else { arg.as_str() };
                if opts_with_args.contains(&opt) {
                    if arg.len() == 2 {
                        skip_next = true;
                    }
                }
                continue;
            }

            found_host = true;
            let h = if let Some(at_pos) = arg.find('@') {
                &arg[at_pos + 1..]
            } else {
                arg.as_str()
            };
            host = Some(h.to_string());
            continue;
        }

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
fn unwrap_scp(cmd: &Command) -> Option<UnwrapResult> {
    let mut host = None;

    for arg in &cmd.args {
        if arg.starts_with('-') {
            continue;
        }
        if let Some(colon_pos) = arg.find(':') {
            let before_colon = &arg[..colon_pos];
            let h = if let Some(at_pos) = before_colon.find('@') {
                &before_colon[at_pos + 1..]
            } else {
                before_colon
            };
            if !h.starts_with('/') && !h.starts_with('.') {
                host = Some(h.to_string());
                break;
            }
        }
    }

    Some(UnwrapResult {
        inner_command: None,
        host,
        wrapper: "scp".to_string(),
    })
}

/// Unwrap rsync command - extract destination host
fn unwrap_rsync(cmd: &Command) -> Option<UnwrapResult> {
    let mut host = None;

    for arg in &cmd.args {
        if arg.starts_with('-') {
            continue;
        }
        if let Some(colon_pos) = arg.find(':') {
            let before_colon = &arg[..colon_pos];
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
fn unwrap_kubectl(cmd: &Command) -> Option<UnwrapResult> {
    if cmd.args.first().map(|s| s.as_str()) != Some("exec") {
        return None;
    }

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

/// Unwrap kitty-remote/wezterm-remote commands
/// Only the "run" subcommand wraps another command
fn unwrap_terminal_remote(cmd: &Command) -> Option<UnwrapResult> {
    let mut skip_next = false;
    let mut found_subcommand = false;
    let mut inner_parts = Vec::new();

    // Options that take arguments
    let opts_with_args = ["-m", "-t", "-i", "-p", "-T", "-w", "--match", "--pane-id", "--tab-id", "--window-id", "--title"];

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if found_subcommand {
            inner_parts.push(arg.clone());
            continue;
        }

        if arg.starts_with('-') {
            if opts_with_args.contains(&arg.as_str()) {
                skip_next = true;
            }
            continue;
        }

        // First non-option is the subcommand
        if arg == "run" {
            // "run" subcommand wraps a command
            found_subcommand = true;
            continue;
        }

        // Other subcommands don't wrap commands
        return None;
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

/// Unwrap env command
fn unwrap_env(cmd: &Command) -> Option<UnwrapResult> {
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

        if matches!(arg.as_str(), "-u" | "--unset" | "-C" | "--chdir" | "-S" | "--split-string") {
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
    use std::path::Path;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        Command {
            name: name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("{} {}", name, args.join(" ")),
        }
    }

    fn test_config() -> Config {
        Config::load(Path::new("config.example.toml")).expect("Failed to load test config")
    }

    #[test]
    fn test_sudo_simple() {
        let config = test_config();
        let cmd = make_cmd("sudo", &["ls", "-la"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_sudo_with_options() {
        let config = test_config();
        let cmd = make_cmd("sudo", &["-A", "-u", "root", "ls"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("ls".to_string()));
    }

    #[test]
    fn test_ssh_with_command() {
        let config = test_config();
        let cmd = make_cmd("ssh", &["user@host", "ls", "-la"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_ssh_with_options() {
        let config = test_config();
        let cmd = make_cmd("ssh", &["-p", "22", "-i", "key.pem", "host", "whoami"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
        assert_eq!(result.inner_command, Some("whoami".to_string()));
    }

    #[test]
    fn test_scp() {
        let config = test_config();
        let cmd = make_cmd("scp", &["file.txt", "user@host:/path/"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
    }

    #[test]
    fn test_env() {
        let config = test_config();
        let cmd = make_cmd("env", &["VAR=value", "ls"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("ls".to_string()));
    }

    #[test]
    fn test_env_with_flags() {
        let config = test_config();
        let cmd = make_cmd("env", &["VAR=1", "rm", "-rf", "/tmp"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf /tmp".to_string()));
    }

    #[test]
    fn test_nice_with_flags() {
        let config = test_config();
        let cmd = make_cmd("nice", &["-n", "10", "ls", "-la"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_kubectl_exec_simple() {
        let config = test_config();
        let cmd = make_cmd("kubectl", &["exec", "mypod", "--", "ls", "-la"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
        assert_eq!(result.wrapper, "kubectl exec");
    }

    #[test]
    fn test_kubectl_exec_with_options() {
        let config = test_config();
        let cmd = make_cmd("kubectl", &["exec", "-it", "mypod", "-c", "mycontainer", "--", "/bin/bash"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("/bin/bash".to_string()));
    }

    #[test]
    fn test_kubectl_exec_with_namespace() {
        let config = test_config();
        let cmd = make_cmd("kubectl", &["exec", "-n", "prod", "mypod", "--", "rm", "-rf", "/tmp"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf /tmp".to_string()));
    }

    #[test]
    fn test_kubectl_get_not_wrapper() {
        let config = test_config();
        let cmd = make_cmd("kubectl", &["get", "pods"]);
        let result = unwrap_command(&cmd, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_kubectl_exec_no_separator() {
        let config = test_config();
        let cmd = make_cmd("kubectl", &["exec", "mypod"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, None);
    }

    #[test]
    fn test_timeout_simple() {
        let config = test_config();
        let cmd = make_cmd("timeout", &["30", "ls", "-la"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_timeout_with_options() {
        let config = test_config();
        let cmd = make_cmd("timeout", &["-k", "10", "30s", "rm", "-rf", "/tmp"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("rm -rf /tmp".to_string()));
    }

    #[test]
    fn test_kitty_remote_run() {
        let config = test_config();
        let cmd = make_cmd("kitty-remote", &["run", "htop"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("htop".to_string()));
    }

    #[test]
    fn test_kitty_remote_run_with_options() {
        let config = test_config();
        let cmd = make_cmd("kitty-remote", &["-t", "build", "run", "make", "-j4"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("make -j4".to_string()));
    }

    #[test]
    fn test_kitty_remote_ls_not_wrapper() {
        let config = test_config();
        let cmd = make_cmd("kitty-remote", &["ls"]);
        let result = unwrap_command(&cmd, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_wezterm_remote_run() {
        let config = test_config();
        let cmd = make_cmd("wezterm-remote", &["run", "npm", "run", "dev"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("npm run dev".to_string()));
    }

    #[test]
    fn test_wezterm_remote_send_text_not_wrapper() {
        let config = test_config();
        let cmd = make_cmd("wezterm-remote", &["-p", "0", "send-text", "hello"]);
        let result = unwrap_command(&cmd, &config);
        assert!(result.is_none());
    }
}
