//! Wrapper command handling (sudo, ssh, env, etc.)
//!
//! Unwraps wrapper commands to analyze the inner command.
//! Simple wrappers are config-driven, complex ones have special handling.

mod env;
mod kubectl;
mod rsync;
mod scp;
mod shell;
mod ssh;
mod terminal_remote;
mod timeout;
mod xargs;

use crate::analyzer::Command;
use crate::config::{Config, WrapperConfig};

/// Result of unwrapping a wrapper command
#[derive(Debug)]
pub struct UnwrapResult {
    /// The inner command after unwrapping
    pub inner_command: Option<String>,
    /// For SSH/SCP: the extracted host
    pub host: Option<String>,
    /// The wrapper that was unwrapped (for debugging/tests)
    #[allow(dead_code)]
    pub wrapper: String,
}

/// Check if a command is a wrapper and unwrap it
pub fn unwrap_command(cmd: &Command, config: &Config) -> Option<UnwrapResult> {
    // Special handlers for complex wrappers
    match cmd.name.as_str() {
        "ssh" => return ssh::unwrap(cmd),
        "scp" => return scp::unwrap(cmd),
        "rsync" => return rsync::unwrap(cmd),
        "env" => return env::unwrap(cmd),
        "kubectl" => return kubectl::unwrap(cmd),
        "timeout" => return timeout::unwrap(cmd),
        "kitty-remote" | "wezterm-remote" => return terminal_remote::unwrap(cmd),
        "xargs" => return xargs::unwrap(cmd),
        "sh" | "bash" | "zsh" => return shell::unwrap(cmd),
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
    fn test_nice_with_flags() {
        let config = test_config();
        let cmd = make_cmd("nice", &["-n", "10", "ls", "-la"]);
        let result = unwrap_command(&cmd, &config).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }
}
