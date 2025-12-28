//! Shell wrapper handling (sh -c, bash -c, zsh -c, nu -c)

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Check if this is a shell -c command and unwrap it
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    // Only handle sh, bash, zsh, nu with -c flag
    if !matches!(cmd.name.as_str(), "sh" | "bash" | "zsh" | "nu") {
        return None;
    }

    // Need at least -c and the command string
    if cmd.args.len() < 2 {
        return None;
    }

    // Check for -c flag (nu also uses --commands)
    let c_pos = cmd.args.iter().position(|a| a == "-c" || a == "--commands")?;

    // The command string follows -c
    if c_pos + 1 >= cmd.args.len() {
        return None;
    }

    let inner_command = &cmd.args[c_pos + 1];

    // Strip surrounding quotes if present (analyzer preserves them for raw_string)
    let stripped = strip_quotes(inner_command);

    Some(UnwrapResult {
        inner_command: Some(stripped),
        host: None,
        wrapper: cmd.name.clone(),
    })
}

/// Strip surrounding single or double quotes from a string
fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
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
    fn test_sh_c_simple() {
        let cmd = make_cmd("sh", &["-c", "ls -la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_bash_c_simple() {
        let cmd = make_cmd("bash", &["-c", "echo hello"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("echo hello".to_string()));
    }

    #[test]
    fn test_zsh_c_simple() {
        let cmd = make_cmd("zsh", &["-c", "pwd"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("pwd".to_string()));
    }

    #[test]
    fn test_sh_without_c_not_wrapper() {
        let cmd = make_cmd("sh", &["script.sh"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_sh_c_no_command() {
        let cmd = make_cmd("sh", &["-c"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_nu_c_simple() {
        let cmd = make_cmd("nu", &["-c", "ls"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls".to_string()));
    }

    #[test]
    fn test_nu_commands_long_form() {
        let cmd = make_cmd("nu", &["--commands", "echo hello"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("echo hello".to_string()));
    }
}
