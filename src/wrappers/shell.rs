//! Shell wrapper handling
//!
//! - `bash -c "command"` - parse the command string
//! - `bash script.sh` - check script path as binary

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Check if this is a shell command and unwrap it
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    // Only handle sh, bash, zsh, fish, nu
    if !matches!(cmd.name.as_str(), "sh" | "bash" | "zsh" | "fish" | "nu") {
        return None;
    }

    if cmd.args.is_empty() {
        return None;
    }

    // Check for -c flag (nu also uses --commands)
    if let Some(c_pos) = cmd.args.iter().position(|a| a == "-c" || a == "--commands") {
        // -c mode: parse the command string
        if c_pos + 1 >= cmd.args.len() {
            return None;
        }

        let inner_command = &cmd.args[c_pos + 1];
        let stripped = strip_quotes(inner_command);

        return Some(UnwrapResult {
            inner_command: Some(stripped),
            host: None,
            wrapper: cmd.name.clone(),
        });
    }

    // Script mode: bash script.sh [args...]
    // Find first non-flag argument as the script path
    let script = cmd.args.iter().find(|a| !a.starts_with('-'))?;

    // Return script path as the "command" to check against rules
    Some(UnwrapResult {
        inner_command: Some(script.clone()),
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
    use crate::test_support::make_command;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        make_command(name, args)
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
    fn test_sh_script_mode() {
        let cmd = make_cmd("sh", &["script.sh"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("script.sh".to_string()));
    }

    #[test]
    fn test_bash_script_with_path() {
        let cmd = make_cmd("bash", &["/tmp/claude/run-qemu.sh"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(
            result.inner_command,
            Some("/tmp/claude/run-qemu.sh".to_string())
        );
    }

    #[test]
    fn test_bash_script_with_args() {
        let cmd = make_cmd("bash", &["-x", "/tmp/script.sh", "arg1"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("/tmp/script.sh".to_string()));
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

    #[test]
    fn test_fish_c_simple() {
        let cmd = make_cmd("fish", &["-c", "ls -la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }
}
