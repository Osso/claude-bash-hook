//! Script analysis for inline code execution (php -r, python -c, etc.)
//!
//! Each language has its own module that checks if inline scripts are read-only.

pub mod lua;
pub mod perl;
pub mod php;
pub mod python;

use crate::analyzer::Command;
use crate::config::{Config, ExecContext, Permission, PermissionResult};

/// Check if an interpreter command (e.g. python3 script.py) runs a script
/// that would be allowed by config rules on its own.
pub fn check_interpreter_script(
    cmd: &Command,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> Option<PermissionResult> {
    // Skip module execution (-m) which is handled by config rules like "python3 -m json.tool"
    if cmd.args.iter().any(|a| a == "-m") {
        return None;
    }

    // Find the first non-flag arg (the script path)
    let script = cmd.args.iter().find(|a| !a.starts_with('-'))?;

    // Check if the script path is allowed as a command
    let result = config.check_command_with_cwd(script, &[], virtual_cwd, ctx);
    if result.permission == Permission::Allow {
        return Some(result);
    }
    if initial_cwd != virtual_cwd {
        let result = config.check_command_with_cwd(script, &[], initial_cwd, ctx);
        if result.permission == Permission::Allow {
            return Some(result);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_command;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        make_command(name, args)
    }

    fn config_with_script(script: &str) -> Config {
        let toml = format!(
            r#"
            [[rules]]
            commands = ["{}"]
            permission = "allow"
            reason = "allowed script"
        "#,
            script
        );
        toml::from_str(&toml).unwrap()
    }

    #[test]
    fn test_python3_allowed_script() {
        let config = config_with_script("scripts/compare_refs.py");
        let cmd = make_cmd("python3", &["scripts/compare_refs.py", "arg1"]);
        let result =
            check_interpreter_script(&cmd, &config, None, None, ExecContext::default()).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_python3_unknown_script_returns_none() {
        let config = config_with_script("scripts/compare_refs.py");
        let cmd = make_cmd("python3", &["scripts/other.py"]);
        let result = check_interpreter_script(&cmd, &config, None, None, ExecContext::default());
        assert!(result.is_none());
    }

    #[test]
    fn test_python3_dash_m_skipped() {
        let config = config_with_script("json.tool");
        let cmd = make_cmd("python3", &["-m", "json.tool"]);
        let result = check_interpreter_script(&cmd, &config, None, None, ExecContext::default());
        assert!(result.is_none());
    }

    #[test]
    fn test_python3_dash_c_no_script_path() {
        let config = config_with_script("scripts/foo.py");
        let cmd = make_cmd("python3", &["-c", "print('hi')"]);
        // -c's argument "print('hi')" won't match any script rule
        let result = check_interpreter_script(&cmd, &config, None, None, ExecContext::default());
        assert!(result.is_none());
    }

    #[test]
    fn test_python3_script_with_cwd() {
        let toml = r#"
            [[rules]]
            commands = ["scripts/compare_refs.py"]
            permission = "allow"
            reason = "allowed script"
            cwd = "/home/user/project"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        let cmd = make_cmd("python3", &["scripts/compare_refs.py"]);
        let result = check_interpreter_script(
            &cmd,
            &config,
            None,
            Some("/home/user/project"),
            ExecContext::default(),
        )
        .unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
