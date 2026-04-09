//! Cargo-specific command handling

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Allow running binaries from target/debug/ or target/release/ when under project cwd.
/// E.g., /home/user/project/target/debug/myapp is allowed when cwd is /home/user/project
pub fn check_target_binary(
    cmd: &Command,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
) -> Option<PermissionResult> {
    if !is_cargo_target_binary(&cmd.name) {
        return None;
    }

    // Resolve relative paths (./target/debug/foo) to absolute using cwd
    let resolved_name = if cmd.name.starts_with("./") || !cmd.name.starts_with('/') {
        if let Some(cwd) = virtual_cwd.or(initial_cwd) {
            format!(
                "{}/{}",
                cwd.trim_end_matches('/'),
                cmd.name.strip_prefix("./").unwrap_or(&cmd.name)
            )
        } else {
            cmd.name.clone()
        }
    } else {
        cmd.name.clone()
    };

    let cwds = [virtual_cwd, initial_cwd];
    for cwd in cwds.into_iter().flatten() {
        let prefix = if cwd.ends_with('/') {
            cwd.to_string()
        } else {
            format!("{}/", cwd)
        };
        if resolved_name.starts_with(&prefix) {
            return Some(PermissionResult {
                permission: Permission::Allow,
                reason: "cargo target binary in project dir".to_string(),
                suggestion: None,
            });
        }
    }

    None
}

fn is_cargo_target_binary(name: &str) -> bool {
    name.contains("/target/debug/")
        || name.contains("/target/release/")
        || name.starts_with("target/debug/")
        || name.starts_with("target/release/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_command;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        make_command(name, args)
    }

    #[test]
    fn test_target_debug_in_project_allowed() {
        let cmd = make_cmd(
            "/home/user/project/target/debug/myapp",
            &["dump-tree", "--filter", "Foo"],
        );
        let result = check_target_binary(&cmd, None, Some("/home/user/project")).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_target_release_in_project_allowed() {
        let cmd = make_cmd("/home/user/project/target/release/myapp", &["--help"]);
        let result = check_target_binary(&cmd, None, Some("/home/user/project")).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_target_binary_outside_project_returns_none() {
        let cmd = make_cmd("/other/project/target/debug/myapp", &[]);
        let result = check_target_binary(&cmd, None, Some("/home/user/project"));
        assert!(result.is_none());
    }

    #[test]
    fn test_target_binary_virtual_cwd() {
        let cmd = make_cmd("/home/user/project/target/debug/myapp", &[]);
        let result =
            check_target_binary(&cmd, Some("/home/user/project"), Some("/other/dir")).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_non_target_binary_returns_none() {
        let cmd = make_cmd("/usr/bin/ls", &[]);
        let result = check_target_binary(&cmd, None, Some("/usr"));
        assert!(result.is_none());
    }

    #[test]
    fn test_relative_target_binary_allowed() {
        let cmd = make_cmd("./target/debug/myapp", &["test"]);
        let result = check_target_binary(&cmd, None, Some("/home/user/project")).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_relative_target_binary_no_dot_slash() {
        let cmd = make_cmd("target/debug/myapp", &[]);
        let result = check_target_binary(&cmd, None, Some("/home/user/project")).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
