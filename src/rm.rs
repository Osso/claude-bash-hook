//! rm command special handling
//!
//! Auto-allows rm for files under /tmp/ or the project directory

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use std::process::Command as ProcessCommand;

/// Check if an rm command should be auto-allowed
/// Allows deletion of files under /tmp/ or the project directory (initial_cwd)
pub fn check_rm(cmd: &Command, initial_cwd: Option<&str>) -> Option<PermissionResult> {
    if cmd.name != "rm" {
        return None;
    }

    // Extract file arguments (skip flags)
    let file_args: Vec<&str> = cmd
        .args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .collect();

    // No files specified - let normal handling deal with it
    if file_args.is_empty() {
        return None;
    }

    // Check each file argument
    for path in &file_args {
        if !is_safe_path(path, initial_cwd) {
            return None;
        }
    }

    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "rm in /tmp or project dir".to_string(),
        suggestion: None,
    })
}

/// Check if a path is safe to delete (under /tmp/ or project dir)
fn is_safe_path(path: &str, initial_cwd: Option<&str>) -> bool {
    if path.is_empty() {
        return false;
    }

    if path.contains('\0') || path.contains('\n') {
        return false;
    }

    let resolved = match resolve_path(path) {
        Some(p) => p,
        None => {
            // Path doesn't exist - check parent
            if let Some(parent) = std::path::Path::new(path).parent() {
                if let Some(parent_str) = parent.to_str() {
                    if !parent_str.is_empty() {
                        if let Some(resolved_parent) = resolve_path(parent_str) {
                            return is_under_allowed_dir(&resolved_parent, initial_cwd);
                        }
                    }
                }
            }
            return false;
        }
    };

    is_under_allowed_dir(&resolved, initial_cwd)
}

/// Check if a resolved path is under /tmp/ or project dir
fn is_under_allowed_dir(resolved: &str, initial_cwd: Option<&str>) -> bool {
    // Allow /tmp/
    if resolved.starts_with("/tmp/") {
        let after = &resolved[5..];
        if !after.is_empty() && !after.chars().all(|c| c == '/') {
            return true;
        }
    }

    // Allow project directory
    if let Some(cwd) = initial_cwd {
        let cwd_prefix = if cwd.ends_with('/') {
            cwd.to_string()
        } else {
            format!("{}/", cwd)
        };

        if resolved.starts_with(&cwd_prefix) {
            return true;
        }
    }

    false
}

/// Resolve a path using realpath
fn resolve_path(path: &str) -> Option<String> {
    let output = ProcessCommand::new("realpath")
        .arg("-m") // don't require path to exist
        .arg("--")
        .arg(path)
        .output()
        .ok()?;

    if output.status.success() {
        let resolved = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !resolved.is_empty() {
            return Some(resolved);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "rm".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("rm {}", args.join(" ")),
        }
    }

    #[test]
    fn test_rm_tmp_file() {
        let cmd = make_cmd(&["/tmp/test.txt"]);
        let result = check_rm(&cmd, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_tmp_subdir() {
        let cmd = make_cmd(&["-rf", "/tmp/mydir/subdir"]);
        let result = check_rm(&cmd, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_tmp_itself_not_allowed() {
        let cmd = make_cmd(&["-rf", "/tmp"]);
        let result = check_rm(&cmd, None);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_tmp_slash_not_allowed() {
        let cmd = make_cmd(&["-rf", "/tmp/"]);
        let result = check_rm(&cmd, None);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_home_not_allowed() {
        let cmd = make_cmd(&["/home/user/file"]);
        let result = check_rm(&cmd, None);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_project_file() {
        // Use /syncthing as project dir since it exists on this system
        let cmd = make_cmd(&["/syncthing/Sync/Projects/test/target/debug/test"]);
        let result = check_rm(&cmd, Some("/syncthing/Sync/Projects/test")).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_outside_project() {
        let cmd = make_cmd(&["/var/other/file"]);
        let result = check_rm(&cmd, Some("/syncthing/Sync/Projects/test"));
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_multiple_tmp_files() {
        let cmd = make_cmd(&["/tmp/a", "/tmp/b", "/tmp/c"]);
        let result = check_rm(&cmd, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_mixed_paths_not_allowed() {
        let cmd = make_cmd(&["/tmp/a", "/home/user/b"]);
        let result = check_rm(&cmd, None);
        assert!(result.is_none()); // passthrough because /home path
    }

    #[test]
    fn test_not_rm_command() {
        let cmd = Command {
            name: "ls".to_string(),
            args: vec!["/tmp".to_string()],
            text: "ls /tmp".to_string(),
        };
        let result = check_rm(&cmd, None);
        assert!(result.is_none());
    }
}
