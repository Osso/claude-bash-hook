//! rm command special handling
//!
//! Auto-allows rm for files under /tmp/ or the project directory

use crate::analyzer::Command;
use crate::config::{Config, Permission, PermissionResult};
use std::path::Path;
use std::process::Command as ProcessCommand;

/// Check if an rm command should be auto-allowed
/// Allows deletion of files under /tmp/ or the project directory (initial_cwd)
/// Uses virtual_cwd to resolve relative paths (from cd commands in pipeline)
pub fn check_rm(
    cmd: &Command,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
) -> Option<PermissionResult> {
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

    // Protected paths force an explicit prompt, even if the path is otherwise
    // under /tmp or the project dir.
    for path in &file_args {
        if has_invalid_path_chars(path) {
            continue;
        }
        if let Some(abs) = absolute_path(path, virtual_cwd)
            && config.is_ask_path(&abs)
        {
            return Some(PermissionResult {
                permission: Permission::Ask,
                reason: format!("rm targets protected path {}", abs),
                suggestion: None,
            });
        }
    }

    // Check each file argument
    for path in &file_args {
        if !is_safe_path(path, virtual_cwd, initial_cwd) {
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
fn is_safe_path(path: &str, virtual_cwd: Option<&str>, initial_cwd: Option<&str>) -> bool {
    if has_invalid_path_chars(path) {
        return false;
    }

    let Some(abs_path) = absolute_path(path, virtual_cwd) else {
        return false;
    };
    let Some(resolved) = resolve_path(&abs_path).or_else(|| resolve_existing_parent(&abs_path))
    else {
        return false;
    };
    is_under_allowed_dir(&resolved, initial_cwd)
}

fn has_invalid_path_chars(path: &str) -> bool {
    path.is_empty() || path.contains('\0') || path.contains('\n')
}

fn absolute_path(path: &str, virtual_cwd: Option<&str>) -> Option<String> {
    if Path::new(path).is_absolute() {
        return Some(path.to_string());
    }

    virtual_cwd.map(|cwd| format!("{}/{}", cwd.trim_end_matches('/'), path))
}

fn resolve_existing_parent(path: &str) -> Option<String> {
    let parent = Path::new(path).parent()?;
    let parent = parent.to_str()?;
    (!parent.is_empty())
        .then_some(parent)
        .and_then(resolve_path)
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
        }
    }

    #[test]
    fn test_rm_tmp_file() {
        let cmd = make_cmd(&["/tmp/test.txt"]);
        let result = check_rm(&cmd, &Config::default(), None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_tmp_subdir() {
        let cmd = make_cmd(&["-rf", "/tmp/mydir/subdir"]);
        let result = check_rm(&cmd, &Config::default(), None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_tmp_itself_not_allowed() {
        let cmd = make_cmd(&["-rf", "/tmp"]);
        let result = check_rm(&cmd, &Config::default(), None, None);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_tmp_slash_not_allowed() {
        let cmd = make_cmd(&["-rf", "/tmp/"]);
        let result = check_rm(&cmd, &Config::default(), None, None);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_home_not_allowed() {
        let cmd = make_cmd(&["/home/user/file"]);
        let result = check_rm(&cmd, &Config::default(), None, None);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_project_file() {
        // Use /syncthing as project dir since it exists on this system
        let cmd = make_cmd(&["/syncthing/Sync/Projects/test/target/debug/test"]);
        let result = check_rm(
            &cmd,
            &Config::default(),
            None,
            Some("/syncthing/Sync/Projects/test"),
        )
        .unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_outside_project() {
        let cmd = make_cmd(&["/var/other/file"]);
        let result = check_rm(
            &cmd,
            &Config::default(),
            None,
            Some("/syncthing/Sync/Projects/test"),
        );
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_multiple_tmp_files() {
        let cmd = make_cmd(&["/tmp/a", "/tmp/b", "/tmp/c"]);
        let result = check_rm(&cmd, &Config::default(), None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_mixed_paths_not_allowed() {
        let cmd = make_cmd(&["/tmp/a", "/home/user/b"]);
        let result = check_rm(&cmd, &Config::default(), None, None);
        assert!(result.is_none()); // passthrough because /home path
    }

    #[test]
    fn test_not_rm_command() {
        let cmd = Command {
            name: "ls".to_string(),
            args: vec!["/tmp".to_string()],
        };
        let result = check_rm(&cmd, &Config::default(), None, None);
        assert!(result.is_none());
    }

    // Virtual cwd tests

    #[test]
    fn test_rm_relative_with_virtual_cwd_tmp() {
        // cd /tmp/claude && rm test -> allowed
        let cmd = make_cmd(&["test"]);
        let result = check_rm(&cmd, &Config::default(), Some("/tmp/claude"), None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_relative_with_virtual_cwd_root() {
        // cd / && rm test -> NOT allowed (would delete /test)
        let cmd = make_cmd(&["test"]);
        let result = check_rm(&cmd, &Config::default(), Some("/"), None);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_relative_with_virtual_cwd_project() {
        // cd /syncthing/Sync/Projects/test && rm target/debug/test -> allowed
        let cmd = make_cmd(&["target/debug/test"]);
        let result = check_rm(
            &cmd,
            &Config::default(),
            Some("/syncthing/Sync/Projects/test"),
            Some("/syncthing/Sync/Projects/test"),
        )
        .unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_rm_relative_no_virtual_cwd() {
        // rm test with no cwd info -> passthrough (can't resolve safely)
        let cmd = make_cmd(&["test"]);
        let result = check_rm(&cmd, &Config::default(), None, None);
        assert!(result.is_none()); // passthrough
    }

    #[test]
    fn test_rm_absolute_ignores_virtual_cwd() {
        // cd / && rm /tmp/test -> allowed (absolute path ignores virtual_cwd)
        let cmd = make_cmd(&["/tmp/test"]);
        let result = check_rm(&cmd, &Config::default(), Some("/"), None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    fn ask_config(patterns: &[&str]) -> Config {
        let list: Vec<String> = patterns.iter().map(|s| format!("\"{}\"", s)).collect();
        let toml = format!("ask_paths = [{}]", list.join(", "));
        toml::from_str(&toml).expect("config")
    }

    #[test]
    fn test_rm_ask_path_matches_absolute() {
        let cmd = make_cmd(&["/home/user/.config/foo"]);
        let config = ask_config(&["/home/user/.config/*"]);
        let result = check_rm(&cmd, &config, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_rm_ask_path_forces_ask_over_tmp_allow() {
        // /tmp path would normally auto-allow; ask_paths forces ask.
        let cmd = make_cmd(&["/tmp/secret"]);
        let config = ask_config(&["/tmp/*"]);
        let result = check_rm(&cmd, &config, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_rm_ask_path_no_match_still_allows_tmp() {
        let cmd = make_cmd(&["/tmp/ok"]);
        let config = ask_config(&["/home/user/.config/*"]);
        let result = check_rm(&cmd, &config, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
