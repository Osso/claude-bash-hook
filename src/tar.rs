//! tar command special handling
//!
//! Auto-allows tar extraction to /tmp/claude/

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use std::process::Command as ProcessCommand;

const SAFE_PREFIX: &str = "/tmp/claude/";

/// Check if a tar command should be auto-allowed
/// Allows extraction to /tmp/claude/ subdirectories
pub fn check_tar(cmd: &Command) -> Option<PermissionResult> {
    if cmd.name != "tar" {
        return None;
    }

    // Check if this is an extract operation
    let is_extract = cmd.args.iter().any(|a| {
        a == "-x" || a == "-xf" || a == "-xzf" || a == "-xjf" || a == "-xJf"
            || a.starts_with("-x")
            || a.contains('x')  // handles combined flags like -xvf
    });

    if !is_extract {
        return None;
    }

    // Find the -C/--directory target
    let target_dir = find_target_dir(&cmd.args);

    match target_dir {
        Some(dir) => {
            if is_safe_tmp_claude_path(dir) {
                Some(PermissionResult {
                    permission: Permission::Allow,
                    reason: "tar extract to /tmp/claude".to_string(),
                    suggestion: None,
                })
            } else {
                // Not a safe path - passthrough
                None
            }
        }
        None => {
            // No -C specified, extracts to current dir - passthrough
            None
        }
    }
}

/// Find the target directory from -C or --directory flag
fn find_target_dir(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        if arg == "-C" || arg == "--directory" {
            if let Some(dir) = args.get(i + 1) {
                return Some(dir);
            }
        }

        if let Some(dir) = arg.strip_prefix("-C") {
            if !dir.is_empty() {
                return Some(dir);
            }
        }

        if let Some(dir) = arg.strip_prefix("--directory=") {
            return Some(dir);
        }

        i += 1;
    }

    None
}

/// Check if a path is safely under /tmp/claude/
fn is_safe_tmp_claude_path(path: &str) -> bool {
    if path.is_empty() || path.contains('\0') || path.contains('\n') {
        return false;
    }

    // Use realpath to resolve the path
    let resolved = match resolve_path(path) {
        Some(p) => p,
        None => return false,
    };

    // Must start with /tmp/claude/
    if !resolved.starts_with(SAFE_PREFIX) {
        return false;
    }

    // Must have something after /tmp/claude/
    let after_prefix = &resolved[SAFE_PREFIX.len()..];
    if after_prefix.is_empty() || after_prefix.chars().all(|c| c == '/') {
        return false;
    }

    true
}

/// Resolve a path using realpath
fn resolve_path(path: &str) -> Option<String> {
    let output = ProcessCommand::new("realpath")
        .arg("-m")
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
            name: "tar".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("tar {}", args.join(" ")),
        }
    }

    #[test]
    fn test_tar_extract_to_tmp_claude() {
        let cmd = make_cmd(&["-xf", "-", "-C", "/tmp/claude/test"]);
        let result = check_tar(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_tar_extract_to_tmp_claude_subdir() {
        let cmd = make_cmd(&["-xzf", "file.tar.gz", "-C", "/tmp/claude/deep/path"]);
        let result = check_tar(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_tar_extract_to_home_not_allowed() {
        let cmd = make_cmd(&["-xf", "file.tar", "-C", "/home/user"]);
        let result = check_tar(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_tar_extract_to_tmp_not_allowed() {
        let cmd = make_cmd(&["-xf", "file.tar", "-C", "/tmp"]);
        let result = check_tar(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_tar_extract_no_directory() {
        let cmd = make_cmd(&["-xf", "file.tar"]);
        let result = check_tar(&cmd);
        assert!(result.is_none()); // passthrough, extracts to cwd
    }

    #[test]
    fn test_tar_create_not_handled() {
        let cmd = make_cmd(&["-cf", "file.tar", "/tmp/claude/test"]);
        let result = check_tar(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_tar_list_not_handled() {
        let cmd = make_cmd(&["-tf", "file.tar"]);
        let result = check_tar(&cmd);
        assert!(result.is_none());
    }
}
