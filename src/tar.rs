//! tar command special handling
//!
//! Auto-allows tar extraction to /tmp/claude/

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use std::process::Command as ProcessCommand;

const SAFE_PREFIX: &str = "/tmp/claude/";

/// Check if a tar command should be auto-allowed
/// Allows:
/// - List mode (tar -t) - read-only
/// - Extraction to /tmp/claude/ subdirectories
pub fn check_tar(cmd: &Command, virtual_cwd: Option<&str>, has_uncertain_flow: bool) -> Option<PermissionResult> {
    if cmd.name != "tar" {
        return None;
    }

    // Check if this is a list operation (read-only, always allow)
    let is_list = cmd.args.iter().any(|a| {
        a == "-t" || a == "-tf" || a == "-tzf" || a == "-tjf" || a == "-tJf"
            || a.starts_with("-t")
            || (a.starts_with('-') && a.contains('t') && !a.contains('x'))
    });

    if is_list {
        return Some(PermissionResult {
            permission: Permission::Allow,
            reason: "tar list (read-only)".to_string(),
            suggestion: None,
        });
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

    if let Some(dir) = target_dir {
        if is_safe_tmp_claude_path(dir) {
            return Some(PermissionResult {
                permission: Permission::Allow,
                reason: "tar extract to /tmp/claude".to_string(),
                suggestion: None,
            });
        }
        // Explicit -C to non-safe path - passthrough
        return None;
    }

    // No -C specified - allow if current directory (or virtual cwd) is under /tmp/claude/
    // But NOT if there's uncertain control flow (cd might have changed in conditional)
    if !has_uncertain_flow && is_cwd_safe(virtual_cwd) {
        return Some(PermissionResult {
            permission: Permission::Allow,
            reason: "tar extract (cwd in /tmp/claude)".to_string(),
            suggestion: None,
        });
    }

    // Passthrough
    None
}

/// Check if cwd (real or virtual) is under /tmp/claude/
fn is_cwd_safe(virtual_cwd: Option<&str>) -> bool {
    // First check virtual_cwd (from cd commands in the chain)
    if let Some(vcwd) = virtual_cwd {
        if let Some(resolved) = resolve_path(vcwd) {
            if resolved.starts_with(SAFE_PREFIX) {
                return true;
            }
        }
    }

    // Fall back to actual cwd
    is_cwd_under_tmp_claude()
}

/// Check if current working directory is under /tmp/claude/
fn is_cwd_under_tmp_claude() -> bool {
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(cwd_str) = cwd.to_str() {
            if let Some(resolved) = resolve_path(cwd_str) {
                return resolved.starts_with(SAFE_PREFIX);
            }
        }
    }
    false
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
        let result = check_tar(&cmd, None, false).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_tar_extract_to_tmp_claude_subdir() {
        let cmd = make_cmd(&["-xzf", "file.tar.gz", "-C", "/tmp/claude/deep/path"]);
        let result = check_tar(&cmd, None, false).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_tar_extract_to_home_not_allowed() {
        let cmd = make_cmd(&["-xf", "file.tar", "-C", "/home/user"]);
        let result = check_tar(&cmd, None, false);
        assert!(result.is_none());
    }

    #[test]
    fn test_tar_extract_to_tmp_not_allowed() {
        let cmd = make_cmd(&["-xf", "file.tar", "-C", "/tmp"]);
        let result = check_tar(&cmd, None, false);
        assert!(result.is_none());
    }

    #[test]
    fn test_tar_extract_no_directory() {
        let cmd = make_cmd(&["-xf", "file.tar"]);
        let result = check_tar(&cmd, None, false);
        assert!(result.is_none()); // passthrough, extracts to cwd (not /tmp/claude)
    }

    #[test]
    fn test_tar_extract_with_virtual_cwd() {
        // Simulates: cd /tmp/claude/dir && tar -xf file.tar
        let cmd = make_cmd(&["-xf", "file.tar"]);
        let result = check_tar(&cmd, Some("/tmp/claude/mydir"), false).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_tar_extract_with_virtual_cwd_unsafe() {
        // Simulates: cd /home/user && tar -xf file.tar
        let cmd = make_cmd(&["-xf", "file.tar"]);
        let result = check_tar(&cmd, Some("/home/user"), false);
        assert!(result.is_none());
    }

    #[test]
    fn test_tar_extract_with_uncertain_flow() {
        // Simulates: if true; then cd /; fi && tar -xf file.tar
        // Even with virtual_cwd in /tmp/claude, uncertain flow should passthrough
        let cmd = make_cmd(&["-xf", "file.tar"]);
        let result = check_tar(&cmd, Some("/tmp/claude/mydir"), true);
        assert!(result.is_none());
    }

    #[test]
    fn test_tar_extract_explicit_c_with_uncertain_flow() {
        // Explicit -C /tmp/claude is still allowed even with uncertain flow
        let cmd = make_cmd(&["-xf", "file.tar", "-C", "/tmp/claude/dir"]);
        let result = check_tar(&cmd, None, true).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_tar_create_not_handled() {
        let cmd = make_cmd(&["-cf", "file.tar", "/tmp/claude/test"]);
        let result = check_tar(&cmd, None, false);
        assert!(result.is_none());
    }

    #[test]
    fn test_tar_list_allowed() {
        let cmd = make_cmd(&["-tf", "file.tar"]);
        let result = check_tar(&cmd, None, false).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_tar_list_verbose_allowed() {
        let cmd = make_cmd(&["-tvf", "file.tar"]);
        let result = check_tar(&cmd, None, false).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
