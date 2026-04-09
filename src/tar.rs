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
pub fn check_tar(
    cmd: &Command,
    virtual_cwd: Option<&str>,
    has_uncertain_flow: bool,
) -> Option<PermissionResult> {
    if cmd.name != "tar" {
        return None;
    }

    match tar_mode(&cmd.args) {
        TarMode::List => Some(allow_reason("tar list (read-only)")),
        TarMode::Extract => allow_tar_extract(&cmd.args, virtual_cwd, has_uncertain_flow),
        TarMode::Other => None,
    }
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

fn allow_tar_extract(
    args: &[String],
    virtual_cwd: Option<&str>,
    has_uncertain_flow: bool,
) -> Option<PermissionResult> {
    if let Some(dir) = find_target_dir(args) {
        return is_safe_tmp_claude_path(dir).then(|| allow_reason("tar extract to /tmp/claude"));
    }

    (!has_uncertain_flow && is_cwd_safe(virtual_cwd))
        .then(|| allow_reason("tar extract (cwd in /tmp/claude)"))
}

fn allow_reason(reason: &str) -> PermissionResult {
    PermissionResult {
        permission: Permission::Allow,
        reason: reason.to_string(),
        suggestion: None,
    }
}

#[derive(Clone, Copy)]
enum TarMode {
    List,
    Extract,
    Other,
}

fn tar_mode(args: &[String]) -> TarMode {
    if args.iter().any(|arg| is_tar_list_flag(arg)) {
        return TarMode::List;
    }
    if args.iter().any(|arg| is_tar_extract_flag(arg)) {
        return TarMode::Extract;
    }
    TarMode::Other
}

fn is_tar_list_flag(arg: &str) -> bool {
    arg == "-t"
        || arg == "-tf"
        || arg == "-tzf"
        || arg == "-tjf"
        || arg == "-tJf"
        || arg.starts_with("-t")
        || (arg.starts_with('-') && arg.contains('t') && !arg.contains('x'))
}

fn is_tar_extract_flag(arg: &str) -> bool {
    arg == "-x"
        || arg == "-xf"
        || arg == "-xzf"
        || arg == "-xjf"
        || arg == "-xJf"
        || arg.starts_with("-x")
        || arg.contains('x')
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
