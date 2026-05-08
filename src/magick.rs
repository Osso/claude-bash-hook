//! magick / convert command special handling
//!
//! Auto-allows `magick` and `convert` when every path-like argument
//! resolves under /tmp/.

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use std::process::Command as ProcessCommand;

const REALPATH: &str = "/usr/bin/realpath";

/// Check if a magick/convert command should be auto-allowed.
/// Allows when at least one arg is path-like and every path-like
/// arg resolves under /tmp/.
pub fn check_magick(cmd: &Command) -> Option<PermissionResult> {
    if cmd.name != "magick" && cmd.name != "convert" {
        return None;
    }

    let mut saw_path = false;
    for arg in &cmd.args {
        if is_flag(arg) || !is_path_like(arg) {
            continue;
        }
        saw_path = true;
        if !is_safe_tmp_path(arg) {
            return None;
        }
    }

    if !saw_path {
        return None;
    }

    Some(PermissionResult {
        permission: Permission::Allow,
        reason: format!("{} on /tmp paths", cmd.name),
        suggestion: None,
    })
}

fn is_flag(arg: &str) -> bool {
    arg.starts_with('-') || arg.starts_with('+')
}

/// Path-like: contains a slash. Magick non-path args (geometry like
/// `360x60+550+520`, format strings like `xc:white`, `info:`) never
/// contain `/`.
fn is_path_like(arg: &str) -> bool {
    arg.contains('/')
}

fn is_safe_tmp_path(path: &str) -> bool {
    if path.is_empty() || path.contains('\0') || path.contains('\n') {
        return false;
    }

    let Some(resolved) = resolve_path(path).or_else(|| resolve_existing_parent(path)) else {
        return false;
    };
    is_under_tmp(&resolved)
}

fn resolve_existing_parent(path: &str) -> Option<String> {
    let parent = std::path::Path::new(path).parent()?;
    let parent = parent.to_str()?;
    (!parent.is_empty())
        .then_some(parent)
        .and_then(resolve_path)
}

fn is_under_tmp(resolved: &str) -> bool {
    if !resolved.starts_with("/tmp/") {
        return false;
    }
    let after = &resolved[5..];
    !after.is_empty() && !after.chars().all(|c| c == '/')
}

fn resolve_path(path: &str) -> Option<String> {
    let output = ProcessCommand::new(REALPATH)
        .arg("-m")
        .arg("--")
        .arg(path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    let resolved = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!resolved.is_empty()).then_some(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        Command {
            name: name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn magick_tmp_input_only() {
        let cmd = make_cmd(
            "magick",
            &[
                "/tmp/claude/guild-buttons.webp",
                "-crop",
                "360x60+550+520",
                "+repage",
                "-resize",
                "1440x240",
            ],
        );
        let result = check_magick(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn magick_tmp_input_and_output() {
        let cmd = make_cmd(
            "magick",
            &["/tmp/in.png", "-resize", "100x100", "/tmp/out.png"],
        );
        let result = check_magick(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn magick_home_input_blocks() {
        let cmd = make_cmd("magick", &["/home/user/in.png", "/tmp/out.png"]);
        assert!(check_magick(&cmd).is_none());
    }

    #[test]
    fn magick_home_output_blocks() {
        let cmd = make_cmd("magick", &["/tmp/in.png", "/home/user/out.png"]);
        assert!(check_magick(&cmd).is_none());
    }

    #[test]
    fn convert_tmp_paths() {
        let cmd = make_cmd("convert", &["/tmp/a.png", "/tmp/b.png"]);
        let result = check_magick(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn magick_no_path_args_falls_through() {
        let cmd = make_cmd("magick", &["xc:white", "info:"]);
        assert!(check_magick(&cmd).is_none());
    }

    #[test]
    fn not_magick_command() {
        let cmd = make_cmd("ls", &["/tmp/foo"]);
        assert!(check_magick(&cmd).is_none());
    }

    #[test]
    fn relative_path_blocks() {
        let cmd = make_cmd("magick", &["./local.png", "/tmp/out.png"]);
        assert!(check_magick(&cmd).is_none());
    }
}
