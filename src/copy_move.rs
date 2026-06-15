//! cp/mv/install destination guarding
//!
//! These commands write to their destination argument. When that destination
//! falls under a write-protected path (`ask_paths` or `ask_write_paths`) we
//! force an explicit prompt instead of letting the blanket allow rule pass it.
//! Reads are unaffected; only the write target matters here.

use crate::analyzer::Command;
use crate::config::{Config, Permission, PermissionResult};
use std::path::Path;

/// Non-target options that consume the following argument (separated form),
/// whose value must not be mistaken for a source/destination.
const OPTS_WITH_ARG: &[&str] = &[
    "-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "--suffix",
];

/// Check whether a cp/mv/install command writes to a protected destination.
/// Returns `Ask` if so, otherwise `None` (let normal rules decide).
pub fn check_copy_move(
    cmd: &Command,
    config: &Config,
    virtual_cwd: Option<&str>,
) -> Option<PermissionResult> {
    if !matches!(cmd.name.as_str(), "cp" | "mv" | "install") {
        return None;
    }

    for dest in destination_paths(cmd) {
        if let Some(abs) = absolute_path(&dest, virtual_cwd)
            && is_dest_protected(config, &abs)
        {
            return Some(PermissionResult {
                permission: Permission::Ask,
                reason: format!("{} writes to protected path {}", cmd.name, abs),
                suggestion: None,
            });
        }
    }
    None
}

/// A destination is protected if the path itself is protected (dest is the
/// written file) or if writing a child under it would be (dest is a directory
/// the command copies into).
fn is_dest_protected(config: &Config, abs: &str) -> bool {
    if config.is_write_protected(abs) {
        return true;
    }
    let child = format!("{}/x", abs.trim_end_matches('/'));
    config.is_write_protected(&child)
}

/// Determine the destination path(s) a cp/mv/install invocation writes to.
fn destination_paths(cmd: &Command) -> Vec<String> {
    let mut positionals: Vec<String> = Vec::new();
    let mut target_dir: Option<String> = None;
    let mut directory_mode = false; // install -d / --directory: every positional is a target

    let mut iter = cmd.args.iter().peekable();
    while let Some(arg) = iter.next() {
        if matches!(arg.as_str(), "-t" | "--target-directory") {
            target_dir = iter.next().cloned(); // separated form: -t DIR
            continue;
        }
        if let Some(dir) = target_dir_from_arg(arg) {
            target_dir = Some(dir); // glued/eq form: -tDIR, --target-directory=DIR
            continue;
        }
        if matches!(arg.as_str(), "-d" | "--directory") {
            directory_mode = true;
            continue;
        }
        if OPTS_WITH_ARG.contains(&arg.as_str()) {
            iter.next(); // skip the option's value
            continue;
        }
        if arg.starts_with('-') && arg != "-" {
            continue; // some other flag
        }
        positionals.push(arg.clone());
    }

    if let Some(dir) = target_dir {
        return vec![dir];
    }
    if directory_mode {
        return positionals; // all args are directories to create
    }
    // Last positional is the destination; everything before it is a source.
    positionals.into_iter().next_back().into_iter().collect()
}

/// Extract a target directory from a `-tDIR` or `--target-directory=DIR` arg.
fn target_dir_from_arg(arg: &str) -> Option<String> {
    if let Some(dir) = arg.strip_prefix("--target-directory=") {
        return Some(dir.to_string());
    }
    if arg.len() > 2 && arg.starts_with("-t") {
        return Some(arg[2..].to_string());
    }
    None
}

fn absolute_path(path: &str, virtual_cwd: Option<&str>) -> Option<String> {
    if path.is_empty() || path.contains('\0') || path.contains('\n') {
        return None;
    }
    if Path::new(path).is_absolute() {
        return Some(path.to_string());
    }
    virtual_cwd.map(|cwd| format!("{}/{}", cwd.trim_end_matches('/'), path))
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

    fn cfg(patterns: &[&str]) -> Config {
        let list: Vec<String> = patterns.iter().map(|s| format!("\"{}\"", s)).collect();
        toml::from_str(&format!("ask_write_paths = [{}]", list.join(", "))).expect("config")
    }

    #[test]
    fn test_cp_to_protected_bin() {
        let cmd = make_cmd("cp", &["myfile", "/usr/bin/myfile"]);
        let result = check_copy_move(&cmd, &cfg(&["/usr/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_mv_to_protected_bin() {
        let cmd = make_cmd("mv", &["a", "b", "/usr/bin/"]);
        // /usr/bin/ won't match /usr/bin/* (needs a child), but /usr/* would.
        let result = check_copy_move(&cmd, &cfg(&["/usr/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_cp_to_unprotected() {
        let cmd = make_cmd("cp", &["a", "/home/user/b"]);
        let result = check_copy_move(&cmd, &cfg(&["/usr/bin/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_cp_source_in_protected_dest_safe() {
        // Reading FROM a protected dir is fine; only the destination is guarded.
        let cmd = make_cmd("cp", &["/usr/bin/tool", "/home/user/tool"]);
        let result = check_copy_move(&cmd, &cfg(&["/usr/bin/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_cp_target_directory_flag() {
        let cmd = make_cmd("cp", &["-t", "/usr/local/bin", "a", "b"]);
        let result = check_copy_move(&cmd, &cfg(&["/usr/local/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_cp_target_directory_eq() {
        let cmd = make_cmd("cp", &["--target-directory=/usr/local/bin", "a"]);
        let result = check_copy_move(&cmd, &cfg(&["/usr/local/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_cp_target_directory_glued() {
        let cmd = make_cmd("cp", &["-t/usr/local/bin", "a"]);
        let result = check_copy_move(&cmd, &cfg(&["/usr/local/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_install_mode_skips_value() {
        // -m 755 must not be treated as the destination.
        let cmd = make_cmd("install", &["-m", "755", "myfile", "/usr/bin/myfile"]);
        let result = check_copy_move(&cmd, &cfg(&["/usr/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_install_directory_mode() {
        let cmd = make_cmd("install", &["-d", "/usr/lib/foo"]);
        let result = check_copy_move(&cmd, &cfg(&["/usr/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_relative_dest_with_virtual_cwd() {
        let cmd = make_cmd("cp", &["a", "bin/tool"]);
        let result = check_copy_move(&cmd, &cfg(&["/usr/local/*"]), Some("/usr/local")).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_not_copy_move_command() {
        let cmd = make_cmd("ls", &["/usr/bin"]);
        let result = check_copy_move(&cmd, &cfg(&["/usr/bin/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_ask_paths_also_protects() {
        // ask_paths (universal) should also trigger the write guard.
        let cfg: Config = toml::from_str(r#"ask_paths = ["/etc/*"]"#).expect("config");
        let cmd = make_cmd("cp", &["a", "/etc/passwd"]);
        let result = check_copy_move(&cmd, &cfg, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }
}
