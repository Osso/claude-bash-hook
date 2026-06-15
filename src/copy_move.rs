//! Write-target guarding for file-mutating commands.
//!
//! Commands that create or modify files at a path argument — cp/mv/install/ln
//! (destination), mkdir/touch (every path), chmod/chown/chgrp (every path) —
//! are checked against the write-protected paths (`ask_paths` or
//! `ask_write_paths`). When a target falls under one, we force an explicit
//! prompt instead of letting the blanket allow rule pass it. Reads are
//! unaffected; only the write target matters here.

use crate::analyzer::Command;
use crate::config::{Config, Permission, PermissionResult};
use std::path::Path;

/// cp/mv/install/ln options that consume the following argument (separated
/// form), whose value must not be mistaken for a source/destination.
const DEST_OPTS_WITH_ARG: &[&str] = &[
    "-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "--suffix",
];

/// Per-command options that consume the following argument for the
/// "every positional is a target" commands. Their values are not write
/// targets (modes, dates, reference files) and must be skipped.
fn opts_with_arg_for(command: &str) -> &'static [&'static str] {
    match command {
        "mkdir" => &["-m", "--mode"],
        // touch -r REFERENCE is a read; -d/-t are timestamps, not paths.
        "touch" => &["-d", "--date", "-r", "--reference", "-t", "--time"],
        // --reference/--from values are read sources, not targets.
        "chmod" => &["--reference"],
        "chown" | "chgrp" => &["--reference", "--from"],
        _ => &[],
    }
}

/// Check whether a file-mutating command writes to a protected target.
/// Returns `Ask` if so, otherwise `None` (let normal rules decide).
pub fn check_write_command(
    cmd: &Command,
    config: &Config,
    virtual_cwd: Option<&str>,
) -> Option<PermissionResult> {
    for dest in write_targets(cmd) {
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

/// Compression tools that create/replace files in place.
fn is_compression_command(command: &str) -> bool {
    matches!(
        command,
        "gzip"
            | "gunzip"
            | "bzip2"
            | "bunzip2"
            | "xz"
            | "unxz"
            | "zstd"
            | "unzstd"
            | "lzma"
            | "unlzma"
            | "compress"
    )
}

/// True if `command` is a file-mutating command this module guards.
pub fn is_write_command(command: &str) -> bool {
    matches!(
        command,
        "cp" | "mv" | "install" | "ln" | "mkdir" | "touch" | "chmod" | "chown" | "chgrp"
    ) || is_compression_command(command)
}

/// Extract the path(s) a command writes to, per its argument grammar.
fn write_targets(cmd: &Command) -> Vec<String> {
    match cmd.name.as_str() {
        // Destination is the last positional (or an explicit target directory).
        "cp" | "mv" | "install" | "ln" => destination_paths(cmd),
        // Every positional path is created or modified in place. Leading
        // specs (mode/owner) are not absolute paths, so they never match a
        // protected glob and are harmless to include.
        "mkdir" | "touch" | "chmod" | "chown" | "chgrp" => all_positional_targets(cmd),
        name if is_compression_command(name) => compression_targets(cmd),
        _ => Vec::new(),
    }
}

/// Targets of a compression command. The named files are compressed/decompressed
/// in place (creating e.g. `foo.gz` and removing `foo`). Stdout/test/list modes
/// don't touch a file path, so they have no targets (a `>` redirect, if any, is
/// caught by the redirect guard).
fn compression_targets(cmd: &Command) -> Vec<String> {
    const READ_ONLY_FLAGS: &[&str] = &[
        "-c",
        "--stdout",
        "--to-stdout",
        "-t",
        "--test",
        "-l",
        "--list",
        "-L",
        "--license",
        "-V",
        "--version",
        "-h",
        "--help",
    ];
    const OPTS_WITH_ARG: &[&str] = &[
        "-S",
        "--suffix",
        "-T",
        "--threads",
        "-b",
        "--block-size",
        "-F",
        "--format",
        "-C",
        "--check",
    ];

    if cmd
        .args
        .iter()
        .any(|a| READ_ONLY_FLAGS.contains(&a.as_str()))
    {
        return Vec::new();
    }

    let mut targets = Vec::new();
    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        if matches!(arg.as_str(), "-o" | "--output") {
            if let Some(out) = iter.next() {
                targets.push(out.clone()); // explicit output path (zstd/xz)
            }
            continue;
        }
        if OPTS_WITH_ARG.contains(&arg.as_str()) {
            iter.next();
            continue;
        }
        if arg.starts_with('-') && arg != "-" {
            continue;
        }
        targets.push(arg.clone());
    }
    targets
}

/// Collect every positional argument as a write target, skipping flags and the
/// values of options that take an argument.
fn all_positional_targets(cmd: &Command) -> Vec<String> {
    let opts_with_arg = opts_with_arg_for(&cmd.name);
    let mut targets = Vec::new();
    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        if opts_with_arg.contains(&arg.as_str()) {
            iter.next(); // skip the option's value
            continue;
        }
        if arg.starts_with('-') && arg != "-" {
            continue;
        }
        targets.push(arg.clone());
    }
    targets
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
        if DEST_OPTS_WITH_ARG.contains(&arg.as_str()) {
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
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_mv_to_protected_bin() {
        let cmd = make_cmd("mv", &["a", "b", "/usr/bin/"]);
        // /usr/bin/ won't match /usr/bin/* (needs a child), but /usr/* would.
        let result = check_write_command(&cmd, &cfg(&["/usr/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_cp_to_unprotected() {
        let cmd = make_cmd("cp", &["a", "/home/user/b"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_cp_source_in_protected_dest_safe() {
        // Reading FROM a protected dir is fine; only the destination is guarded.
        let cmd = make_cmd("cp", &["/usr/bin/tool", "/home/user/tool"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_cp_target_directory_flag() {
        let cmd = make_cmd("cp", &["-t", "/usr/local/bin", "a", "b"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/local/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_cp_target_directory_eq() {
        let cmd = make_cmd("cp", &["--target-directory=/usr/local/bin", "a"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/local/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_cp_target_directory_glued() {
        let cmd = make_cmd("cp", &["-t/usr/local/bin", "a"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/local/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_install_mode_skips_value() {
        // -m 755 must not be treated as the destination.
        let cmd = make_cmd("install", &["-m", "755", "myfile", "/usr/bin/myfile"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_install_directory_mode() {
        let cmd = make_cmd("install", &["-d", "/usr/lib/foo"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_relative_dest_with_virtual_cwd() {
        let cmd = make_cmd("cp", &["a", "bin/tool"]);
        let result =
            check_write_command(&cmd, &cfg(&["/usr/local/*"]), Some("/usr/local")).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_not_copy_move_command() {
        let cmd = make_cmd("ls", &["/usr/bin"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_ask_paths_also_protects() {
        // ask_paths (universal) should also trigger the write guard.
        let cfg: Config = toml::from_str(r#"ask_paths = ["/etc/*"]"#).expect("config");
        let cmd = make_cmd("cp", &["a", "/etc/passwd"]);
        let result = check_write_command(&cmd, &cfg, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_ln_symlink_into_protected() {
        // Link location (last positional) is the write; the target is ignored.
        let cmd = make_cmd("ln", &["-s", "/home/user/real", "/usr/bin/link"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_ln_target_in_protected_safe() {
        // Pointing a link AT a protected path (but creating it elsewhere) is fine.
        let cmd = make_cmd("ln", &["-s", "/usr/bin/real", "/home/user/link"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_mkdir_protected() {
        let cmd = make_cmd("mkdir", &["-p", "/usr/lib/newdir"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_mkdir_mode_skips_value() {
        // -m 0755 must not trip; the dir is unprotected.
        let cmd = make_cmd("mkdir", &["-m", "0755", "/home/user/d"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_touch_protected() {
        let cmd = make_cmd("touch", &["/usr/bin/foo"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_touch_reference_is_read_not_target() {
        // -r REFERENCE is a read source; only the trailing file is written.
        let cmd = make_cmd("touch", &["-r", "/usr/bin/ref", "/home/user/out"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_chmod_protected_target() {
        // Mode spec (755) is the first positional; the file is the target.
        let cmd = make_cmd("chmod", &["755", "/usr/bin/foo"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_chmod_recursive_protected() {
        let cmd = make_cmd("chmod", &["-R", "u+w", "/usr/lib"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_chown_protected_target() {
        let cmd = make_cmd("chown", &["root:root", "/usr/bin/foo"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_chgrp_unprotected() {
        let cmd = make_cmd("chgrp", &["staff", "/home/user/file"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_gzip_protected_asks() {
        let cmd = make_cmd("gzip", &["/usr/bin/foo"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_gzip_stdout_is_read_only() {
        // gzip -c writes stdout, not the named file; no target.
        let cmd = make_cmd("gzip", &["-c", "/usr/bin/foo"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_gunzip_protected_asks() {
        let cmd = make_cmd("gunzip", &["/usr/lib/foo.gz"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_zstd_output_path_asks() {
        let cmd = make_cmd("zstd", &["in", "-o", "/usr/bin/out.zst"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/bin/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_gzip_suffix_value_skipped() {
        // -S .z value must not be treated as a target; the file is unprotected.
        let cmd = make_cmd("gzip", &["-S", ".z", "/home/user/foo"]);
        let result = check_write_command(&cmd, &cfg(&["/usr/*"]), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_is_write_command() {
        for c in [
            "cp", "mv", "install", "ln", "mkdir", "touch", "chmod", "chown", "chgrp", "gzip",
            "gunzip", "xz", "zstd",
        ] {
            assert!(is_write_command(c), "{c} should be a write command");
        }
        for c in ["ls", "cat", "rm", "tee", "zcat", "zgrep"] {
            assert!(!is_write_command(c), "{c} should not be a write command");
        }
    }
}
