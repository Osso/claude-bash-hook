//! Docker command special handling

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Find the index of the compose subcommand (exec, run, ps, etc.)
/// Skips compose-level options like -f, --file, -p, --project-name
fn find_compose_subcommand(cmd: &Command) -> usize {
    let compose_opts_with_args = ["-f", "--file", "-p", "--project-name", "--env-file"];
    let mut i = 1;
    while i < cmd.args.len() {
        let arg = &cmd.args[i];
        if arg.starts_with('-') {
            if arg.contains('=') {
                i += 1;
            } else if compose_opts_with_args.iter().any(|o| *o == arg) {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            break;
        }
    }
    i
}

/// Check if a docker run should be allowed
/// Allows if no read-write bind mounts are present
pub fn check_docker_run(cmd: &Command) -> Option<PermissionResult> {
    // Only handle docker run
    if cmd.name != "docker" || cmd.args.first().map(|s| s.as_str()) != Some("run") {
        return None;
    }

    let args: Vec<&str> = cmd.args.iter().skip(1).map(|s| s.as_str()).collect();

    // Check for read-write bind mounts
    if has_rw_bind_mount(&args) {
        return Some(PermissionResult {
            permission: Permission::Passthrough,
            reason: "docker run with read-write bind mount".to_string(),
            suggestion: None,
        });
    }

    // No rw bind mounts - allow
    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "docker run (no rw bind mounts)".to_string(),
        suggestion: None,
    })
}

/// Check if a docker compose exec should be allowed
/// Allows locally (container already running with its mounts), falls through for remote
pub fn check_docker_compose_exec(cmd: &Command, is_remote: bool) -> Option<PermissionResult> {
    if cmd.name != "docker" || cmd.args.first().map(|s| s.as_str()) != Some("compose") {
        return None;
    }

    let subcommand_idx = find_compose_subcommand(cmd);

    if cmd.args.get(subcommand_idx).map(|s| s.as_str()) != Some("exec") {
        return None;
    }

    if is_remote {
        // Remote: fall through to wrapper behavior (analyze inner command)
        return None;
    }

    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "docker compose exec (local)".to_string(),
        suggestion: None,
    })
}

/// Check if a docker compose run should be allowed
/// Allows if no read-write bind mounts are present
pub fn check_docker_compose_run(cmd: &Command) -> Option<PermissionResult> {
    if cmd.name != "docker" || cmd.args.first().map(|s| s.as_str()) != Some("compose") {
        return None;
    }

    let i = find_compose_subcommand(cmd);

    // Check if subcommand is 'run'
    if cmd.args.get(i).map(|s| s.as_str()) != Some("run") {
        return None;
    }

    // Get args after 'run'
    let args: Vec<&str> = cmd.args[i + 1..].iter().map(|s| s.as_str()).collect();

    // Check for read-write bind mounts
    if has_rw_bind_mount(&args) {
        return Some(PermissionResult {
            permission: Permission::Passthrough,
            reason: "docker compose run with read-write bind mount".to_string(),
            suggestion: None,
        });
    }

    // No rw bind mounts - allow
    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "docker compose run (no rw bind mounts)".to_string(),
        suggestion: None,
    })
}

/// Check if args contain any read-write bind mounts
fn has_rw_bind_mount(args: &[&str]) -> bool {
    let mut i = 0;
    while i < args.len() {
        if has_inline_rw_mount(args[i]) || has_following_rw_mount(args, i) {
            return true;
        }

        i += consumed_mount_args(args, i);
    }

    false
}

fn has_inline_rw_mount(arg: &str) -> bool {
    arg.strip_prefix("-v=")
        .map(is_rw_bind_mount)
        .or_else(|| arg.strip_prefix("--volume=").map(is_rw_bind_mount))
        .or_else(|| arg.strip_prefix("--mount=").map(is_rw_mount))
        .unwrap_or(false)
}

fn has_following_rw_mount(args: &[&str], index: usize) -> bool {
    let arg = args[index];
    if arg == "-v" || arg == "--volume" {
        return args
            .get(index + 1)
            .is_some_and(|volume| is_rw_bind_mount(volume));
    }
    if arg == "--mount" {
        return args.get(index + 1).is_some_and(|mount| is_rw_mount(mount));
    }
    false
}

fn consumed_mount_args(args: &[&str], index: usize) -> usize {
    match args[index] {
        "-v" | "--volume" | "--mount" if args.get(index + 1).is_some() => 2,
        _ => 1,
    }
}

/// Check if a -v volume spec is a dangerous read-write bind mount
/// Format: [host-src:]container-dest[:options]
/// Returns false (safe) for: named volumes, ro mounts, /tmp mounts
fn is_rw_bind_mount(volume: &str) -> bool {
    let parts: Vec<&str> = volume.split(':').collect();

    // Need at least host:container to be a bind mount
    if parts.len() < 2 {
        return false;
    }

    let host_path = parts[0];

    // Named volumes (no path separator) are not bind mounts
    if !host_path.starts_with('/') && !host_path.starts_with('.') && !host_path.starts_with('~') {
        return false;
    }

    // Check if read-only
    if parts.len() >= 3 {
        let options = parts[2..].join(":");
        if options.contains("ro") || options.contains("readonly") {
            return false;
        }
    }

    // Allow /tmp mounts - safe for ephemeral data
    if host_path.starts_with("/tmp/") || host_path == "/tmp" {
        return false;
    }

    // It's a bind mount without ro to a non-tmp path - potentially dangerous
    true
}

/// Check if a --mount spec is a dangerous read-write bind mount
/// Format: type=bind,source=/src,target=/dest[,readonly]
/// Returns false (safe) for: non-bind mounts, readonly, /tmp sources
fn is_rw_mount(mount: &str) -> bool {
    let mut is_bind = false;
    let mut is_readonly = false;
    let mut source_path = "";

    for part in mount.split(',') {
        if part == "type=bind" {
            is_bind = true;
        }
        if part == "readonly" || part == "readonly=true" || part == "ro" || part == "ro=true" {
            is_readonly = true;
        }
        if let Some(src) = part.strip_prefix("source=") {
            source_path = src;
        } else if let Some(src) = part.strip_prefix("src=") {
            source_path = src;
        }
    }

    // Not a bind mount or readonly - safe
    if !is_bind || is_readonly {
        return false;
    }

    // /tmp mounts are safe
    if source_path.starts_with("/tmp/") || source_path == "/tmp" {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_command;

    fn make_cmd(args: &[&str]) -> Command {
        make_command("docker", args)
    }

    #[test]
    fn test_docker_run_no_volumes() {
        let cmd = make_cmd(&["run", "ubuntu", "ls"]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_run_named_volume() {
        let cmd = make_cmd(&["run", "-v", "myvolume:/data", "ubuntu"]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_run_bind_mount_ro() {
        let cmd = make_cmd(&["run", "-v", "/host/path:/container:ro", "ubuntu"]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_run_bind_mount_rw() {
        let cmd = make_cmd(&["run", "-v", "/host/path:/container", "ubuntu"]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_docker_run_bind_mount_tmp() {
        // /tmp mounts are allowed
        let cmd = make_cmd(&["run", "-v", "/tmp/output:/container", "ubuntu"]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_run_bind_mount_relative() {
        let cmd = make_cmd(&["run", "-v", "./local:/container", "ubuntu"]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_docker_run_mount_bind_rw() {
        let cmd = make_cmd(&[
            "run",
            "--mount",
            "type=bind,source=/src,target=/dst",
            "ubuntu",
        ]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_docker_run_mount_bind_readonly() {
        let cmd = make_cmd(&[
            "run",
            "--mount",
            "type=bind,source=/src,target=/dst,readonly",
            "ubuntu",
        ]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_run_mount_volume() {
        let cmd = make_cmd(&[
            "run",
            "--mount",
            "type=volume,source=myvolume,target=/dst",
            "ubuntu",
        ]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_run_volume_equals_syntax() {
        let cmd = make_cmd(&["run", "-v=/host:/container", "ubuntu"]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_docker_ps_not_handled() {
        let cmd = make_cmd(&["ps"]);
        let result = check_docker_run(&cmd);
        assert!(result.is_none());
    }

    // docker compose run tests

    #[test]
    fn test_docker_compose_run_no_volumes() {
        let cmd = make_cmd(&["compose", "run", "web", "pytest"]);
        let result = check_docker_compose_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_compose_run_with_file_flag() {
        let cmd = make_cmd(&["compose", "-f", "docker-compose.test.yml", "run", "test"]);
        let result = check_docker_compose_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_compose_run_bind_mount_tmp() {
        // /tmp mounts are allowed
        let cmd = make_cmd(&["compose", "run", "-v", "/tmp/test:/output", "test"]);
        let result = check_docker_compose_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_compose_run_bind_mount_rw() {
        // Non-tmp rw mounts need confirmation
        let cmd = make_cmd(&["compose", "run", "-v", "/home/user:/output", "test"]);
        let result = check_docker_compose_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_docker_compose_run_bind_mount_ro() {
        let cmd = make_cmd(&["compose", "run", "-v", "/tmp:/output:ro", "test"]);
        let result = check_docker_compose_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_compose_run_named_volume() {
        let cmd = make_cmd(&["compose", "run", "-v", "myvolume:/data", "test"]);
        let result = check_docker_compose_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_compose_exec_not_handled_by_run() {
        let cmd = make_cmd(&["compose", "exec", "web", "bash"]);
        let result = check_docker_compose_run(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_docker_compose_ps_not_handled() {
        let cmd = make_cmd(&["compose", "ps"]);
        let result = check_docker_compose_run(&cmd);
        assert!(result.is_none());
    }

    // docker compose exec tests

    #[test]
    fn test_docker_compose_exec_local_allowed() {
        let cmd = make_cmd(&["compose", "exec", "web", "bash"]);
        let result = check_docker_compose_exec(&cmd, false).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_compose_exec_with_file_flag_local() {
        let cmd = make_cmd(&["compose", "-f", "docker-compose.yml", "exec", "web", "ls"]);
        let result = check_docker_compose_exec(&cmd, false).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_compose_exec_remote_falls_through() {
        let cmd = make_cmd(&["compose", "exec", "web", "bash"]);
        let result = check_docker_compose_exec(&cmd, true);
        assert!(result.is_none());
    }

    #[test]
    fn test_docker_compose_exec_not_run() {
        let cmd = make_cmd(&["compose", "run", "web", "pytest"]);
        let result = check_docker_compose_exec(&cmd, false);
        assert!(result.is_none());
    }

    #[test]
    fn test_docker_compose_exec_not_ps() {
        let cmd = make_cmd(&["compose", "ps"]);
        let result = check_docker_compose_exec(&cmd, false);
        assert!(result.is_none());
    }
}
