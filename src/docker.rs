//! Docker command special handling

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

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

/// Check if args contain any read-write bind mounts
fn has_rw_bind_mount(args: &[&str]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];

        // Handle -v/--volume
        if arg == "-v" || arg == "--volume" {
            if let Some(volume) = args.get(i + 1) {
                if is_rw_bind_mount(volume) {
                    return true;
                }
                i += 2;
                continue;
            }
        }

        // Handle -v=value or --volume=value
        if let Some(volume) = arg.strip_prefix("-v=").or_else(|| arg.strip_prefix("--volume=")) {
            if is_rw_bind_mount(volume) {
                return true;
            }
            i += 1;
            continue;
        }

        // Handle --mount
        if arg == "--mount" {
            if let Some(mount) = args.get(i + 1) {
                if is_rw_mount(mount) {
                    return true;
                }
                i += 2;
                continue;
            }
        }

        // Handle --mount=value
        if let Some(mount) = arg.strip_prefix("--mount=") {
            if is_rw_mount(mount) {
                return true;
            }
            i += 1;
            continue;
        }

        i += 1;
    }

    false
}

/// Check if a -v volume spec is a read-write bind mount
/// Format: [host-src:]container-dest[:options]
/// Bind mounts have an absolute or relative host path
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

    // It's a bind mount without ro - read-write
    true
}

/// Check if a --mount spec is a read-write bind mount
/// Format: type=bind,source=/src,target=/dest[,readonly]
fn is_rw_mount(mount: &str) -> bool {
    let mut is_bind = false;
    let mut is_readonly = false;

    for part in mount.split(',') {
        if part == "type=bind" {
            is_bind = true;
        }
        if part == "readonly" || part == "readonly=true" || part == "ro" || part == "ro=true" {
            is_readonly = true;
        }
    }

    is_bind && !is_readonly
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "docker".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("docker {}", args.join(" ")),
        }
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
    fn test_docker_run_bind_mount_relative() {
        let cmd = make_cmd(&["run", "-v", "./local:/container", "ubuntu"]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_docker_run_mount_bind_rw() {
        let cmd = make_cmd(&["run", "--mount", "type=bind,source=/src,target=/dst", "ubuntu"]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Passthrough);
    }

    #[test]
    fn test_docker_run_mount_bind_readonly() {
        let cmd = make_cmd(&["run", "--mount", "type=bind,source=/src,target=/dst,readonly", "ubuntu"]);
        let result = check_docker_run(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_docker_run_mount_volume() {
        let cmd = make_cmd(&["run", "--mount", "type=volume,source=myvolume,target=/dst", "ubuntu"]);
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
}
