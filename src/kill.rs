//! Kill command analysis - prevent dangerous kill operations

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Check if a kill command targets dangerous PIDs
/// Returns Some(Deny) if dangerous, None otherwise to allow normal processing
pub fn check_kill(cmd: &Command) -> Option<PermissionResult> {
    // Look for dangerous PID arguments
    for arg in &cmd.args {
        // Skip signal flags like -9, -TERM, -s, etc.
        if arg.starts_with('-') && !arg.chars().skip(1).all(|c| c.is_ascii_digit()) {
            continue;
        }

        // Check for PID 1 (init/systemd)
        if arg == "1" {
            return Some(PermissionResult {
                permission: Permission::Deny,
                reason: "kill PID 1 (init/systemd) is dangerous".to_string(),
                suggestion: None,
            });
        }

        // Check for -1 (all processes)
        if arg == "-1" {
            return Some(PermissionResult {
                permission: Permission::Deny,
                reason: "kill -1 (all processes) is dangerous".to_string(),
                suggestion: None,
            });
        }
    }

    // Safe - allow
    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "kill command".to_string(),
        suggestion: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "kill".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_normal_kill_allowed() {
        let cmd = make_cmd(&["12345"]);
        let result = check_kill(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_kill_with_signal_allowed() {
        let cmd = make_cmd(&["-9", "12345"]);
        let result = check_kill(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_kill_term_allowed() {
        let cmd = make_cmd(&["-TERM", "12345"]);
        let result = check_kill(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_kill_pid_1_denied() {
        let cmd = make_cmd(&["1"]);
        let result = check_kill(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Deny);
    }

    #[test]
    fn test_kill_signal_pid_1_denied() {
        let cmd = make_cmd(&["-9", "1"]);
        let result = check_kill(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Deny);
    }

    #[test]
    fn test_kill_all_processes_denied() {
        let cmd = make_cmd(&["-1"]);
        let result = check_kill(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Deny);
    }

    #[test]
    fn test_kill_signal_all_denied() {
        let cmd = make_cmd(&["-9", "-1"]);
        let result = check_kill(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Deny);
    }

    #[test]
    fn test_kill_multiple_pids_allowed() {
        let cmd = make_cmd(&["12345", "67890"]);
        let result = check_kill(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_kill_with_pid_1_in_list_denied() {
        let cmd = make_cmd(&["12345", "1", "67890"]);
        let result = check_kill(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Deny);
    }
}
