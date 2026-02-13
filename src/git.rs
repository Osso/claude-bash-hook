//! Git command special handling

use crate::analyzer::Command;
use crate::config::{Config, Permission, PermissionResult};
use std::process::Command as ProcessCommand;

/// Protected branch names
const PROTECTED_BRANCHES: &[&str] = &["master", "main"];

/// Check if a git checkout should be allowed
pub fn check_git_checkout(cmd: &Command) -> Option<PermissionResult> {
    // Only handle git checkout
    if cmd.name != "git" || cmd.args.first().map(|s| s.as_str()) != Some("checkout") {
        return None;
    }

    let args: Vec<&str> = cmd.args.iter().skip(1).map(|s| s.as_str()).collect();

    // git checkout -b <branch> - creating a branch is safe
    if args
        .iter()
        .any(|a| *a == "-b" || *a == "-B" || *a == "--branch")
    {
        return Some(PermissionResult {
            permission: Permission::Allow,
            reason: "create branch".to_string(),
            suggestion: None,
        });
    }

    // git checkout -- <file> or git checkout <file> - could discard changes, ask
    // git checkout <branch> - switching branches, also ask (suggest git switch)
    Some(PermissionResult {
        permission: Permission::Ask,
        reason: "checkout can discard changes".to_string(),
        suggestion: Some(
            "Consider using 'git switch <branch>' or 'git restore <file>' instead".to_string(),
        ),
    })
}

/// Check if a git reset should be allowed
/// --hard discards changes and should ask, otherwise allow
pub fn check_git_reset(cmd: &Command) -> Option<PermissionResult> {
    // Only handle git reset
    if cmd.name != "git" || cmd.args.first().map(|s| s.as_str()) != Some("reset") {
        return None;
    }

    // git reset --hard - destructive, can lose uncommitted changes
    if cmd.args.iter().any(|a| a == "--hard") {
        return Some(PermissionResult {
            permission: Permission::Deny,
            reason: "git reset --hard discards changes".to_string(),
            suggestion: None,
        });
    }

    // git reset (soft/mixed) - safe, just moves HEAD/unstages
    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "git reset (no --hard)".to_string(),
        suggestion: None,
    })
}

/// Check if a git push should be allowed
pub fn check_git_push(
    cmd: &Command,
    config: &Config,
    cwd: Option<&str>,
) -> Option<PermissionResult> {
    // Only handle git push
    if cmd.name != "git" || cmd.args.first().map(|s| s.as_str()) != Some("push") {
        return None;
    }

    let has_dangerous_force = cmd.args.iter().any(|a| a == "-f" || a == "--force");
    let has_force_with_lease = cmd.args.iter().any(|a| a == "--force-with-lease");
    let target_branch = get_push_target_branch(cmd);

    let is_protected = target_branch
        .as_ref()
        .is_some_and(|b| PROTECTED_BRANCHES.contains(&b.as_str()));

    // Force push to protected branch - always deny
    if has_dangerous_force && is_protected {
        return Some(PermissionResult {
            permission: Permission::Deny,
            reason: format!(
                "force push to protected branch '{}'",
                target_branch.as_deref().unwrap_or("unknown")
            ),
            suggestion: None,
        });
    }

    // Force push to non-protected branch - ask
    if has_dangerous_force {
        return Some(PermissionResult {
            permission: Permission::Ask,
            reason: "force push".to_string(),
            suggestion: Some("Consider using --force-with-lease for safer force push".to_string()),
        });
    }

    if is_protected {
        // Check if this directory is allowed to push to master
        let branch = target_branch.as_deref().unwrap_or("unknown");
        if config.is_master_push_allowed(cwd) {
            return Some(PermissionResult {
                permission: Permission::Allow,
                reason: format!("push to '{}' (allowed directory)", branch),
                suggestion: None,
            });
        }

        let reason = if has_force_with_lease {
            format!("force push to protected branch '{}'", branch)
        } else {
            format!("push to protected branch '{}'", branch)
        };
        return Some(PermissionResult {
            permission: Permission::Ask,
            reason,
            suggestion: None,
        });
    }

    // Allow push (including --force-with-lease) to non-protected branches
    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "git push".to_string(),
        suggestion: None,
    })
}

/// Try to determine the target branch for a git push
fn get_push_target_branch(cmd: &Command) -> Option<String> {
    let args: Vec<&str> = cmd.args.iter().skip(1).map(|s| s.as_str()).collect();

    // Skip flags and their arguments
    let mut positional: Vec<&str> = Vec::new();
    let mut skip_next = false;

    for arg in &args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if *arg == "-u" || *arg == "--set-upstream" || *arg == "-o" || *arg == "--push-option" {
            skip_next = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        positional.push(arg);
    }

    // git push [remote] [branch]
    // If branch is specified, use it
    if positional.len() >= 2 {
        let branch = positional[1];
        // Handle refspec like HEAD:main or feature:main
        if let Some(colon_pos) = branch.find(':') {
            return Some(branch[colon_pos + 1..].to_string());
        }
        return Some(branch.to_string());
    }

    // If only remote or no args, check current branch
    get_current_branch()
}

/// Get the current git branch
fn get_current_branch() -> Option<String> {
    let output = ProcessCommand::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;

    if output.status.success() {
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !branch.is_empty() && branch != "HEAD" {
            return Some(branch);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "git".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("git {}", args.join(" ")),
        }
    }

    fn default_config() -> Config {
        Config::default()
    }

    #[test]
    fn test_force_push_to_feature_asks() {
        let cmd = make_cmd(&["push", "-f", "origin", "feature-branch"]);
        let result = check_git_push(&cmd, &default_config(), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
        assert!(result.suggestion.is_some()); // suggests --force-with-lease
    }

    #[test]
    fn test_force_push_to_main_denied() {
        let cmd = make_cmd(&["push", "-f", "origin", "main"]);
        let result = check_git_push(&cmd, &default_config(), None).unwrap();
        assert_eq!(result.permission, Permission::Deny);
    }

    #[test]
    fn test_force_push_to_master_denied() {
        let cmd = make_cmd(&["push", "--force", "origin", "master"]);
        let result = check_git_push(&cmd, &default_config(), None).unwrap();
        assert_eq!(result.permission, Permission::Deny);
    }

    #[test]
    fn test_force_push_refspec_to_main_denied() {
        let cmd = make_cmd(&["push", "-f", "origin", "HEAD:main"]);
        let result = check_git_push(&cmd, &default_config(), None).unwrap();
        assert_eq!(result.permission, Permission::Deny);
    }

    #[test]
    fn test_force_with_lease_to_feature_allows() {
        let cmd = make_cmd(&["push", "--force-with-lease", "origin", "feature-branch"]);
        let result = check_git_push(&cmd, &default_config(), None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_force_with_lease_to_main_asks() {
        let cmd = make_cmd(&["push", "--force-with-lease", "origin", "main"]);
        let result = check_git_push(&cmd, &default_config(), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_push_to_master_asks() {
        let cmd = make_cmd(&["push", "origin", "master"]);
        let result = check_git_push(&cmd, &default_config(), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_push_to_main_asks() {
        let cmd = make_cmd(&["push", "origin", "main"]);
        let result = check_git_push(&cmd, &default_config(), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_push_to_feature_allows() {
        let cmd = make_cmd(&["push", "origin", "feature-branch"]);
        let result = check_git_push(&cmd, &default_config(), None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_push_refspec_to_main_asks() {
        let cmd = make_cmd(&["push", "origin", "HEAD:main"]);
        let result = check_git_push(&cmd, &default_config(), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_non_push_returns_none() {
        let cmd = make_cmd(&["status"]);
        let result = check_git_push(&cmd, &default_config(), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_push_to_master_allowed_dir() {
        let config_str = r#"
            default = "passthrough"
            master_push_allowed = ["/allowed/project"]
        "#;
        let config: Config = toml::from_str(config_str).unwrap();
        let cmd = make_cmd(&["push", "origin", "master"]);
        let result = check_git_push(&cmd, &config, Some("/allowed/project")).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_push_to_master_not_allowed_dir() {
        let config_str = r#"
            default = "passthrough"
            master_push_allowed = ["/allowed/project"]
        "#;
        let config: Config = toml::from_str(config_str).unwrap();
        let cmd = make_cmd(&["push", "origin", "master"]);
        let result = check_git_push(&cmd, &config, Some("/other/project")).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    // Git checkout tests

    #[test]
    fn test_checkout_create_branch_allows() {
        let cmd = make_cmd(&["checkout", "-b", "feature-branch"]);
        let result = check_git_checkout(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_checkout_create_branch_uppercase_allows() {
        let cmd = make_cmd(&["checkout", "-B", "feature-branch"]);
        let result = check_git_checkout(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_checkout_branch_asks() {
        let cmd = make_cmd(&["checkout", "main"]);
        let result = check_git_checkout(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
        assert!(result.suggestion.is_some());
    }

    #[test]
    fn test_checkout_file_asks() {
        let cmd = make_cmd(&["checkout", "--", "file.txt"]);
        let result = check_git_checkout(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_non_checkout_returns_none() {
        let cmd = make_cmd(&["status"]);
        let result = check_git_checkout(&cmd);
        assert!(result.is_none());
    }

    // Git reset tests

    #[test]
    fn test_reset_hard_denied() {
        let cmd = make_cmd(&["reset", "--hard"]);
        let result = check_git_reset(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Deny);
    }

    #[test]
    fn test_reset_hard_with_ref_denied() {
        let cmd = make_cmd(&["reset", "--hard", "HEAD~1"]);
        let result = check_git_reset(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Deny);
    }

    #[test]
    fn test_reset_soft_allows() {
        let cmd = make_cmd(&["reset", "--soft", "HEAD~1"]);
        let result = check_git_reset(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_reset_mixed_allows() {
        let cmd = make_cmd(&["reset", "--mixed", "HEAD~1"]);
        let result = check_git_reset(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_reset_no_flags_allows() {
        let cmd = make_cmd(&["reset", "HEAD~1"]);
        let result = check_git_reset(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_reset_unstage_allows() {
        let cmd = make_cmd(&["reset", "file.txt"]);
        let result = check_git_reset(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
