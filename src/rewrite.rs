//! Command rewriting — prepend a proxy binary (e.g., rtk) to allowed commands.

use crate::config::{Config, Permission, PermissionResult};
use serde_json::json;

/// Build `updatedInput` JSON if the command should be rewritten.
/// Only rewrites when the permission is Allow and the config matches.
pub fn maybe_rewrite(
    command: &str,
    result: &PermissionResult,
    config: &Config,
) -> Option<serde_json::Value> {
    if result.permission != Permission::Allow {
        return None;
    }
    let rewritten = config.rewrite_command(command)?;
    Some(json!({ "command": rewritten }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite_config() -> Config {
        toml::from_str(
            r#"
            [rewrite]
            enabled = true
            binary = "rtk"
            prefixes = ["git", "docker compose"]
        "#,
        )
        .expect("rewrite config")
    }

    fn allow_result() -> PermissionResult {
        PermissionResult {
            permission: Permission::Allow,
            reason: "allowed".to_string(),
            suggestion: None,
        }
    }

    #[test]
    fn test_maybe_rewrite_for_allowed_command() {
        let value = maybe_rewrite("git status", &allow_result(), &rewrite_config());
        assert_eq!(value, Some(json!({ "command": "rtk git status" })));
    }

    #[test]
    fn test_maybe_rewrite_skips_non_allow_permission() {
        let result = PermissionResult {
            permission: Permission::Ask,
            reason: "ask".to_string(),
            suggestion: None,
        };
        assert_eq!(
            maybe_rewrite("git status", &result, &rewrite_config()),
            None
        );
    }

    #[test]
    fn test_maybe_rewrite_skips_non_matching_command() {
        assert_eq!(
            maybe_rewrite("ls -la", &allow_result(), &rewrite_config()),
            None
        );
    }
}
