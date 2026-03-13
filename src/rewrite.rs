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
