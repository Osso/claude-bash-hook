//! Shared network host policy matching.

use glob_match::glob_match;

use super::{Config, ExecContext, Permission, PermissionResult};

impl Config {
    /// Check a host against the shared network host policy.
    /// Falls back to the legacy inline curl host rule when no network host
    /// rules are loaded, so existing config.toml files keep working.
    pub fn check_network_host_flagged(
        &self,
        host: Option<&str>,
        ctx: ExecContext,
    ) -> (PermissionResult, bool) {
        let Some(host) = host else {
            return (
                PermissionResult {
                    permission: Permission::Ask,
                    reason: "network host (unknown host)".to_string(),
                    suggestion: None,
                },
                false,
            );
        };

        if self.network.hosts.is_empty() {
            return self.check_command_with_host_flagged("curl", &[], Some(host), ctx);
        }

        for host_rule in &self.network.hosts {
            if glob_match(&host_rule.pattern, host) {
                let is_wildcard = host_rule.pattern == "*";
                return (
                    PermissionResult {
                        permission: self.parse_permission(&host_rule.permission),
                        reason: format!("network host (host: {})", host),
                        suggestion: None,
                    },
                    is_wildcard,
                );
            }
        }

        (
            PermissionResult {
                permission: Permission::Ask,
                reason: format!("network host (unknown host: {})", host),
                suggestion: None,
            },
            false,
        )
    }
}
