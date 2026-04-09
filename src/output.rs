//! Output formatting helpers

use crate::config::PermissionResult;

/// Format the reason string
pub fn format_reason(command: &str, result: &PermissionResult) -> String {
    let mut reason = if result.reason.is_empty() {
        command.to_string()
    } else {
        format!("{}: {}", shorten_command(command), result.reason)
    };

    if let Some(ref suggestion) = result.suggestion {
        reason = format!("{}\n{}", reason, suggestion);
    }

    reason
}

/// Shorten a long command for display
fn shorten_command(command: &str) -> &str {
    if command.len() > 60 {
        // Find a valid char boundary at or before 60 bytes
        let mut end = 60;
        while !command.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        &command[..end]
    } else {
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Permission, PermissionResult};

    #[test]
    fn test_format_reason_uses_full_command_when_reason_empty() {
        let result = PermissionResult {
            permission: Permission::Allow,
            reason: String::new(),
            suggestion: None,
        };
        assert_eq!(format_reason("ls -la", &result), "ls -la");
    }

    #[test]
    fn test_format_reason_appends_suggestion() {
        let result = PermissionResult {
            permission: Permission::Ask,
            reason: "needs review".to_string(),
            suggestion: Some("Use Task()".to_string()),
        };
        assert_eq!(
            format_reason("git push origin master", &result),
            "git push origin master: needs review\nUse Task()"
        );
    }

    #[test]
    fn test_format_reason_shortens_long_command() {
        let long_command = format!("{}{}", "x".repeat(80), " tail");
        let result = PermissionResult {
            permission: Permission::Ask,
            reason: "too long".to_string(),
            suggestion: None,
        };
        let formatted = format_reason(&long_command, &result);
        assert!(formatted.starts_with(&"x".repeat(60)));
        assert!(formatted.ends_with(": too long"));
    }

    #[test]
    fn test_shorten_command_preserves_char_boundary() {
        let command = format!("{}é{}", "a".repeat(59), "suffix");
        let shortened = shorten_command(&command);
        assert!(shortened.is_char_boundary(shortened.len()));
        assert_eq!(shortened, &"a".repeat(59));
    }
}
