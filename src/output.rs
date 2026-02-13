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
