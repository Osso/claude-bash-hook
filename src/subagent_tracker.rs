//! Track active subagents via counter file.
//!
//! Claude Code fires SubagentStart/SubagentStop hook events but doesn't include
//! a subagent indicator in PreToolUse events. We bridge this gap by maintaining
//! a per-session counter file at `/tmp/claude/subagents/{session_id}.count`.
//!
//! When a subagent is active, the main thread is blocked waiting for the Task()
//! result, so any PreToolUse firing during that time must be from the subagent.

use std::fs;
use std::path::PathBuf;

fn counter_path(session_id: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/claude/subagents/{}.count", session_id))
}

fn read_count(session_id: &str) -> u32 {
    fs::read_to_string(counter_path(session_id))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Increment the active subagent count (called on SubagentStart)
pub fn increment(session_id: &str) {
    let path = counter_path(session_id);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, (read_count(session_id) + 1).to_string());
}

/// Decrement the active subagent count (called on SubagentStop)
pub fn decrement(session_id: &str) {
    let count = read_count(session_id);
    if count <= 1 {
        let _ = fs::remove_file(counter_path(session_id));
    } else {
        let _ = fs::write(counter_path(session_id), (count - 1).to_string());
    }
}

/// Check if any subagents are currently active for this session
pub fn has_active_subagents(session_id: &str) -> bool {
    read_count(session_id) > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subagent_counter() {
        let session = "test-subagent-counter";
        let _ = fs::remove_file(counter_path(session));

        assert!(!has_active_subagents(session));

        increment(session);
        assert!(has_active_subagents(session));

        increment(session);
        assert!(has_active_subagents(session));

        decrement(session);
        assert!(has_active_subagents(session)); // still 1

        decrement(session);
        assert!(!has_active_subagents(session)); // back to 0

        // Extra decrement should not panic
        decrement(session);
        assert!(!has_active_subagents(session));
    }
}
