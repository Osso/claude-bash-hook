//! AI-powered advice for permission decisions

use crate::config::Permission;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Get AI advice on whether to allow a command
pub fn get_advice(command: &str, reason: &str, permission: &Permission) -> Option<String> {
    let perm_str = permission_label(permission)?;
    let prompt = build_prompt(command, reason, perm_str);
    let mut child = spawn_claude_safe(&prompt)?;
    wait_for_child(&mut child)?;
    read_child_output(&mut child)
}

fn permission_label(permission: &Permission) -> Option<&'static str> {
    match permission {
        Permission::Ask => "ask",
        Permission::Deny => "deny",
        _ => return None,
    }
    .into()
}

fn build_prompt(command: &str, reason: &str, permission: &str) -> String {
    format!(
        "A CLI permission hook is asking whether to allow this bash command.\n\
         Command: {}\n\
         Current decision: {} because: {}\n\n\
         Should this command be allowed? Reply with ONLY:\n\
         - \"Allow: <reason>\" if the command is safe\n\
         - \"Deny: <reason>\" if risky\n\
         Keep under 30 words.",
        command, permission, reason
    )
}

fn spawn_claude_safe(prompt: &str) -> Option<std::process::Child> {
    Command::new("claude-safe")
        .args(["-p", &prompt, "--model", "haiku"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

fn wait_for_child(child: &mut std::process::Child) -> Option<()> {
    let timeout = Duration::from_secs(10);
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                return None;
            }
        }
    }

    Some(())
}

fn read_child_output(child: &mut std::process::Child) -> Option<String> {
    let mut output = String::new();
    let stdout = child.stdout.as_mut()?;
    stdout.read_to_string(&mut output).ok()?;

    let trimmed = output.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(format!("AI advice: {}", trimmed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as ProcessCommand;

    #[test]
    fn test_permission_label_for_supported_permissions() {
        assert_eq!(permission_label(&Permission::Ask), Some("ask"));
        assert_eq!(permission_label(&Permission::Deny), Some("deny"));
        assert_eq!(permission_label(&Permission::Allow), None);
    }

    #[test]
    fn test_build_prompt_contains_core_fields() {
        let prompt = build_prompt("rm -rf /tmp/x", "dangerous", "ask");
        assert!(prompt.contains("Command: rm -rf /tmp/x"));
        assert!(prompt.contains("Current decision: ask because: dangerous"));
        assert!(prompt.contains("Allow: <reason>"));
        assert!(prompt.contains("Deny: <reason>"));
    }

    #[test]
    fn test_get_advice_returns_none_for_unsupported_permission() {
        assert_eq!(get_advice("ls -la", "safe", &Permission::Allow), None);
        assert_eq!(get_advice("ls -la", "safe", &Permission::Passthrough), None);
    }

    #[test]
    fn test_wait_for_child_success() {
        let mut child = ProcessCommand::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn shell");
        assert_eq!(wait_for_child(&mut child), Some(()));
    }

    #[test]
    fn test_read_child_output_returns_prefixed_text() {
        let mut child = ProcessCommand::new("sh")
            .args(["-c", "printf 'Allow: safe\\n'"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn shell");
        let _ = child.wait();
        assert_eq!(
            read_child_output(&mut child),
            Some("AI advice: Allow: safe".to_string())
        );
    }

    #[test]
    fn test_read_child_output_ignores_empty_stdout() {
        let mut child = ProcessCommand::new("sh")
            .args(["-c", "printf ''"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn shell");
        let _ = child.wait();
        assert_eq!(read_child_output(&mut child), None);
    }

    #[test]
    fn test_read_child_output_requires_stdout_pipe() {
        let mut child = ProcessCommand::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn shell");
        let _ = child.wait();
        assert_eq!(read_child_output(&mut child), None);
    }
}
