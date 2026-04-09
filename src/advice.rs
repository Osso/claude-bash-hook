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
