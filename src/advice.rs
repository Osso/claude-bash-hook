//! AI-powered advice for permission decisions

use crate::config::Permission;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Get AI advice on whether to allow a command
pub fn get_advice(command: &str, reason: &str, permission: &Permission) -> Option<String> {
    let perm_str = match permission {
        Permission::Ask => "ask",
        Permission::Deny => "deny",
        _ => return None,
    };

    let prompt = format!(
        "A CLI permission hook is asking whether to allow this bash command.\n\
         Command: {}\n\
         Current decision: {} because: {}\n\n\
         Should this command be allowed? Reply with ONLY:\n\
         - \"Allow: <reason>\" if the command is safe\n\
         - \"Deny: <reason>\" if risky\n\
         Keep under 30 words.",
        command, perm_str, reason
    );

    // Spawn claude-safe with timeout
    let mut child = Command::new("claude-safe")
        .args(["-p", &prompt, "--model", "haiku"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Wait with timeout (10 seconds)
    let timeout = Duration::from_secs(10);
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                return None;
            }
        }
    }

    let mut output = String::new();
    child.stdout?.read_to_string(&mut output).ok()?;

    let trimmed = output.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(format!("AI advice: {}", trimmed))
    }
}
