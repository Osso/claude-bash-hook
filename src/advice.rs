//! LLM-based passthrough classifier using codex spark.
//! Intercepts commands the rule engine left as passthrough and classifies
//! them as Allow (safe), Ask (unsafe), or real passthrough (unsure).

use std::time::Duration;

use crate::config::{Permission, PermissionResult};

const CODEX_MODEL: &str = "gpt-5.3-codex-spark";
const CODEX_TIMEOUT: Duration = Duration::from_secs(8);

enum Advice {
    Safe { reason: String },
    Unsafe { reason: String },
    Unsure,
}

/// Classify a passthrough bash command via codex spark.
///
/// Returns `Some(Allow)` for safe commands, `Some(Ask)` for unsafe ones
/// (surfaces to the user), and `None` for unsure (real passthrough — let
/// Claude Code's permission system decide).
pub fn classify_passthrough(command: &str, cwd: Option<&str>) -> Option<PermissionResult> {
    let rt = tokio::runtime::Runtime::new().ok()?;
    let advice = rt.block_on(ask_codex(command, cwd))?;
    match advice {
        Advice::Safe { reason } => Some(PermissionResult {
            permission: Permission::Allow,
            reason,
            suggestion: None,
        }),
        Advice::Unsafe { reason } => Some(PermissionResult {
            permission: Permission::Ask,
            reason,
            suggestion: None,
        }),
        Advice::Unsure => None,
    }
}

async fn ask_codex(command: &str, _cwd: Option<&str>) -> Option<Advice> {
    use llm_sdk::Backend;
    use llm_sdk::codex_cli::CodexCli;

    let backend = CodexCli::new()
        .ok()?
        .model(CODEX_MODEL)
        .timeout(CODEX_TIMEOUT);
    let prompt = build_prompt(command);
    let output = backend.complete(&prompt).await.ok()?;
    Some(parse_advice(&output.text))
}

fn build_prompt(command: &str) -> String {
    format!(
        "An AI coding agent wants to run this bash command:\n\
         Command: {command}\n\
         \n\
         Decide whether this should be auto-allowed for the rest of the session.\n\
         Reply with EXACTLY one of, followed by a one-line reason:\n\
         \n\
         SAFE <reason>   — read-only OR easily reversible inside the project\n\
                          (git commit/branch/merge/rebase/stash/reset, mkdir,\n\
                          touch, file edits in cwd, cargo build, npm install,\n\
                          curl GET, docker build). Anything you can undo with\n\
                          a follow-up command in the same repo is SAFE.\n\
         UNSAFE <reason> — IRREVERSIBLE or BLAST RADIUS beyond the repo\n\
                          (`rm -rf` outside cwd, `dd of=/dev/...`,\n\
                          `git push --force` to shared branches, `DROP TABLE`\n\
                          on prod, `kubectl delete` on prod, `sudo` mutating\n\
                          system state, `curl ... | sh`, sending real email\n\
                          / Slack / API calls to third-party services).\n\
         UNSURE <reason> — ambiguous; let the human decide\n\
         \n\
         Modifying repository state is the AGENT'S JOB. Don't flag a command \
         UNSAFE just because it writes files, creates commits, or changes git \
         history — those are recoverable. Reserve UNSAFE for things a human \
         would also want a chance to refuse.\n\
         \n\
         Err UNSURE — not UNSAFE — for anything you're not confident about."
    )
}

fn parse_advice(text: &str) -> Advice {
    let trimmed = text.trim();
    let upper = trimmed.to_uppercase();
    let reason_after = |needle: &str| -> String {
        upper
            .find(needle)
            .map(|i| trimmed[i + needle.len()..].trim().to_string())
            .unwrap_or_default()
    };
    // UNSAFE / UNSURE both contain "SAFE" as a substring — check longer tokens first.
    if upper.starts_with("UNSAFE") {
        return Advice::Unsafe {
            reason: reason_after("UNSAFE"),
        };
    }
    if upper.starts_with("UNSURE") {
        return Advice::Unsure;
    }
    if upper.starts_with("SAFE") {
        return Advice::Safe {
            reason: reason_after("SAFE"),
        };
    }
    Advice::Unsure
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_safe() {
        match parse_advice("SAFE read-only listing") {
            Advice::Safe { reason } => assert_eq!(reason, "read-only listing"),
            _ => panic!("expected Safe"),
        }
    }

    #[test]
    fn parse_unsafe_beats_safe_substring() {
        match parse_advice("UNSAFE deletes data") {
            Advice::Unsafe { reason } => assert_eq!(reason, "deletes data"),
            _ => panic!("expected Unsafe"),
        }
    }

    #[test]
    fn parse_unsure() {
        assert!(matches!(parse_advice("UNSURE depends on context"), Advice::Unsure));
    }

    #[test]
    fn parse_unknown_is_unsure() {
        assert!(matches!(parse_advice("hmm not sure"), Advice::Unsure));
    }
}
