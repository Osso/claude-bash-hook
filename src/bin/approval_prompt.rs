//! MCP server wired via `claude --permission-prompt-tool`.
//!
//! Exposes one tool, `approval_prompt`, that Claude Code calls before running
//! any permission-gated tool. The return value is a JSON-stringified decision
//! body as described in the Claude Agent SDK:
//!
//! - `{"behavior":"allow","updatedInput":{...}}`
//! - `{"behavior":"deny","message":"..."}`
//! - allow + remember: add `updatedPermissions:[{type:"addRules",...}]`
//!
//! Flow: Codex decides SAFE/UNSAFE/UNSURE. SAFE → allow + session-scoped
//! remember. UNSAFE → deny with Codex's reason. UNSURE → allow-once (task #3
//! will replace this with an interactive TUI prompt).

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use log::{info, warn};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    service::{RequestContext, RoleServer},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const CODEX_TIMEOUT: Duration = Duration::from_secs(8);
const CODEX_MODEL: &str = "gpt-5.3-codex-spark";

#[derive(Debug, Deserialize, JsonSchema)]
struct ApprovalInput {
    #[schemars(description = "Name of the tool Claude wants to use (Bash, Edit, Write, Read, ...)")]
    tool_name: String,
    #[schemars(description = "Arguments Claude passed to the tool")]
    input: HashMap<String, serde_json::Value>,
    #[serde(default)]
    #[schemars(description = "Opaque identifier Claude assigned to this tool invocation")]
    tool_use_id: Option<String>,
    #[serde(default)]
    #[schemars(description = "CLI policy suggestions for this call")]
    permission_suggestions: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    #[schemars(description = "Path that triggered a deny rule, if any")]
    blocked_path: Option<String>,
}

/// A permission rule persisted on "always allow".
#[derive(Debug, Serialize, Clone)]
struct PermissionRule {
    #[serde(rename = "toolName")]
    tool_name: String,
    #[serde(rename = "ruleContent", skip_serializing_if = "Option::is_none")]
    rule_content: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct AddRulesUpdate {
    #[serde(rename = "type")]
    kind: &'static str,
    destination: &'static str,
    behavior: &'static str,
    rules: Vec<PermissionRule>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "behavior", rename_all = "lowercase")]
enum Decision {
    Allow {
        #[serde(rename = "updatedInput")]
        updated_input: HashMap<String, serde_json::Value>,
        #[serde(rename = "updatedPermissions", skip_serializing_if = "Vec::is_empty")]
        updated_permissions: Vec<AddRulesUpdate>,
    },
    Deny {
        message: String,
    },
}

// ── Codex advice ─────────────────────────────────────────────────────────────

enum Advice {
    Safe { reason: String },
    Unsafe { reason: String },
    Unsure,
}

/// Short, human-readable target string for the prompt and logs.
fn rule_target(tool_name: &str, input: &HashMap<String, serde_json::Value>) -> Option<String> {
    match tool_name {
        "Bash" => input.get("command").and_then(|v| v.as_str()).map(String::from),
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" | "Read" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .map(String::from),
        _ => None,
    }
}

fn build_prompt(
    tool_name: &str,
    target: Option<&str>,
    suggestions: Option<&[serde_json::Value]>,
    blocked_path: Option<&str>,
) -> String {
    let target_line = target
        .map(|t| format!("Target: {}", t))
        .unwrap_or_else(|| "Target: (no recognizable target field)".to_string());

    let mut extras = String::new();

    if let Some(path) = blocked_path {
        extras.push_str(&format!("\nBlocked path: {path}"));
    }

    if let Some(sugs) = suggestions {
        let non_empty: Vec<&serde_json::Value> = sugs.iter().collect();
        if !non_empty.is_empty() {
            extras.push_str("\nPolicy suggestions:");
            for s in non_empty {
                let line = serde_json::to_string(s).unwrap_or_default();
                let line = if line.len() > 200 {
                    let truncated: String = line.chars().take(199).collect();
                    format!("{truncated}\u{2026}")
                } else {
                    line
                };
                extras.push_str(&format!("\n  {line}"));
            }
        }
    }

    format!(
        "An AI coding agent wants to use tool `{tool_name}`.\n\
         {target_line}{extras}\n\
         \n\
         Decide whether this should be auto-allowed for the rest of the session.\n\
         Reply with EXACTLY one of, followed by a one-line reason:\n\
         \n\
         SAFE <reason>   — routine, read-only, or clearly harmless\n\
         UNSAFE <reason> — modifies important state, leaks secrets, or risky\n\
         UNSURE <reason> — ambiguous; let the human decide\n\
         \n\
         Err UNSURE for anything you're not confident about."
    )
}

async fn ask_codex(
    tool_name: &str,
    target: Option<&str>,
    suggestions: Option<&[serde_json::Value]>,
    blocked_path: Option<&str>,
) -> Option<Advice> {
    use llm_sdk::Backend;
    use llm_sdk::codex_cli::CodexCli;

    let backend = CodexCli::new()
        .ok()?
        .model(CODEX_MODEL)
        .timeout(CODEX_TIMEOUT);
    let prompt = build_prompt(tool_name, target, suggestions, blocked_path);
    let output = backend.complete(&prompt).await.ok()?;
    Some(parse_advice(&output.text))
}

/// Bypass codex when `CLAUDE_APPROVAL_MOCK` is set, so the MCP protocol path
/// (including the UNSURE → `elicitation/create` round-trip) can be exercised
/// without hitting an LLM. Recognized values are case-insensitive: `safe`,
/// `unsafe`, `unsure`. Any other value is treated as unset.
fn mock_advice_from_env() -> Option<Advice> {
    let raw = std::env::var("CLAUDE_APPROVAL_MOCK").ok()?;
    mock_advice_from_str(&raw)
}

fn mock_advice_from_str(raw: &str) -> Option<Advice> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "safe" => Some(Advice::Safe {
            reason: "mocked SAFE via CLAUDE_APPROVAL_MOCK".to_string(),
        }),
        "unsafe" => Some(Advice::Unsafe {
            reason: "mocked UNSAFE via CLAUDE_APPROVAL_MOCK".to_string(),
        }),
        "unsure" => Some(Advice::Unsure),
        _ => None,
    }
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
    // UNSAFE / UNSURE both contain "SAFE" as substring — check longer tokens first.
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

// ── Config writer ────────────────────────────────────────────────────────────

/// Append `[[rules]]` blocks to `~/.config/claude-bash-hook/config.toml` so
/// the hook also allows these commands in later sessions (not just this one).
///
/// Gated by the `CLAUDE_APPROVAL_PERSIST=1` env var so it stays opt-in while
/// the Codex SAFE judgment is being tuned.
mod config_writer {
    use std::ffi::OsString;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};

    pub fn config_path() -> Option<PathBuf> {
        let home = std::env::var_os("HOME")?;
        let mut p = PathBuf::from(home);
        p.push(".config/claude-bash-hook/config.toml");
        Some(p)
    }

    /// Take an exclusive advisory lock on `path` (creates if missing). Held
    /// until the returned `File` is dropped.
    fn flock_exclusive(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(file)
    }

    /// Encode `s` as a TOML string. Prefers literal `'...'` (no escaping)
    /// when safe, falls back to basic `"..."` with escapes.
    pub(super) fn toml_encode(s: &str) -> String {
        let literal_safe =
            !s.contains('\'') && !s.contains('\n') && !s.contains('\r') && !s.contains('\0');
        if literal_safe {
            return format!("'{s}'");
        }
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for ch in s.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    fn render_block(command: &str, reason: &str) -> String {
        format!(
            "\n[[rules]]\ncommands = [{}]\npermission = \"allow\"\nreason = {}\n",
            toml_encode(command),
            toml_encode(reason),
        )
    }

    /// Append an `allow` rule for a literal Bash command into `cfg_path`.
    /// Creates the file (and parent dir) if missing. Flocks a sibling
    /// `.lock` file during the read-modify-write so concurrent hook calls
    /// don't clobber each other. Writes via tmp + atomic rename.
    pub fn append_bash_allow_rule_at(
        cfg_path: &Path,
        command: &str,
        reason: &str,
    ) -> io::Result<()> {
        if let Some(parent) = cfg_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut lock_path: OsString = cfg_path.as_os_str().to_owned();
        lock_path.push(".lock");
        let _guard = flock_exclusive(Path::new(&lock_path))?;

        let mut existing = String::new();
        match File::open(cfg_path) {
            Ok(mut f) => {
                f.read_to_string(&mut existing)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        // Skip if an identical `commands = ["<cmd>"]` single-command rule
        // already exists. Cheap duplicate-guard, not a full TOML parse.
        let needle = format!("commands = [{}]", toml_encode(command));
        if existing.contains(&needle) {
            return Ok(());
        }

        if !existing.is_empty() && !existing.ends_with('\n') {
            existing.push('\n');
        }
        existing.push_str(&render_block(command, reason));

        let mut tmp_path: OsString = cfg_path.as_os_str().to_owned();
        tmp_path.push(".tmp");
        let tmp = Path::new(&tmp_path);
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(tmp)?;
            f.write_all(existing.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, cfg_path)?;
        Ok(())
    }

    /// Wrapper using the default user config path.
    pub fn append_bash_allow_rule(command: &str, reason: &str) -> io::Result<()> {
        let path = config_path().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "HOME not set; cannot locate config")
        })?;
        append_bash_allow_rule_at(&path, command, reason)
    }
}

// ── Elicitation fallback ─────────────────────────────────────────────────────

/// Ask the MCP client (Claude Code) to prompt the user via the standard
/// `elicitation/create` request. This is the right mechanism from an MCP
/// server context: the client renders the prompt in its own UI, users
/// already trust that UI, and we don't need a TTY/GUI dialog binary on
/// the machine.
///
/// The schema is a single-property object with a 3-value string enum so
/// the client can render a 3-way choice (deny / once / always). If the
/// client doesn't support elicitation, callers fall back to allow-once.
mod elicit {
    use rmcp::model::{
        CreateElicitationRequestParam, ElicitationAction, ElicitationSchema, EnumSchema,
        PrimitiveSchema,
    };

    pub const CHOICE_KEY: &str = "choice";
    pub const CHOICE_DENY: &str = "deny";
    pub const CHOICE_ONCE: &str = "once";
    pub const CHOICE_ALWAYS: &str = "always";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UserChoice {
        Deny,
        AllowOnce,
        AllowAlways,
    }

    pub fn format_message(tool: &str, target: &str, hint: &str) -> String {
        let hint = if hint.is_empty() { "ambiguous" } else { hint };
        let target = truncate(target, 400);
        format!(
            "Codex can't classify this tool call.\n\n\
             Tool: {tool}\n\
             Target: {target}\n\
             Note: {hint}\n\n\
             How should this be handled?"
        )
    }

    fn truncate(s: &str, max: usize) -> String {
        if s.len() <= max {
            s.to_string()
        } else {
            let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
            out.push('…');
            out
        }
    }

    pub fn build_request(tool: &str, target: &str, hint: &str) -> CreateElicitationRequestParam {
        let enum_schema = EnumSchema::new(vec![
            CHOICE_DENY.to_string(),
            CHOICE_ONCE.to_string(),
            CHOICE_ALWAYS.to_string(),
        ])
        .enum_names(vec![
            "Deny".to_string(),
            "Allow once".to_string(),
            "Always allow".to_string(),
        ])
        .description("What should happen with this tool call?");

        let schema = ElicitationSchema::builder()
            .required_property(CHOICE_KEY, PrimitiveSchema::Enum(enum_schema))
            .build()
            .expect("static schema is valid");

        CreateElicitationRequestParam {
            message: format_message(tool, target, hint),
            requested_schema: schema,
        }
    }

    pub fn parse_result(action: ElicitationAction, content: Option<&serde_json::Value>) -> Option<UserChoice> {
        match action {
            ElicitationAction::Decline | ElicitationAction::Cancel => {
                Some(UserChoice::AllowOnce)
            }
            ElicitationAction::Accept => {
                let choice = content
                    .and_then(|v| v.get(CHOICE_KEY))
                    .and_then(|v| v.as_str())?;
                match choice {
                    CHOICE_DENY => Some(UserChoice::Deny),
                    CHOICE_ONCE => Some(UserChoice::AllowOnce),
                    CHOICE_ALWAYS => Some(UserChoice::AllowAlways),
                    _ => None,
                }
            }
        }
    }
}

// ── Server ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ApprovalServer {
    tool_router: ToolRouter<Self>,
}

impl ApprovalServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Elicit a 3-choice decision from the user via MCP. Falls back to
    /// allow-once on capability miss, transport error, or invalid response.
    async fn handle_unsure(
        &self,
        params: &ApprovalInput,
        target: &Option<String>,
        ctx: &RequestContext<RoleServer>,
    ) -> Decision {
        let allow_once = || Decision::Allow {
            updated_input: params.input.clone(),
            updated_permissions: Vec::new(),
        };

        let Some(t) = target.as_deref() else {
            info!(
                "unsure + no recognized target; allow-once tool={}",
                params.tool_name
            );
            return allow_once();
        };

        if !ctx.peer.supports_elicitation() {
            warn!("client does not support elicitation; allow-once");
            return allow_once();
        }

        let req = elicit::build_request(&params.tool_name, t, "codex unsure");
        let result = match ctx.peer.create_elicitation(req).await {
            Ok(r) => r,
            Err(e) => {
                warn!("elicitation failed ({e}); allow-once");
                return allow_once();
            }
        };

        let choice = match elicit::parse_result(result.action, result.content.as_ref()) {
            Some(c) => c,
            None => {
                warn!(
                    "elicitation returned invalid content tool={} target={t:?}; allow-once",
                    params.tool_name
                );
                return allow_once();
            }
        };

        match choice {
            elicit::UserChoice::Deny => {
                info!("user chose DENY tool={} target={t:?}", params.tool_name);
                Decision::Deny {
                    message: "Denied by user".to_string(),
                }
            }
            elicit::UserChoice::AllowOnce => {
                info!("user chose ONCE tool={} target={t:?}", params.tool_name);
                allow_once()
            }
            elicit::UserChoice::AllowAlways => {
                info!("user chose ALWAYS tool={} target={t:?}", params.tool_name);
                if params.tool_name == "Bash" {
                    if let Err(e) =
                        config_writer::append_bash_allow_rule(t, "approved by user via elicit")
                    {
                        warn!("persist failed cmd={t:?} err={e}");
                    } else {
                        info!("persisted bash allow rule cmd={t:?}");
                    }
                }
                let remember = AddRulesUpdate {
                    kind: "addRules",
                    destination: "session",
                    behavior: "allow",
                    rules: vec![PermissionRule {
                        tool_name: params.tool_name.clone(),
                        rule_content: Some(t.to_string()),
                    }],
                };
                Decision::Allow {
                    updated_input: params.input.clone(),
                    updated_permissions: vec![remember],
                }
            }
        }
    }

    fn decide(params: &ApprovalInput, advice: Advice) -> Decision {
        let target = rule_target(&params.tool_name, &params.input);
        match advice {
            Advice::Safe { reason } => {
                info!(
                    "codex SAFE tool={} target={:?} reason={}",
                    params.tool_name, target, reason
                );
                let remember = target.as_ref().map(|t| AddRulesUpdate {
                    kind: "addRules",
                    destination: "session",
                    behavior: "allow",
                    rules: vec![PermissionRule {
                        tool_name: params.tool_name.clone(),
                        rule_content: Some(t.clone()),
                    }],
                });
                Decision::Allow {
                    updated_input: params.input.clone(),
                    updated_permissions: remember.into_iter().collect(),
                }
            }
            Advice::Unsafe { reason } => {
                info!(
                    "codex UNSAFE tool={} target={:?} reason={}",
                    params.tool_name, target, reason
                );
                Decision::Deny {
                    message: if reason.is_empty() {
                        "Codex flagged this tool call as unsafe".to_string()
                    } else {
                        format!("Codex: {reason}")
                    },
                }
            }
            Advice::Unsure => {
                info!(
                    "codex UNSURE (or unreachable) tool={} target={:?} — allow-once fallback",
                    params.tool_name, target
                );
                Decision::Allow {
                    updated_input: params.input.clone(),
                    updated_permissions: Vec::new(),
                }
            }
        }
    }
}

#[tool_router]
impl ApprovalServer {
    #[tool(
        description = "Permission prompt callback wired via claude --permission-prompt-tool. \
                       Do not call this tool directly; Claude Code invokes it before running \
                       permission-gated tools so the user can approve or deny each call."
    )]
    async fn approval_prompt(
        &self,
        Parameters(params): Parameters<ApprovalInput>,
        ctx: RequestContext<RoleServer>,
    ) -> String {
        let target = rule_target(&params.tool_name, &params.input);
        info!(
            "approval_prompt tool={} tool_use_id={:?} target={:?}",
            params.tool_name, params.tool_use_id, target
        );

        let advice = if let Some(mocked) = mock_advice_from_env() {
            info!(
                "CLAUDE_APPROVAL_MOCK set; bypassing codex tool={} target={:?}",
                params.tool_name, target
            );
            mocked
        } else {
            ask_codex(
                &params.tool_name,
                target.as_deref(),
                params.permission_suggestions.as_deref(),
                params.blocked_path.as_deref(),
            )
            .await
            .unwrap_or_else(|| {
                    warn!("codex unreachable; falling back to Unsure");
                    Advice::Unsure
                })
        };

        // Capture SAFE reason before `decide` consumes `advice`; used only
        // when CLAUDE_APPROVAL_PERSIST=1 so Codex SAFE writes a real
        // [[rules]] block into the hook config.
        let persist_reason = match (&advice, params.tool_name.as_str()) {
            (Advice::Safe { reason }, "Bash")
                if std::env::var_os("CLAUDE_APPROVAL_PERSIST").is_some() =>
            {
                Some(reason.clone())
            }
            _ => None,
        };

        // On UNSURE, ask the user via MCP elicitation. Claude Code renders
        // a 3-choice prompt in its own UI (no TTY/GUI dialog needed). On
        // missing capability or error, fall back to allow-once.
        let decision = if matches!(advice, Advice::Unsure) {
            self.handle_unsure(&params, &target, &ctx).await
        } else {
            Self::decide(&params, advice)
        };

        if let (Some(reason), Some(cmd)) = (persist_reason, target.as_deref()) {
            let note = if reason.is_empty() {
                "codex auto-approved".to_string()
            } else {
                format!("codex auto-approved: {reason}")
            };
            match config_writer::append_bash_allow_rule(cmd, &note) {
                Ok(()) => info!("persisted bash allow rule cmd={cmd:?}"),
                Err(e) => warn!("persist failed cmd={cmd:?} err={e}"),
            }
        }
        serde_json::to_string(&decision).unwrap_or_else(|_| {
            r#"{"behavior":"deny","message":"internal encoding error"}"#.to_string()
        })
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ApprovalServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Permission prompt callback. Wire via: \
                 claude --permission-prompt-tool mcp__claude-bash-hook-approval__approval_prompt"
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let _ = systemd_journal_logger::JournalLog::new().map(|l| {
        l.with_syslog_identifier("claude-bash-hook-approval".into())
            .install()
    });
    log::set_max_level(log::LevelFilter::Info);

    let service = ApprovalServer::new();
    let server = service.serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ElicitationAction;

    fn input(pairs: &[(&str, &str)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect()
    }

    #[test]
    fn parse_advice_safe() {
        match parse_advice("SAFE read-only listing") {
            Advice::Safe { reason } => assert_eq!(reason, "read-only listing"),
            _ => panic!("expected Safe"),
        }
    }

    #[test]
    fn parse_advice_unsafe_beats_safe_substring() {
        match parse_advice("UNSAFE deletes user data") {
            Advice::Unsafe { reason } => assert_eq!(reason, "deletes user data"),
            _ => panic!("expected Unsafe"),
        }
    }

    #[test]
    fn parse_advice_unsure() {
        assert!(matches!(parse_advice("UNSURE depends on cwd"), Advice::Unsure));
    }

    #[test]
    fn parse_advice_unknown_is_unsure() {
        assert!(matches!(parse_advice("hmm"), Advice::Unsure));
    }

    #[test]
    fn mock_advice_safe() {
        assert!(matches!(
            mock_advice_from_str("safe"),
            Some(Advice::Safe { .. })
        ));
        assert!(matches!(
            mock_advice_from_str("SAFE"),
            Some(Advice::Safe { .. })
        ));
        assert!(matches!(
            mock_advice_from_str("  Safe  "),
            Some(Advice::Safe { .. })
        ));
    }

    #[test]
    fn mock_advice_unsafe() {
        assert!(matches!(
            mock_advice_from_str("unsafe"),
            Some(Advice::Unsafe { .. })
        ));
        assert!(matches!(
            mock_advice_from_str("UNSAFE"),
            Some(Advice::Unsafe { .. })
        ));
    }

    #[test]
    fn mock_advice_unsure() {
        assert!(matches!(
            mock_advice_from_str("unsure"),
            Some(Advice::Unsure)
        ));
    }

    #[test]
    fn mock_advice_unknown_is_none() {
        assert!(mock_advice_from_str("").is_none());
        assert!(mock_advice_from_str("foo").is_none());
        assert!(mock_advice_from_str("yes").is_none());
    }

    #[test]
    fn rule_target_bash() {
        let i = input(&[("command", "ls -la")]);
        assert_eq!(rule_target("Bash", &i).as_deref(), Some("ls -la"));
    }

    #[test]
    fn rule_target_edit() {
        let i = input(&[("file_path", "/tmp/x.txt")]);
        assert_eq!(rule_target("Edit", &i).as_deref(), Some("/tmp/x.txt"));
    }

    #[test]
    fn rule_target_unknown_tool() {
        let i = input(&[("foo", "bar")]);
        assert_eq!(rule_target("Mystery", &i), None);
    }

    #[test]
    fn decide_safe_emits_session_rule() {
        let params = ApprovalInput {
            tool_name: "Bash".into(),
            input: input(&[("command", "ls")]),
            tool_use_id: None,
            permission_suggestions: None,
            blocked_path: None,
        };
        let d = ApprovalServer::decide(
            &params,
            Advice::Safe {
                reason: "read-only".into(),
            },
        );
        match d {
            Decision::Allow {
                updated_permissions,
                ..
            } => {
                assert_eq!(updated_permissions.len(), 1);
                assert_eq!(updated_permissions[0].rules[0].tool_name, "Bash");
                assert_eq!(
                    updated_permissions[0].rules[0].rule_content.as_deref(),
                    Some("ls")
                );
            }
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn decide_unsafe_emits_deny_with_reason() {
        let params = ApprovalInput {
            tool_name: "Bash".into(),
            input: input(&[("command", "rm -rf /")]),
            tool_use_id: None,
            permission_suggestions: None,
            blocked_path: None,
        };
        let d = ApprovalServer::decide(
            &params,
            Advice::Unsafe {
                reason: "destroys root".into(),
            },
        );
        match d {
            Decision::Deny { message } => assert!(message.contains("destroys root")),
            _ => panic!("expected Deny"),
        }
    }

    #[test]
    fn toml_encode_prefers_literal() {
        assert_eq!(config_writer::toml_encode("ls -la"), "'ls -la'");
        assert_eq!(
            config_writer::toml_encode("/tmp/path with spaces"),
            "'/tmp/path with spaces'"
        );
    }

    #[test]
    fn toml_encode_falls_back_to_basic_when_literal_unsafe() {
        // Single quote forces basic string with escaping.
        assert_eq!(config_writer::toml_encode("it's"), r#""it's""#);
        // Double quotes and backslashes must be escaped.
        assert_eq!(
            config_writer::toml_encode("say \"hi\"\nback\\slash"),
            r#""say \"hi\"\nback\\slash""#
        );
    }

    #[test]
    fn config_writer_creates_file_and_appends_rule() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sub/config.toml");
        config_writer::append_bash_allow_rule_at(&cfg, "ls -la", "codex auto-approved").unwrap();

        let contents = std::fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("[[rules]]"));
        assert!(contents.contains("commands = ['ls -la']"));
        assert!(contents.contains("permission = \"allow\""));
        assert!(contents.contains("reason = 'codex auto-approved'"));
    }

    #[test]
    fn config_writer_preserves_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(
            &cfg,
            "default = \"passthrough\"\n\n# keep this comment\n[[rules]]\ncommands = [\"git status\"]\npermission = \"allow\"\n",
        )
        .unwrap();

        config_writer::append_bash_allow_rule_at(&cfg, "ls", "safe").unwrap();

        let contents = std::fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("# keep this comment"));
        assert!(contents.contains("commands = [\"git status\"]"));
        assert!(contents.contains("commands = ['ls']"));
    }

    #[test]
    fn config_writer_is_idempotent_for_same_command() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        config_writer::append_bash_allow_rule_at(&cfg, "ls", "first").unwrap();
        config_writer::append_bash_allow_rule_at(&cfg, "ls", "second").unwrap();

        let contents = std::fs::read_to_string(&cfg).unwrap();
        let count = contents.matches("commands = ['ls']").count();
        assert_eq!(count, 1, "duplicate rule should not be written twice");
        assert!(contents.contains("reason = 'first'"));
        assert!(!contents.contains("reason = 'second'"));
    }

    #[test]
    fn elicit_parse_accept_deny() {
        let content = serde_json::json!({"choice": "deny"});
        assert_eq!(
            elicit::parse_result(ElicitationAction::Accept, Some(&content)),
            Some(elicit::UserChoice::Deny)
        );
    }

    #[test]
    fn elicit_parse_accept_once() {
        let content = serde_json::json!({"choice": "once"});
        assert_eq!(
            elicit::parse_result(ElicitationAction::Accept, Some(&content)),
            Some(elicit::UserChoice::AllowOnce)
        );
    }

    #[test]
    fn elicit_parse_accept_always() {
        let content = serde_json::json!({"choice": "always"});
        assert_eq!(
            elicit::parse_result(ElicitationAction::Accept, Some(&content)),
            Some(elicit::UserChoice::AllowAlways)
        );
    }

    #[test]
    fn elicit_parse_decline_is_allow_once() {
        assert_eq!(
            elicit::parse_result(ElicitationAction::Decline, None),
            Some(elicit::UserChoice::AllowOnce)
        );
    }

    #[test]
    fn elicit_parse_cancel_is_allow_once() {
        assert_eq!(
            elicit::parse_result(ElicitationAction::Cancel, None),
            Some(elicit::UserChoice::AllowOnce)
        );
    }

    #[test]
    fn elicit_parse_accept_unknown_choice_is_none() {
        let content = serde_json::json!({"choice": "maybe"});
        assert_eq!(
            elicit::parse_result(ElicitationAction::Accept, Some(&content)),
            None
        );
    }

    #[test]
    fn elicit_parse_accept_missing_content_is_none() {
        assert_eq!(elicit::parse_result(ElicitationAction::Accept, None), None);
    }

    #[test]
    fn elicit_message_includes_tool_target_hint() {
        let m = elicit::format_message("Bash", "ls -la", "codex unsure");
        assert!(m.contains("Bash"));
        assert!(m.contains("ls -la"));
        assert!(m.contains("codex unsure"));
    }

    #[test]
    fn elicit_message_truncates_long_targets() {
        let long = "x".repeat(1000);
        let m = elicit::format_message("Bash", &long, "");
        assert!(m.len() < 700);
        assert!(m.contains('…'));
    }

    #[test]
    fn elicit_request_schema_has_three_choices() {
        let req = elicit::build_request("Bash", "ls", "hint");
        // Serialize and inspect — the schema must include all three enum values.
        let json = serde_json::to_value(&req.requested_schema).unwrap();
        let choice = &json["properties"]["choice"];
        let values = choice["enum"].as_array().unwrap();
        let strings: Vec<&str> = values.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(strings, vec!["deny", "once", "always"]);
    }

    #[test]
    fn config_writer_escapes_quotes_in_command() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        config_writer::append_bash_allow_rule_at(&cfg, "echo \"hi\"", "safe").unwrap();

        let contents = std::fs::read_to_string(&cfg).unwrap();
        // Parse it back through the toml crate to prove the file is valid.
        let parsed: toml::Value = toml::from_str(&contents).expect("valid TOML");
        let rule_cmd = parsed["rules"][0]["commands"][0].as_str().unwrap();
        assert_eq!(rule_cmd, "echo \"hi\"");
    }

    #[test]
    fn decide_unsure_allows_once_no_rule() {
        let params = ApprovalInput {
            tool_name: "Bash".into(),
            input: input(&[("command", "weird thing")]),
            tool_use_id: None,
            permission_suggestions: None,
            blocked_path: None,
        };
        let d = ApprovalServer::decide(&params, Advice::Unsure);
        match d {
            Decision::Allow {
                updated_permissions,
                ..
            } => assert!(updated_permissions.is_empty()),
            _ => panic!("expected Allow"),
        }
    }

    #[test]
    fn build_prompt_omits_extras_when_absent() {
        let with_extras = build_prompt("Bash", Some("ls -la"), None, None);
        let legacy = {
            let target_line = "Target: ls -la";
            format!(
                "An AI coding agent wants to use tool `Bash`.\n\
                 {target_line}\n\
                 \n\
                 Decide whether this should be auto-allowed for the rest of the session.\n\
                 Reply with EXACTLY one of, followed by a one-line reason:\n\
                 \n\
                 SAFE <reason>   — routine, read-only, or clearly harmless\n\
                 UNSAFE <reason> — modifies important state, leaks secrets, or risky\n\
                 UNSURE <reason> — ambiguous; let the human decide\n\
                 \n\
                 Err UNSURE for anything you're not confident about."
            )
        };
        assert_eq!(with_extras, legacy);
    }

    #[test]
    fn build_prompt_includes_blocked_path() {
        let p = build_prompt("Bash", Some("cat /etc/passwd"), None, Some("/etc/passwd"));
        assert!(p.contains("Blocked path: /etc/passwd"), "prompt: {p}");
    }

    #[test]
    fn build_prompt_includes_suggestions() {
        let sugs = vec![serde_json::json!({"behavior": "allow", "rule": "git status"})];
        let p = build_prompt("Bash", Some("git status"), Some(&sugs), None);
        assert!(p.contains("Policy suggestions:"), "prompt: {p}");
        assert!(
            p.contains(r#""behavior":"allow""#) || p.contains(r#""behavior": "allow""#),
            "prompt: {p}"
        );
    }

    #[test]
    fn build_prompt_truncates_long_suggestion() {
        let long_val = "x".repeat(300);
        let sugs = vec![serde_json::json!({"key": long_val})];
        let p = build_prompt("Bash", Some("cmd"), Some(&sugs), None);
        let sug_line = p
            .lines()
            .find(|l| l.trim_start().starts_with('{'))
            .expect("suggestion line present");
        assert!(sug_line.ends_with('\u{2026}'), "line: {sug_line}");
        // 2 spaces indent + up to 199 chars + 3-byte ellipsis = at most 204 bytes
        assert!(sug_line.len() <= 205, "line len={}", sug_line.len());
    }
}
