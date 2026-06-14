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
//! Flow:
//!   1. `pre_classify` short-circuits file-edit tools (Edit/Write/MultiEdit/
//!      NotebookEdit) when the target lives inside the agent's working scope
//!      (cwd / worktree / `/tmp`). In-scope editing is normal worker behavior,
//!      so it is classified SAFE without spending a Codex call.
//!   2. Outside-scope edits and Bash invocations consult Codex via tool-
//!      specific prompts (`build_prompt_edit` frames the question as scope-
//!      escape; `build_prompt_bash` keeps the read-vs-write taxonomy).
//!   3. SAFE → allow + session-scoped remember. UNSAFE → deny with Codex's
//!      reason. UNSURE → MCP elicitation; falls back to allow-once.

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
    #[schemars(
        description = "Name of the tool Claude wants to use (Bash, Edit, Write, Read, ...)"
    )]
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
    #[serde(default)]
    #[schemars(description = "Working directory for the current Claude session, if available")]
    cwd: Option<String>,
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

#[derive(Debug)]
enum Advice {
    Safe { reason: String },
    Unsafe { reason: String },
    Unsure,
}

/// Short, human-readable target string for the prompt and logs.
fn rule_target(tool_name: &str, input: &HashMap<String, serde_json::Value>) -> Option<String> {
    match tool_name {
        "Bash" => input
            .get("command")
            .and_then(|v| v.as_str())
            .map(String::from),
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" | "Read" => input
            .get("file_path")
            .and_then(|v| v.as_str())
            .map(String::from),
        _ => None,
    }
}

/// Returns true when `tool_name` is one of the file-mutating tools whose
/// "is this safe?" question collapses to "is this an in-scope edit?".
fn is_file_edit_tool(tool_name: &str) -> bool {
    matches!(tool_name, "Edit" | "Write" | "MultiEdit" | "NotebookEdit")
}

/// Normalize `path` to an absolute path with `.` and `..` components
/// resolved lexically. Does not resolve symlinks (tolerates non-existent
/// paths so Write-to-new-file still classifies). Returns None when the
/// path can't even be made absolute.
fn normalize_abs(path: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::path::{Component, PathBuf};
    let abs = std::path::absolute(path).ok()?;
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    Some(out)
}

/// Resolve `p` to a real path, walking up the existing prefix when the
/// tail doesn't exist yet (e.g. Write to a new file). Returns the
/// canonicalized prefix joined with the lexical tail. None if no
/// component of `p` exists.
fn canonicalize_loose(p: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut existing = p.to_path_buf();
    let mut suffix = PathBuf::new();
    loop {
        if let Ok(canon) = std::fs::canonicalize(&existing) {
            return Some(if suffix.as_os_str().is_empty() {
                canon
            } else {
                canon.join(suffix)
            });
        }
        let basename = existing.file_name()?.to_owned();
        if !existing.pop() {
            return None;
        }
        suffix = std::path::PathBuf::from(&basename).join(&suffix);
    }
}

/// Returns true when `path` resolves inside the agent's working scope —
/// either `cwd` (which for ask-spawned sessions is a `.claude/worktrees/*`
/// directory) or `/tmp`. Falls back to the hook process's `current_dir`
/// when no `cwd` is supplied (the MCP server path).
///
/// Compares lexically first; if that misses, retries with symlink-resolved
/// paths so a `/home/user/Projects/...` symlink and a `/syncthing/...`
/// canonical cwd still match.
fn is_in_agent_scope(path: &str, cwd: Option<&str>) -> bool {
    use std::path::{Path, PathBuf};

    let target = match normalize_abs(Path::new(path)) {
        Some(p) => p,
        None => return false,
    };
    if target.starts_with("/tmp") {
        return true;
    }
    let cwd_raw: PathBuf = match cwd {
        Some(s) => PathBuf::from(s),
        None => match std::env::current_dir() {
            Ok(p) => p,
            Err(_) => return false,
        },
    };
    let cwd_norm = match normalize_abs(&cwd_raw) {
        Some(p) => p,
        None => return false,
    };
    if target.starts_with(&cwd_norm) {
        return true;
    }
    // Symlink fallback: resolve both sides via canonicalize and retry.
    let target_canon = canonicalize_loose(&target);
    let cwd_canon = std::fs::canonicalize(&cwd_norm).ok();
    if let (Some(t), Some(c)) = (target_canon, cwd_canon) {
        return t.starts_with(c);
    }
    false
}

/// Pre-classification before consulting Codex. Returns `Some(Safe)` for
/// file-edit tools whose target sits inside the agent's working scope —
/// editing files in the worktree or `/tmp` is the worker's job, so it
/// should bypass LLM judgment entirely. Bash and out-of-scope edits
/// return `None` and flow on to Codex.
fn pre_classify(tool_name: &str, target: Option<&str>, cwd: Option<&str>) -> Option<Advice> {
    if !is_file_edit_tool(tool_name) {
        return None;
    }
    let path = target?;
    if is_in_agent_scope(path, cwd) {
        return Some(Advice::Safe {
            reason: "edit inside agent scope (cwd/worktree/tmp)".to_string(),
        });
    }
    None
}

/// Append the shared `Blocked path` and `Policy suggestions` block used
/// by every prompt variant.
fn append_extras(
    extras: &mut String,
    suggestions: Option<&[serde_json::Value]>,
    blocked_path: Option<&str>,
) {
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
}

fn build_prompt(
    tool_name: &str,
    target: Option<&str>,
    suggestions: Option<&[serde_json::Value]>,
    blocked_path: Option<&str>,
) -> String {
    if is_file_edit_tool(tool_name) {
        build_prompt_edit(tool_name, target, suggestions, blocked_path)
    } else {
        build_prompt_bash(tool_name, target, suggestions, blocked_path)
    }
}

/// Codex prompt for Bash and other side-effecting tools. Classification
/// is based on REVERSIBILITY and BLAST RADIUS, not on whether the
/// command writes anything: an AI coding agent's job is to modify
/// project state, so "modifies state" cannot be the unsafe signal.
fn build_prompt_bash(
    tool_name: &str,
    target: Option<&str>,
    suggestions: Option<&[serde_json::Value]>,
    blocked_path: Option<&str>,
) -> String {
    let target_line = target
        .map(|t| format!("Target: {}", t))
        .unwrap_or_else(|| "Target: (no recognizable target field)".to_string());

    let mut extras = String::new();
    append_extras(&mut extras, suggestions, blocked_path);

    format!(
        "An AI coding agent wants to use tool `{tool_name}`.\n\
         {target_line}{extras}\n\
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

/// Codex prompt for file-edit tools (Edit/Write/MultiEdit/NotebookEdit)
/// that escaped the in-scope pre-classification. The question is no
/// longer "is editing risky?" — editing is the worker's job — but
/// "is this a deliberate scope escape?".
fn build_prompt_edit(
    tool_name: &str,
    target: Option<&str>,
    suggestions: Option<&[serde_json::Value]>,
    blocked_path: Option<&str>,
) -> String {
    let target_line = target
        .map(|t| format!("Target: {}", t))
        .unwrap_or_else(|| "Target: (no recognizable target field)".to_string());

    let mut extras = String::new();
    append_extras(&mut extras, suggestions, blocked_path);

    format!(
        "An AI coding agent wants to use tool `{tool_name}` to modify a file.\n\
         {target_line}{extras}\n\
         \n\
         Editing files is the agent's normal job. In-scope edits like source files, \
         manifests such as `Cargo.toml`, and scratch files under the worktree or \
         `/tmp` are already auto-allowed. This prompt only asks whether THIS path \
         is a deliberate, expected target OUTSIDE that scope.\n\
         Reply with EXACTLY one of, followed by a one-line reason:\n\
         \n\
         SAFE <reason>   — explicitly intended target outside scope (e.g. shared \
         config the user asked to update)\n\
         UNSAFE <reason> — apparent scope escape: system files, secrets, dotfiles, \
         parent project state, or anywhere edits would be hard to undo\n\
         UNSURE <reason> — ambiguous; let the human decide\n\
         \n\
         Err UNSURE for anything you're not confident about."
    )
}

/// In-process Codex call. Used by the CLI `decide` subcommand. The MCP
/// server path goes through `ask_codex_subprocess` instead so classifier
/// updates take effect without restarting long-lived MCP sessions.
async fn ask_codex_inproc(
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

/// Spawn `<self> decide` as a subprocess and parse its JSON verdict.
/// The MCP server is long-lived per Claude Code session, so calling
/// Codex in-process would freeze the classifier at session start. Each
/// approval shells out to a fresh subprocess instead, picking up any
/// post-deploy binary on disk via `current_exe()`.
async fn ask_codex_subprocess(
    tool_name: &str,
    target: Option<&str>,
    suggestions: Option<&[serde_json::Value]>,
    blocked_path: Option<&str>,
    cwd: Option<&str>,
) -> Option<Advice> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    let exe = std::env::current_exe().ok()?;
    let payload = build_decide_payload(tool_name, target, suggestions, blocked_path, cwd);
    let payload_str = serde_json::to_string(&payload).ok()?;

    let mut child = Command::new(&exe)
        .arg("decide")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let mut stdin = child.stdin.take()?;
    stdin.write_all(payload_str.as_bytes()).await.ok()?;
    stdin.write_all(b"\n").await.ok()?;
    drop(stdin);

    let output = child.wait_with_output().await.ok()?;
    if !output.status.success() {
        warn!(
            "decide subprocess exited non-zero ({:?}); treating as Unsure",
            output.status.code()
        );
        return None;
    }
    parse_decide_output(&output.stdout)
}

fn build_decide_payload(
    tool_name: &str,
    target: Option<&str>,
    suggestions: Option<&[serde_json::Value]>,
    blocked_path: Option<&str>,
    cwd: Option<&str>,
) -> serde_json::Value {
    let input_field = match tool_name {
        "Bash" => serde_json::json!({"command": target.unwrap_or("")}),
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" | "Read" => {
            serde_json::json!({"file_path": target.unwrap_or("")})
        }
        _ => serde_json::Value::Object(serde_json::Map::new()),
    };

    serde_json::json!({
        "tool_name": tool_name,
        "input": input_field,
        "cwd": cwd,
        "permission_suggestions": suggestions,
        "blocked_path": blocked_path,
    })
}

/// Parse the JSON line emitted by `run_decide_cli`: `{"verdict":"safe|unsafe|unsure","reason":"…"}`.
fn parse_decide_output(stdout: &[u8]) -> Option<Advice> {
    let text = std::str::from_utf8(stdout).ok()?.trim();
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let verdict = v.get("verdict")?.as_str()?;
    let reason = v
        .get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();
    match verdict {
        "safe" => Some(Advice::Safe { reason }),
        "unsafe" => Some(Advice::Unsafe { reason }),
        "unsure" => Some(Advice::Unsure),
        _ => None,
    }
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
            io::Error::new(
                io::ErrorKind::NotFound,
                "HOME not set; cannot locate config",
            )
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

    pub fn parse_result(
        action: ElicitationAction,
        content: Option<&serde_json::Value>,
    ) -> Option<UserChoice> {
        match action {
            ElicitationAction::Decline | ElicitationAction::Cancel => Some(UserChoice::AllowOnce),
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
        hint: &str,
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

        let req = elicit::build_request(&params.tool_name, t, hint);
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
                info!(
                    "user chose DENY tool={} target={t:?}; approving once",
                    params.tool_name
                );
                allow_once()
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

    /// Build an Allow decision for SAFE advice, attaching a session-scoped
    /// allow rule for the recognized target. Unsafe and Unsure are routed
    /// through `handle_unsure` instead of this path.
    fn decide_safe(params: &ApprovalInput, reason: String) -> Decision {
        let target = rule_target(&params.tool_name, &params.input);
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
        } else if let Some(pre) =
            pre_classify(&params.tool_name, target.as_deref(), params.cwd.as_deref())
        {
            info!(
                "pre-classified SAFE (in-scope edit) tool={} target={:?}",
                params.tool_name, target
            );
            pre
        } else {
            ask_codex_subprocess(
                &params.tool_name,
                target.as_deref(),
                params.permission_suggestions.as_deref(),
                params.blocked_path.as_deref(),
                params.cwd.as_deref(),
            )
            .await
            .unwrap_or_else(|| {
                warn!("decide subprocess unreachable; falling back to Unsure");
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

        // SAFE auto-allows. Anything else (UNSURE / UNSAFE) routes through
        // MCP elicitation so the user gets a 3-choice (deny / once / always)
        // prompt instead of being silently denied. UNSAFE was previously a
        // hard deny, but Codex calls every state-changing command "unsafe"
        // (git merge, git rebase, …) so the deny path was a usability wall
        // rather than a safety net.
        let decision = match advice {
            Advice::Safe { reason } => Self::decide_safe(&params, reason),
            Advice::Unsure => {
                info!(
                    "codex UNSURE tool={} target={:?} — eliciting",
                    params.tool_name, target
                );
                self.handle_unsure(&params, &target, &ctx, "codex unsure")
                    .await
            }
            Advice::Unsafe { reason } => {
                info!(
                    "codex UNSAFE tool={} target={:?} reason={} — eliciting",
                    params.tool_name, target, reason
                );
                let hint = if reason.is_empty() {
                    "codex flagged as unsafe".to_string()
                } else {
                    format!("codex: {reason}")
                };
                self.handle_unsure(&params, &target, &ctx, &hint).await
            }
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

// ── persist-rule subcommand ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PersistRuleInput {
    tool_name: String,
    input: HashMap<String, serde_json::Value>,
    feedback: String,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Serialize)]
struct PersistRuleOutput {
    rule_written: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    commands: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn build_persist_prompt(target: &str, feedback: &str) -> String {
    format!(
        "A user wants to permanently auto-approve a class of bash commands.\n\
         \n\
         Original command: {target}\n\
         User's intent: {feedback}\n\
         \n\
         Output ONLY a JSON array of bash command prefixes that should be auto-approved\n\
         based on this intent. Stay conservative — only include commands you would\n\
         allow without asking. Each prefix is matched as a literal string at the\n\
         start of the bash invocation, so \"git status\" allows `git status`, `git status -s`,\n\
         `git status --short`, etc. Do NOT include destructive commands.\n\
         \n\
         Example output: [\"git status\", \"git log\", \"git diff\", \"git show\"]"
    )
}

fn parse_command_list(text: &str) -> Option<Vec<String>> {
    let trimmed = text.trim();
    // Strip markdown code fences if present.
    let json_str = if trimmed.starts_with("```") {
        let without_open = trimmed.trim_start_matches('`');
        // Strip optional language tag (e.g. "json\n")
        let after_tag = if let Some(nl) = without_open.find('\n') {
            &without_open[nl + 1..]
        } else {
            without_open
        };
        // Strip closing fence
        let stripped = if let Some(close) = after_tag.rfind("```") {
            &after_tag[..close]
        } else {
            after_tag
        };
        stripped.trim()
    } else {
        trimmed
    };

    let list: Vec<String> = serde_json::from_str(json_str).ok()?;
    // Trim each entry and deduplicate, preserving first-seen order.
    let mut seen = std::collections::HashSet::new();
    let deduped: Vec<String> = list
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && seen.insert(s.clone()))
        .collect();
    if deduped.is_empty() {
        None
    } else {
        Some(deduped)
    }
}

async fn ask_codex_for_commands(target: &str, feedback: &str) -> Option<Vec<String>> {
    use llm_sdk::Backend;
    use llm_sdk::codex_cli::CodexCli;

    // Allow CLAUDE_APPROVAL_MOCK to short-circuit codex during tests.
    if let Ok(mock) = std::env::var("CLAUDE_APPROVAL_MOCK") {
        if let Some(rest) = mock.strip_prefix("mock-commands:") {
            return parse_command_list(rest);
        }
    }

    let backend = CodexCli::new()
        .ok()?
        .model(CODEX_MODEL)
        .timeout(CODEX_TIMEOUT);
    let prompt = build_persist_prompt(target, feedback);
    let output = backend.complete(&prompt).await.ok()?;
    parse_command_list(&output.text)
}

async fn run_persist_rule_cli() -> Result<()> {
    use std::io::{self, BufRead, Write};

    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;

    let parsed: PersistRuleInput = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(e) => {
            let err = serde_json::json!({"error": e.to_string()});
            println!("{}", serde_json::to_string(&err)?);
            std::process::exit(2);
        }
    };

    if let Some(ref cwd) = parsed.cwd {
        info!("persist-rule cwd={cwd}");
    }

    let stdout = io::stdout();

    let emit = |out: &PersistRuleOutput| -> Result<()> {
        let mut handle = stdout.lock();
        handle.write_all(serde_json::to_string(out)?.as_bytes())?;
        handle.write_all(b"\n")?;
        handle.flush()?;
        Ok(())
    };

    if parsed.tool_name != "Bash" {
        return emit(&PersistRuleOutput {
            rule_written: false,
            commands: None,
            reason: None,
            error: Some("persist-rule v1 only supports tool_name=Bash".to_string()),
        });
    }

    let target = match parsed.input.get("command").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            return emit(&PersistRuleOutput {
                rule_written: false,
                commands: None,
                reason: None,
                error: Some("missing command".to_string()),
            });
        }
    };

    let commands = match ask_codex_for_commands(&target, &parsed.feedback).await {
        Some(cmds) => cmds,
        None => {
            return emit(&PersistRuleOutput {
                rule_written: false,
                commands: None,
                reason: None,
                error: Some("codex returned no usable commands".to_string()),
            });
        }
    };

    let reason = format!("user: {}", parsed.feedback);
    for cmd in &commands {
        match config_writer::append_bash_allow_rule(cmd, &reason) {
            Ok(()) => info!("persisted bash allow rule cmd={cmd:?}"),
            Err(e) => warn!("persist failed cmd={cmd:?} err={e}"),
        }
    }

    emit(&PersistRuleOutput {
        rule_written: true,
        commands: Some(commands),
        reason: Some(reason),
        error: None,
    })
}

// ── decide subcommand ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DecideInput {
    tool_name: String,
    input: HashMap<String, serde_json::Value>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    permission_suggestions: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    blocked_path: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "verdict", rename_all = "lowercase")]
enum CliVerdict {
    Safe { reason: String },
    Unsafe { reason: String },
    Unsure,
}

async fn run_decide_cli() -> Result<()> {
    use std::io::{self, BufRead, Write};

    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;

    let parsed: DecideInput = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(e) => {
            let err = serde_json::json!({"error": e.to_string()});
            println!("{}", serde_json::to_string(&err)?);
            std::process::exit(2);
        }
    };

    let tool_name = &parsed.tool_name;
    let target = rule_target(tool_name, &parsed.input);

    if let Some(ref cwd) = parsed.cwd {
        info!("decide cwd={cwd}");
    }

    info!("decide tool={} target={:?}", tool_name, target);

    let advice = if let Some(mocked) = mock_advice_from_env() {
        info!(
            "CLAUDE_APPROVAL_MOCK set; bypassing codex tool={} target={:?}",
            tool_name, target
        );
        mocked
    } else if let Some(pre) = pre_classify(tool_name, target.as_deref(), parsed.cwd.as_deref()) {
        info!(
            "pre-classified SAFE (in-scope edit) tool={} target={:?} cwd={:?}",
            tool_name, target, parsed.cwd
        );
        pre
    } else {
        ask_codex_inproc(
            tool_name,
            target.as_deref(),
            parsed.permission_suggestions.as_deref(),
            parsed.blocked_path.as_deref(),
        )
        .await
        .unwrap_or_else(|| {
            warn!("codex unreachable; treating as Unsure");
            Advice::Unsure
        })
    };

    let verdict = match advice {
        Advice::Safe { reason } => {
            info!(
                "decide tool={} target={:?} verdict=safe reason={}",
                tool_name, target, reason
            );
            CliVerdict::Safe { reason }
        }
        Advice::Unsafe { reason } => {
            info!(
                "decide tool={} target={:?} verdict=unsafe reason={}",
                tool_name, target, reason
            );
            CliVerdict::Unsafe { reason }
        }
        Advice::Unsure => {
            info!(
                "decide tool={} target={:?} verdict=unsure",
                tool_name, target
            );
            CliVerdict::Unsure
        }
    };

    let out = serde_json::to_string(&verdict)?;
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(out.as_bytes())?;
    handle.write_all(b"\n")?;
    handle.flush()?;

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let _ = systemd_journal_logger::JournalLog::new().map(|l| {
        l.with_syslog_identifier("claude-bash-hook-approval".into())
            .install()
    });
    log::set_max_level(log::LevelFilter::Info);

    match std::env::args().nth(1).as_deref() {
        Some("decide") => return run_decide_cli().await,
        Some("persist-rule") => return run_persist_rule_cli().await,
        _ => {}
    }

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
        assert!(matches!(
            parse_advice("UNSURE depends on cwd"),
            Advice::Unsure
        ));
    }

    #[test]
    fn parse_advice_unknown_is_unsure() {
        assert!(matches!(parse_advice("hmm"), Advice::Unsure));
    }

    #[test]
    fn parse_decide_output_safe() {
        let bytes = br#"{"verdict":"safe","reason":"git merge is reversible"}"#;
        match parse_decide_output(bytes) {
            Some(Advice::Safe { reason }) => assert_eq!(reason, "git merge is reversible"),
            other => panic!("expected Safe, got {other:?}"),
        }
    }

    #[test]
    fn parse_decide_output_unsafe() {
        let bytes = br#"{"verdict":"unsafe","reason":"rm -rf /"}"#;
        match parse_decide_output(bytes) {
            Some(Advice::Unsafe { reason }) => assert_eq!(reason, "rm -rf /"),
            other => panic!("expected Unsafe, got {other:?}"),
        }
    }

    #[test]
    fn parse_decide_output_unsure() {
        let bytes = br#"{"verdict":"unsure"}"#;
        assert!(matches!(parse_decide_output(bytes), Some(Advice::Unsure)));
    }

    #[test]
    fn parse_decide_output_garbage_returns_none() {
        assert!(parse_decide_output(b"not json").is_none());
        assert!(parse_decide_output(b"{}").is_none());
        assert!(parse_decide_output(br#"{"verdict":"maybe"}"#).is_none());
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
            cwd: None,
        };
        let d = ApprovalServer::decide_safe(&params, "read-only".into());
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
    fn pre_classify_returns_none_for_bash() {
        assert!(pre_classify("Bash", Some("rm -rf /"), Some("/tmp")).is_none());
    }

    #[test]
    fn pre_classify_returns_none_for_unknown_tool() {
        assert!(pre_classify("Mystery", Some("/tmp/x"), Some("/tmp")).is_none());
    }

    #[test]
    fn pre_classify_safe_when_path_under_cwd() {
        let advice = pre_classify("Edit", Some("/tmp/work/file.rs"), Some("/tmp/work"));
        assert!(matches!(advice, Some(Advice::Safe { .. })));
    }

    #[test]
    fn pre_classify_safe_when_path_under_tmp() {
        let advice = pre_classify(
            "Write",
            Some("/tmp/scratch/output.log"),
            Some("/home/user/project"),
        );
        assert!(matches!(advice, Some(Advice::Safe { .. })));
    }

    #[test]
    fn pre_classify_safe_for_manifest_under_cwd() {
        let advice = pre_classify(
            "Write",
            Some("/home/user/project/Cargo.toml"),
            Some("/home/user/project"),
        );
        assert!(matches!(advice, Some(Advice::Safe { .. })));
    }

    #[test]
    fn pre_classify_none_when_path_outside_cwd_and_tmp() {
        let advice = pre_classify("Edit", Some("/etc/passwd"), Some("/home/user/project"));
        assert!(advice.is_none());
    }

    #[test]
    fn pre_classify_none_when_target_missing() {
        assert!(pre_classify("Edit", None, Some("/tmp")).is_none());
    }

    #[test]
    fn pre_classify_none_for_traversal_escape() {
        // /tmp/../etc/passwd normalizes to /etc/passwd → outside scope.
        let advice = pre_classify(
            "Edit",
            Some("/tmp/../etc/passwd"),
            Some("/home/user/project"),
        );
        assert!(
            advice.is_none(),
            "traversal escape must not pre-classify SAFE"
        );
    }

    #[test]
    fn pre_classify_safe_for_multiedit_under_cwd() {
        let advice = pre_classify(
            "MultiEdit",
            Some("/home/user/proj/src/lib.rs"),
            Some("/home/user/proj"),
        );
        assert!(matches!(advice, Some(Advice::Safe { .. })));
    }

    #[test]
    fn pre_classify_safe_for_notebookedit_under_tmp() {
        let advice = pre_classify("NotebookEdit", Some("/tmp/nb.ipynb"), Some("/elsewhere"));
        assert!(matches!(advice, Some(Advice::Safe { .. })));
    }

    #[test]
    fn pre_classify_safe_through_symlink() {
        // Reproduces the wow-ui-sim case: target uses one symlink prefix
        // (e.g. `/home/user/Projects/foo`) and cwd uses the canonical path
        // (e.g. `/syncthing/Projects/foo`). Lexical `starts_with` misses;
        // canonicalize fallback must rescue.
        let real_root = tempfile::tempdir().expect("tmp real");
        let real_proj = real_root.path().join("proj");
        std::fs::create_dir_all(real_proj.join("src")).unwrap();
        let target = real_proj.join("src/lib.rs");
        std::fs::write(&target, "").unwrap();

        let link_root = tempfile::tempdir().expect("tmp link");
        let link_proj = link_root.path().join("proj_link");
        std::os::unix::fs::symlink(&real_proj, &link_proj).unwrap();

        // Target via symlink, cwd via real path → lexical compare misses.
        let target_via_link = link_proj.join("src/lib.rs");
        let advice = pre_classify(
            "Edit",
            Some(target_via_link.to_str().unwrap()),
            Some(real_proj.to_str().unwrap()),
        );
        assert!(
            matches!(advice, Some(Advice::Safe { .. })),
            "edit through symlink should be SAFE; got {advice:?}"
        );

        // And the inverse: target via real path, cwd via symlink.
        let advice = pre_classify(
            "Edit",
            Some(target.to_str().unwrap()),
            Some(link_proj.to_str().unwrap()),
        );
        assert!(
            matches!(advice, Some(Advice::Safe { .. })),
            "edit with symlinked cwd should be SAFE; got {advice:?}"
        );
    }

    #[test]
    fn build_prompt_edit_frames_as_scope_escape() {
        let p = build_prompt("Edit", Some("/etc/passwd"), None, None);
        assert!(
            p.contains("OUTSIDE"),
            "edit prompt should mention OUTSIDE scope; got: {p}"
        );
        assert!(
            p.contains("scope escape") || p.contains("scope"),
            "edit prompt should reference scope; got: {p}"
        );
        // The bash prompt's reversibility framing must NOT appear in the
        // edit prompt.
        assert!(
            !p.contains("REVERSIBILITY") && !p.contains("BLAST RADIUS"),
            "edit prompt must not reuse bash framing; got: {p}"
        );
    }

    #[test]
    fn build_prompt_bash_uses_reversibility_taxonomy() {
        let p = build_prompt("Bash", Some("git merge feature"), None, None);
        // The bash prompt frames classification as reversibility / blast
        // radius — not "modifies important state", which conflated routine
        // writes with destructive ones and made every git command UNSAFE.
        assert!(
            p.contains("REVERSIBLE") || p.contains("reversible"),
            "expected reversibility framing; got: {p}"
        );
        assert!(
            p.contains("git merge"),
            "expected example list to mention git merge as SAFE; got: {p}"
        );
        assert!(
            p.contains("Err UNSURE — not UNSAFE"),
            "expected explicit UNSAFE-fallback guard; got: {p}"
        );
        assert!(!p.contains("OUTSIDE"), "got: {p}");
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
    fn cli_verdict_safe_serializes_with_reason() {
        let v = CliVerdict::Safe {
            reason: "read-only".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            r#"{"verdict":"safe","reason":"read-only"}"#
        );
    }

    #[test]
    fn cli_verdict_unsafe_serializes_with_reason() {
        let v = CliVerdict::Unsafe {
            reason: "destroys data".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            r#"{"verdict":"unsafe","reason":"destroys data"}"#
        );
    }

    #[test]
    fn cli_verdict_unsure_omits_reason() {
        assert_eq!(
            serde_json::to_string(&CliVerdict::Unsure).unwrap(),
            r#"{"verdict":"unsure"}"#
        );
    }

    #[test]
    fn approval_input_parses_cwd() {
        let json = r#"{
            "tool_name": "Edit",
            "input": {"file_path": "/tmp/test.rs"},
            "cwd": "/syncthing/Sync/Projects/foo",
            "permission_suggestions": [],
            "blocked_path": null
        }"#;
        let input: ApprovalInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.cwd.as_deref(), Some("/syncthing/Sync/Projects/foo"));
    }

    #[test]
    fn build_decide_payload_includes_cwd() {
        let payload = build_decide_payload(
            "Edit",
            Some("/syncthing/Sync/Projects/foo/src/lib.rs"),
            None,
            Some("/syncthing/Sync/Projects/foo/src/lib.rs"),
            Some("/syncthing/Sync/Projects/foo"),
        );
        assert_eq!(payload["cwd"], "/syncthing/Sync/Projects/foo");
        assert_eq!(
            payload["input"]["file_path"],
            "/syncthing/Sync/Projects/foo/src/lib.rs"
        );
    }

    #[test]
    fn decide_input_parses_full_payload() {
        let json = r#"{
            "tool_name": "Bash",
            "input": {"command": "ls -la"},
            "cwd": "/home/osso/Repos/ask",
            "permission_suggestions": [{"behavior":"allow","rule":"git status"}],
            "blocked_path": "/etc/passwd"
        }"#;
        let d: DecideInput = serde_json::from_str(json).unwrap();
        assert_eq!(d.tool_name, "Bash");
        assert_eq!(
            d.input.get("command").and_then(|v| v.as_str()),
            Some("ls -la")
        );
        assert_eq!(d.cwd.as_deref(), Some("/home/osso/Repos/ask"));
        assert!(d.permission_suggestions.is_some());
        assert_eq!(d.permission_suggestions.as_ref().unwrap().len(), 1);
        assert_eq!(d.blocked_path.as_deref(), Some("/etc/passwd"));
    }

    #[test]
    fn decide_input_parses_minimal_payload() {
        let json = r#"{"tool_name":"Bash","input":{"command":"ls"}}"#;
        let d: DecideInput = serde_json::from_str(json).unwrap();
        assert_eq!(d.tool_name, "Bash");
        assert!(d.cwd.is_none());
        assert!(d.permission_suggestions.is_none());
        assert!(d.blocked_path.is_none());
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

    // ── persist-rule tests ────────────────────────────────────────────────────

    #[test]
    fn build_persist_prompt_includes_target_and_feedback() {
        let p = build_persist_prompt("git status", "approve any read-only git command");
        assert!(p.contains("git status"), "prompt missing target");
        assert!(
            p.contains("approve any read-only git command"),
            "prompt missing feedback"
        );
    }

    #[test]
    fn parse_command_list_plain_json() {
        let result = parse_command_list(r#"["git status", "git log"]"#);
        assert_eq!(
            result,
            Some(vec!["git status".to_string(), "git log".to_string()])
        );
    }

    #[test]
    fn parse_command_list_fenced_json() {
        let fenced = "```json\n[\"cargo build\", \"cargo test\"]\n```";
        let result = parse_command_list(fenced);
        assert_eq!(
            result,
            Some(vec!["cargo build".to_string(), "cargo test".to_string()])
        );
    }

    #[test]
    fn parse_command_list_garbage_returns_none() {
        assert_eq!(parse_command_list("no idea"), None);
    }

    #[test]
    fn parse_command_list_dedupes_and_trims() {
        let result = parse_command_list(r#"[" git status", "git status", " git log "]"#);
        assert_eq!(
            result,
            Some(vec!["git status".to_string(), "git log".to_string()])
        );
    }

    #[test]
    fn persist_rule_output_serializes_success() {
        let out = PersistRuleOutput {
            rule_written: true,
            commands: Some(vec!["git status".to_string(), "git log".to_string()]),
            reason: Some("user: approve git reads".to_string()),
            error: None,
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&out).unwrap()).unwrap();
        assert_eq!(json["rule_written"], true);
        assert_eq!(json["commands"][0], "git status");
        assert_eq!(json["commands"][1], "git log");
        assert_eq!(json["reason"], "user: approve git reads");
        assert!(json.get("error").is_none() || json["error"].is_null());
    }

    #[test]
    fn persist_rule_output_serializes_skipped() {
        let out = PersistRuleOutput {
            rule_written: false,
            commands: None,
            reason: None,
            error: Some("persist-rule v1 only supports tool_name=Bash".to_string()),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&out).unwrap()).unwrap();
        assert_eq!(json["rule_written"], false);
        assert_eq!(
            json["error"],
            "persist-rule v1 only supports tool_name=Bash"
        );
        assert!(json.get("commands").is_none() || json["commands"].is_null());
        assert!(json.get("reason").is_none() || json["reason"].is_null());
    }
}
