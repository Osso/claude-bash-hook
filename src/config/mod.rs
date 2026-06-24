//! Configuration loading and rule matching

use serde::Deserialize;
use std::path::Path;

/// Embedded default configuration
const DEFAULT_CONFIG: &str = include_str!("../../config.default.toml");
const DEFAULT_NETWORK_CONFIG: &str = include_str!("../../network.default.toml");
const DEFAULT_HOSTRUN_CONFIG: &str = include_str!("../../hostrun.default.toml");

mod matching;
mod network;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_aliases;
#[cfg(test)]
mod tests_npm;
#[cfg(test)]
mod tests_overrides;

/// Permission levels (ordered by restrictiveness)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    Allow = 0,
    Passthrough = 1,
    Ask = 2,
    Deny = 3,
}

impl Default for Permission {
    fn default() -> Self {
        Permission::Ask
    }
}

/// Result of checking a command against rules
#[derive(Debug, Default)]
pub struct PermissionResult {
    pub permission: Permission,
    pub reason: String,
    pub suggestion: Option<String>,
}

/// Execution context passed through all analysis functions
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecContext {
    /// Whether the session is in edit mode (acceptEdits/bypassPermissions)
    pub edit_mode: bool,
    /// Whether the command comes from a subagent (Task() call)
    pub is_subagent: bool,
    /// Whether the session is in bypassPermissions ("yolo") mode
    pub bypass: bool,
}

/// Main configuration structure
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Default permission for unmatched commands
    #[serde(default = "default_permission")]
    pub default: String,

    /// Default permission for subagent commands when no rule matches (optional)
    #[serde(default)]
    pub subagent_default: Option<String>,

    /// Override permission for main thread (non-subagent) commands.
    /// When set, ALL main thread commands use this permission unless the rule
    /// has an explicit `main_thread_permission` override.
    /// Use "deny" to force all bash work through Task() agents.
    #[serde(default)]
    pub main_thread_default: Option<String>,

    /// Classify passthrough commands with codex spark (gpt-5.3-codex-spark).
    /// SAFE → allow, UNSAFE → ask, UNSURE → real passthrough.
    #[serde(default)]
    pub passthrough_llm: bool,

    /// Directories where git push to master/main is allowed
    #[serde(default)]
    pub master_push_allowed: Vec<String>,

    /// MySQL/MariaDB command aliases (for SQL query analysis)
    #[serde(default = "default_mysql_aliases")]
    pub mysql_aliases: Vec<String>,

    /// Commands where the SQL query is passed as a positional argument.
    /// Format: "command subcommand" (e.g., "groundcover-cli sql-clickhouse")
    #[serde(default)]
    pub positional_sql_commands: Vec<String>,

    /// Command rules
    #[serde(default)]
    pub rules: Vec<Rule>,

    /// Wrapper configurations
    #[serde(default)]
    pub wrappers: Vec<WrapperConfig>,

    /// Command suggestions
    #[serde(default)]
    pub suggestions: Vec<Suggestion>,

    /// File paths allowed for Write/Edit on main thread even when main_thread_default is deny.
    /// Supports exact paths and simple "dir/*" glob patterns. ~ expands to $HOME.
    #[serde(default)]
    pub main_thread_write_allow: Vec<String>,

    /// Paths that should always force an explicit prompt for Write/Edit/Read/rm.
    /// Supports exact paths and simple "dir/*" glob patterns. ~ expands to $HOME.
    #[serde(default)]
    pub ask_paths: Vec<String>,

    /// Paths that force an explicit prompt for *modifying* commands only
    /// (Write/Edit/rm/tee/cp/mv/install) but NOT Read. Use for system dirs
    /// like /usr where reads are frequent and benign but writes are dangerous.
    /// Supports exact paths and simple "dir/*" glob patterns. ~ expands to $HOME.
    #[serde(default)]
    pub ask_write_paths: Vec<String>,

    /// Paths auto-allowed for Read. `ask_paths` wins on overlap.
    /// Supports exact paths and simple "dir/*" glob patterns. ~ expands to $HOME.
    #[serde(default)]
    pub read_allow_paths: Vec<String>,

    /// Paths auto-allowed for Write/Edit. `ask_paths` wins on overlap.
    /// Supports exact paths and simple "dir/*" glob patterns. ~ expands to $HOME.
    #[serde(default)]
    pub write_allow_paths: Vec<String>,

    /// Rewrite configuration for prepending a binary (e.g., rtk) to allowed commands
    #[serde(default)]
    pub rewrite: Option<RewriteConfig>,

    /// Command aliases — rewrite command names before analysis
    #[serde(default)]
    pub aliases: Vec<AliasConfig>,

    /// Shared network host policy, loaded from network.toml next to config.toml.
    #[serde(skip)]
    pub network: NetworkConfig,

    /// Hostrun operation policy, loaded from hostrun.toml next to config.toml.
    #[serde(skip)]
    pub hostrun: HostrunConfig,
}

fn default_permission() -> String {
    "ask".to_string()
}

fn default_mysql_aliases() -> Vec<String> {
    vec![
        "mysql".to_string(),
        "mariadb".to_string(),
        "mysql-gc".to_string(),
    ]
}

/// A permission rule
#[derive(Debug, Deserialize)]
pub struct Rule {
    /// Commands this rule matches (e.g., ["ls", "cat", "git status"])
    pub commands: Vec<String>,

    /// Permission: "allow", "ask", "deny", or "check_host"
    pub permission: String,

    /// Override permission when in edit mode (acceptEdits/bypassPermissions)
    #[serde(default)]
    pub edit_mode_permission: Option<String>,

    /// Override permission for subagent commands (Task() calls)
    #[serde(default)]
    pub subagent_permission: Option<String>,

    /// Override permission for main thread (non-subagent) commands.
    /// Only checked when Config.main_thread_default is set.
    #[serde(default)]
    pub main_thread_permission: Option<String>,

    /// Reason for this rule
    #[serde(default)]
    pub reason: String,

    /// Host rules for check_host permission
    #[serde(default)]
    pub host_rules: Vec<HostRule>,

    /// When true and a host matches only the `*` wildcard, query an LLM to
    /// decide if the host is safe, auto-allowing if it says SAFE.
    #[serde(default)]
    pub llm_fallback: bool,

    /// Required working directory (glob pattern, e.g., "/home/user/Projects/linux")
    #[serde(default)]
    pub cwd: Option<String>,

    /// Options that take arguments (for subcommand detection)
    #[serde(default)]
    pub opts_with_args: Vec<String>,
}

impl Rule {
    /// Get the effective permission string, considering execution context
    /// Priority: subagent_permission > edit_mode_permission > permission
    pub fn effective_permission(&self, ctx: ExecContext) -> &str {
        if ctx.is_subagent
            && let Some(ref p) = self.subagent_permission
        {
            return p;
        }
        if ctx.edit_mode
            && let Some(ref p) = self.edit_mode_permission
        {
            return p;
        }
        &self.permission
    }
}

/// Host-based permission rule
#[derive(Debug, Deserialize)]
pub struct HostRule {
    /// Glob pattern for host matching
    pub pattern: String,
    /// Permission for matching hosts
    pub permission: String,
    /// When true, skip inner command analysis — trust all commands on this host
    #[serde(default)]
    pub skip_inner: bool,
}

/// Shared network host policy used by curl and Hostrun HTTP operations.
#[derive(Debug, Default, Deserialize)]
pub struct NetworkConfig {
    /// Host rules applied in order.
    #[serde(default)]
    pub hosts: Vec<HostRule>,

    /// When true and a host matches only the `*` wildcard, query an LLM to
    /// decide if the host is safe, auto-allowing if it says SAFE.
    #[serde(default)]
    pub llm_fallback: bool,
}

/// Hostrun operation policy.
#[derive(Debug, Default, Deserialize)]
pub struct HostrunConfig {
    /// Operation rules applied in order.
    #[serde(default)]
    pub rules: Vec<HostrunRule>,
}

impl HostrunConfig {
    fn validate(&self) -> Result<(), String> {
        for rule in &self.rules {
            if !is_hostrun_permission(&rule.permission) {
                return Err(format!(
                    "Hostrun {} rule has invalid permission {}",
                    rule.operation, rule.permission
                ));
            }
            if rule.operation.starts_with("fs.") && rule.path.is_none() {
                return Err(format!(
                    "Hostrun {} rule requires a path pattern",
                    rule.operation
                ));
            }
        }
        Ok(())
    }
}

fn is_hostrun_permission(permission: &str) -> bool {
    matches!(
        permission,
        "allow" | "ask" | "deny" | "passthrough" | "check_network_host"
    )
}

/// Hostrun operation rule.
#[derive(Debug, Deserialize)]
pub struct HostrunRule {
    /// Hostrun operation, e.g. "fs.read" or "http.request".
    pub operation: String,

    /// Path glob for filesystem operations.
    #[serde(default)]
    pub path: Option<String>,

    /// Permission for matching operations.
    pub permission: String,
}

/// Wrapper command configuration
#[derive(Debug, Clone, Deserialize)]
pub struct WrapperConfig {
    /// The wrapper command name
    pub command: String,

    /// Options that take an argument (e.g., ["-u", "-g"] for sudo)
    #[serde(default)]
    pub opts_with_args: Vec<String>,
}

/// Command suggestion
#[derive(Debug, Deserialize)]
pub struct Suggestion {
    /// Command to match
    pub command: String,

    /// Suggestion message
    pub message: String,

    /// Optional regex pattern for more specific matching
    #[serde(default)]
    pub pattern: Option<String>,
}

/// Configuration for rewriting commands through a proxy binary
#[derive(Debug, Deserialize)]
pub struct RewriteConfig {
    /// Whether rewriting is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Binary to prepend (e.g., "rtk")
    #[serde(default = "default_rewrite_binary")]
    pub binary: String,
    /// Command prefixes to match for rewriting
    #[serde(default)]
    pub prefixes: Vec<String>,
}

fn default_rewrite_binary() -> String {
    "rtk".to_string()
}

/// Command alias — rewrite one command name to another before analysis
#[derive(Debug, Deserialize)]
pub struct AliasConfig {
    /// Command name to match (e.g., "fdfind")
    pub from: String,
    /// Command name to replace with (e.g., "fd")
    pub to: String,
}

/// Replace occurrences of `from` at command-name positions in `s` with `to`.
/// A command position is: start of string (after whitespace), or after |, ||, &&, ;, (, $(.
/// Requires a word boundary after: whitespace, EOF, or shell metachar (;|&)>).
fn replace_command_name(s: &str, from: &str, to: &str) -> String {
    let bytes = s.as_bytes();
    let from_bytes = from.as_bytes();
    let from_len = from.len();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;

    while i < bytes.len() {
        if is_alias_match_at(bytes, i, from_bytes, from_len) {
            result.push_str(to);
            i += from_len;
            continue;
        }

        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

fn is_alias_match_at(bytes: &[u8], index: usize, from_bytes: &[u8], from_len: usize) -> bool {
    is_command_position(bytes, index)
        && bytes[index..].starts_with(from_bytes)
        && has_command_boundary_after(bytes, index, from_len)
}

fn is_command_position(bytes: &[u8], index: usize) -> bool {
    if index == 0 {
        return true;
    }
    let pre = &bytes[..index];
    let Some(last_nonws) = pre.iter().rposition(|&b| !b.is_ascii_whitespace()) else {
        return true;
    };
    let separator = pre[last_nonws];
    if !matches!(separator, b'|' | b';' | b'(' | b'&') {
        return false;
    }
    bytes[last_nonws + 1..index]
        .iter()
        .all(|b| b.is_ascii_whitespace())
}

fn has_command_boundary_after(bytes: &[u8], index: usize, from_len: usize) -> bool {
    bytes.get(index + from_len).map_or(true, |&b| {
        b.is_ascii_whitespace() || matches!(b, b';' | b'|' | b'&' | b')' | b'>')
    })
}

impl Config {
    /// Apply command aliases to a command string.
    /// Replaces command names at word boundaries (first word, or first word after pipes/semicolons/&&/||).
    /// Returns Some(rewritten) if any alias matched, None otherwise.
    pub fn apply_aliases(&self, command: &str) -> Option<String> {
        if self.aliases.is_empty() {
            return None;
        }
        let mut result = command.to_string();
        let mut changed = false;
        for alias in &self.aliases {
            let new = replace_command_name(&result, &alias.from, &alias.to);
            if new != result {
                result = new;
                changed = true;
            }
        }
        changed.then_some(result)
    }

    /// Check if a command should be rewritten and return the rewritten command.
    /// Only call this for commands that were allowed.
    pub fn rewrite_command(&self, command: &str) -> Option<String> {
        let rewrite = self.rewrite.as_ref()?;
        if !rewrite.enabled || rewrite.prefixes.is_empty() {
            return None;
        }

        let trimmed = command.trim();

        // Skip compound commands (&&, ||, ;, |) — too risky to partially rewrite
        if trimmed.contains("&&")
            || trimmed.contains("||")
            || trimmed.contains(';')
            || trimmed.contains('|')
        {
            return None;
        }

        // Skip if already rewritten
        let binary = &rewrite.binary;
        if trimmed.starts_with(binary) && trimmed[binary.len()..].starts_with(' ') {
            return None;
        }

        // Find longest matching prefix
        let mut best_match: Option<&str> = None;
        for prefix in &rewrite.prefixes {
            // Must match at word boundary: "git" matches "git status" but not "github"
            if trimmed == prefix.as_str()
                || (trimmed.starts_with(prefix.as_str())
                    && trimmed.as_bytes().get(prefix.len()) == Some(&b' '))
            {
                if best_match.map_or(true, |b| prefix.len() > b.len()) {
                    best_match = Some(prefix);
                }
            }
        }

        best_match.map(|_| format!("{} {}", binary, trimmed))
    }

    /// Load configuration from a file
    pub fn load(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read config: {}", e))?;

        let mut config: Self =
            toml::from_str(&content).map_err(|e| format!("Failed to parse config: {}", e))?;
        config.load_sidecars(path.parent().unwrap_or_else(|| Path::new(".")))?;
        Ok(config)
    }

    /// Load from default location or return default config
    pub fn load_or_default() -> Self {
        let home = std::env::var("HOME").unwrap_or_default();
        let config_path = Path::new(&home).join(".config/claude-bash-hook/config.toml");

        if config_path.exists() {
            match Self::load(&config_path) {
                Ok(config) => return config,
                Err(e) => {
                    eprintln!("Warning: {}, using defaults", e);
                }
            }
        }

        Self::default()
    }

    fn load_sidecars(&mut self, config_dir: &Path) -> Result<(), String> {
        self.network =
            load_optional_sidecar(&config_dir.join("network.toml"), "network")?.unwrap_or_default();
        self.hostrun =
            load_optional_sidecar(&config_dir.join("hostrun.toml"), "hostrun")?.unwrap_or_default();
        self.hostrun.validate()?;
        Ok(())
    }

    /// Get wrapper config by command name
    pub fn get_wrapper(&self, name: &str) -> Option<&WrapperConfig> {
        self.wrappers.iter().find(|w| w.command == name)
    }

    /// Check if a directory is allowed for git push to master/main
    pub fn is_master_push_allowed(&self, cwd: Option<&str>) -> bool {
        let Some(cwd) = cwd.and_then(canonicalize_for_match) else {
            return false;
        };
        self.master_push_allowed
            .iter()
            .filter_map(|allowed| canonicalize_for_match(&expand_home(allowed)))
            .any(|allowed| is_same_or_child_path(&cwd, &allowed))
    }

    /// Check if a command name is a MySQL/MariaDB alias
    pub fn is_mysql_alias(&self, name: &str) -> bool {
        self.mysql_aliases.iter().any(|alias| alias == name)
    }

    /// Check if a command+subcommand pair is a positional SQL command
    pub fn is_positional_sql_command(&self, name: &str, subcommand: &str) -> bool {
        let key = format!("{} {}", name, subcommand);
        self.positional_sql_commands
            .iter()
            .any(|entry| entry == &key)
    }

    /// Check if a file path is allowed for main thread writes
    pub fn is_main_thread_write_allowed(&self, path: &str) -> bool {
        path_matches_any(path, &self.main_thread_write_allow)
    }

    /// Check if a file path is on the ask-list (force prompt for writes/reads/rm).
    pub fn is_ask_path(&self, path: &str) -> bool {
        path_matches_any(path, &self.ask_paths)
    }

    /// True if `path` is on the write-only ask-list. Does not consider `ask_paths`.
    pub fn is_ask_write_path(&self, path: &str) -> bool {
        path_matches_any(path, &self.ask_write_paths)
    }

    /// True if a *modifying* command targeting `path` must prompt: either the
    /// universal `ask_paths` or the write-only `ask_write_paths` matches.
    pub fn is_write_protected(&self, path: &str) -> bool {
        self.is_ask_path(path) || self.is_ask_write_path(path)
    }

    /// Check if a file path is auto-allowed for Read.
    pub fn is_read_allowed(&self, path: &str) -> bool {
        path_matches_any(path, &self.read_allow_paths)
    }

    /// Check if a file path is auto-allowed for Write/Edit.
    pub fn is_write_allowed(&self, path: &str) -> bool {
        path_matches_any(path, &self.write_allow_paths)
    }
}

fn path_matches_any(path: &str, patterns: &[String]) -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    for pattern in patterns {
        let expanded = if pattern.starts_with("~/") {
            format!("{}{}", home, &pattern[1..])
        } else {
            pattern.clone()
        };
        if path == expanded {
            return true;
        }
        if let Some(prefix) = expanded.strip_suffix("/*")
            && path.starts_with(prefix)
            && path.len() > prefix.len()
            && path.as_bytes()[prefix.len()] == b'/'
        {
            return true;
        }
    }
    false
}

fn canonicalize_for_match(path: &str) -> Option<String> {
    let path = Path::new(path);
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    canonical.to_str().map(str::to_string)
}

fn expand_home(path: &str) -> String {
    if !path.starts_with("~/") {
        return path.to_string();
    }

    std::env::var("HOME")
        .map(|home| format!("{}{}", home, &path[1..]))
        .unwrap_or_else(|_| path.to_string())
}

fn is_same_or_child_path(path: &str, allowed: &str) -> bool {
    path == allowed || path.starts_with(&path_prefix(allowed))
}

fn path_prefix(path: &str) -> String {
    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{}/", path)
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut config: Self =
            toml::from_str(DEFAULT_CONFIG).expect("Embedded default config is invalid");
        config.network =
            toml::from_str(DEFAULT_NETWORK_CONFIG).expect("Embedded network config is invalid");
        config.hostrun =
            toml::from_str(DEFAULT_HOSTRUN_CONFIG).expect("Embedded Hostrun config is invalid");
        config
            .hostrun
            .validate()
            .expect("Embedded Hostrun config is invalid");
        config
    }
}

fn load_optional_sidecar<T>(path: &Path, name: &str) -> Result<Option<T>, String>
where
    T: for<'de> Deserialize<'de>,
{
    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {} config: {}", name, e))?;

    toml::from_str(&content)
        .map(Some)
        .map_err(|e| format!("Failed to parse {} config: {}", name, e))
}
