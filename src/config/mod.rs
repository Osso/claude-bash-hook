//! Configuration loading and rule matching

use serde::Deserialize;
use std::path::Path;

/// Embedded default configuration
const DEFAULT_CONFIG: &str = include_str!("../../config.default.toml");

mod matching;
#[cfg(test)]
mod tests;
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

    /// Enable AI-powered advice for permission decisions
    #[serde(default)]
    pub enable_advice: bool,

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

    /// Rewrite configuration for prepending a binary (e.g., rtk) to allowed commands
    #[serde(default)]
    pub rewrite: Option<RewriteConfig>,
}

fn default_permission() -> String {
    "ask".to_string()
}

fn default_mysql_aliases() -> Vec<String> {
    vec!["mysql".to_string(), "mariadb".to_string()]
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

impl Config {
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

        toml::from_str(&content).map_err(|e| format!("Failed to parse config: {}", e))
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

    /// Get wrapper config by command name
    pub fn get_wrapper(&self, name: &str) -> Option<&WrapperConfig> {
        self.wrappers.iter().find(|w| w.command == name)
    }

    /// Check if a directory is allowed for git push to master/main
    pub fn is_master_push_allowed(&self, cwd: Option<&str>) -> bool {
        let Some(cwd) = cwd else {
            return false;
        };

        // Canonicalize cwd for comparison
        let cwd_path = std::path::Path::new(cwd);
        let cwd_canonical = cwd_path
            .canonicalize()
            .unwrap_or_else(|_| cwd_path.to_path_buf());
        let cwd_str = cwd_canonical.to_string_lossy();

        for allowed in &self.master_push_allowed {
            // Expand ~ to home directory
            let expanded = if allowed.starts_with("~/") {
                if let Ok(home) = std::env::var("HOME") {
                    format!("{}{}", home, &allowed[1..])
                } else {
                    allowed.clone()
                }
            } else {
                allowed.clone()
            };

            // Canonicalize allowed path
            let allowed_path = std::path::Path::new(&expanded);
            let allowed_canonical = allowed_path
                .canonicalize()
                .unwrap_or_else(|_| allowed_path.to_path_buf());
            let allowed_str = allowed_canonical.to_string_lossy();

            // Check exact match or subdirectory
            if cwd_str == allowed_str {
                return true;
            }
            let prefix = if allowed_str.ends_with('/') {
                allowed_str.to_string()
            } else {
                format!("{}/", allowed_str)
            };
            if cwd_str.starts_with(&prefix) {
                return true;
            }
        }

        false
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
        let home = std::env::var("HOME").unwrap_or_default();
        for pattern in &self.main_thread_write_allow {
            let expanded = if pattern.starts_with("~/") {
                format!("{}{}", home, &pattern[1..])
            } else {
                pattern.clone()
            };
            // Exact match
            if path == expanded {
                return true;
            }
            // Simple glob: "dir/*" matches any direct child of dir
            if let Some(prefix) = expanded.strip_suffix("/*") {
                if path.starts_with(prefix)
                    && path.len() > prefix.len()
                    && path.as_bytes()[prefix.len()] == b'/'
                {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for Config {
    fn default() -> Self {
        // Use embedded default config
        toml::from_str(DEFAULT_CONFIG).expect("Embedded default config is invalid")
    }
}
