//! Configuration loading and rule matching

use serde::Deserialize;
use std::path::Path;

/// Embedded default configuration
const DEFAULT_CONFIG: &str = include_str!("../../config.default.toml");

mod matching;
#[cfg(test)]
mod tests;

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

/// Main configuration structure
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Default permission for unmatched commands
    #[serde(default = "default_permission")]
    pub default: String,

    /// Enable AI-powered advice for permission decisions
    #[serde(default)]
    pub enable_advice: bool,

    /// Directories where git push to master/main is allowed
    #[serde(default)]
    pub master_push_allowed: Vec<String>,

    /// MySQL/MariaDB command aliases (for SQL query analysis)
    #[serde(default = "default_mysql_aliases")]
    pub mysql_aliases: Vec<String>,

    /// Command rules
    #[serde(default)]
    pub rules: Vec<Rule>,

    /// Wrapper configurations
    #[serde(default)]
    pub wrappers: Vec<WrapperConfig>,

    /// Command suggestions
    #[serde(default)]
    pub suggestions: Vec<Suggestion>,
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
    /// Get the effective permission string, considering edit mode
    pub fn effective_permission(&self, edit_mode: bool) -> &str {
        if edit_mode {
            if let Some(ref p) = self.edit_mode_permission {
                return p;
            }
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

impl Config {
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
}

impl Default for Config {
    fn default() -> Self {
        // Use embedded default config
        toml::from_str(DEFAULT_CONFIG).expect("Embedded default config is invalid")
    }
}
