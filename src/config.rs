//! Configuration loading and rule matching

use glob_match::glob_match;
use serde::Deserialize;
use std::path::Path;

/// Permission levels (ordered by restrictiveness)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    Allow = 0,
    Ask = 1,
    Deny = 2,
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

/// A permission rule
#[derive(Debug, Deserialize)]
pub struct Rule {
    /// Commands this rule matches (e.g., ["ls", "cat", "git status"])
    pub commands: Vec<String>,

    /// Permission: "allow", "ask", "deny", or "check_host"
    pub permission: String,

    /// Reason for this rule
    #[serde(default)]
    pub reason: String,

    /// Host rules for check_host permission
    #[serde(default)]
    pub host_rules: Vec<HostRule>,
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
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config: {}", e))?;

        toml::from_str(&content).map_err(|e| format!("Failed to parse config: {}", e))
    }

    /// Load from default location or return default config
    pub fn load_or_default() -> Self {
        let home = std::env::var("HOME").unwrap_or_default();
        let config_path = Path::new(&home).join(".config/claude-bash-hook/config.toml");

        if config_path.exists() {
            match Self::load(&config_path) {
                Ok(config) => return config,
                Err(e) => eprintln!("Warning: {}", e),
            }
        }

        Self::default()
    }

    /// Get wrapper config by command name
    pub fn get_wrapper(&self, name: &str) -> Option<&WrapperConfig> {
        self.wrappers.iter().find(|w| w.command == name)
    }

    /// Check a command against rules
    pub fn check_command(&self, name: &str, args: &[String]) -> PermissionResult {
        // First check for suggestions
        let suggestion = self.find_suggestion(name, args);

        // Then match against rules
        for rule in &self.rules {
            if let Some(result) = self.match_rule(rule, name, args, suggestion.clone()) {
                return result;
            }
        }

        // Return default
        PermissionResult {
            permission: self.parse_permission(&self.default),
            reason: "No matching rule".to_string(),
            suggestion,
        }
    }

    /// Check a command with host information
    pub fn check_command_with_host(
        &self,
        name: &str,
        args: &[String],
        host: Option<&str>,
    ) -> PermissionResult {
        let suggestion = self.find_suggestion(name, args);

        for rule in &self.rules {
            if let Some(result) = self.match_rule_with_host(rule, name, args, host, suggestion.clone())
            {
                return result;
            }
        }

        PermissionResult {
            permission: self.parse_permission(&self.default),
            reason: "No matching rule".to_string(),
            suggestion,
        }
    }

    /// Match a single rule
    fn match_rule(
        &self,
        rule: &Rule,
        name: &str,
        args: &[String],
        suggestion: Option<String>,
    ) -> Option<PermissionResult> {
        for pattern in &rule.commands {
            if self.matches_pattern(pattern, name, args) {
                return Some(PermissionResult {
                    permission: self.parse_permission(&rule.permission),
                    reason: rule.reason.clone(),
                    suggestion,
                });
            }
        }
        None
    }

    /// Match a rule with host checking
    fn match_rule_with_host(
        &self,
        rule: &Rule,
        name: &str,
        args: &[String],
        host: Option<&str>,
        suggestion: Option<String>,
    ) -> Option<PermissionResult> {
        for pattern in &rule.commands {
            if self.matches_pattern(pattern, name, args) {
                // Check if this is a host-checking rule
                if rule.permission == "check_host" {
                    if let Some(h) = host {
                        // Match against host rules
                        for host_rule in &rule.host_rules {
                            if glob_match(&host_rule.pattern, h) {
                                return Some(PermissionResult {
                                    permission: self.parse_permission(&host_rule.permission),
                                    reason: format!("{} (host: {})", rule.reason, h),
                                    suggestion,
                                });
                            }
                        }
                    }
                    // No host or no matching host rule - use ask as default
                    return Some(PermissionResult {
                        permission: Permission::Ask,
                        reason: format!("{} (unknown host)", rule.reason),
                        suggestion,
                    });
                }

                return Some(PermissionResult {
                    permission: self.parse_permission(&rule.permission),
                    reason: rule.reason.clone(),
                    suggestion,
                });
            }
        }
        None
    }

    /// Check if a command matches a pattern
    /// Pattern can be:
    /// - "ls" - just the command name
    /// - "git status" - command with subcommand
    /// - "rm -rf" - command with specific flag
    fn matches_pattern(&self, pattern: &str, name: &str, args: &[String]) -> bool {
        let parts: Vec<&str> = pattern.split_whitespace().collect();

        if parts.is_empty() {
            return false;
        }

        // First part must match command name
        if parts[0] != name {
            return false;
        }

        if parts.len() == 1 {
            // Just matching the command name
            return true;
        }

        // Check remaining parts against args
        for part in &parts[1..] {
            if part.starts_with('-') {
                // This is a flag - check if it's in args
                if !self.has_flag(args, part) {
                    return false;
                }
            } else {
                // This is a subcommand - find first non-flag arg, skipping flag arguments
                let subcommand = self.find_subcommand(name, args);
                if subcommand.as_deref() != Some(*part) {
                    return false;
                }
            }
        }

        true
    }

    /// Find the subcommand (first positional arg), skipping flags and their arguments
    fn find_subcommand(&self, cmd_name: &str, args: &[String]) -> Option<String> {
        // Flags that take an argument for common commands
        let flags_with_args: &[&str] = match cmd_name {
            "git" => &["-C", "-c", "--git-dir", "--work-tree", "-C", "--namespace"],
            "docker" => &["-H", "--host", "--config", "--context", "-c", "-l", "--log-level"],
            "kubectl" => &["-n", "--namespace", "--context", "--cluster", "-s", "--server"],
            _ => &[],
        };

        let mut skip_next = false;
        for arg in args {
            if skip_next {
                skip_next = false;
                continue;
            }

            if arg.starts_with('-') {
                // Check if this flag takes an argument
                let flag = if arg.contains('=') {
                    // --flag=value format, no need to skip next
                    continue;
                } else {
                    arg.as_str()
                };

                if flags_with_args.contains(&flag) {
                    skip_next = true;
                }
                continue;
            }

            // Found a positional argument - this is the subcommand
            return Some(arg.clone());
        }

        None
    }

    /// Check if a flag is present in args
    /// Handles combined flags like -rf matching -r and -f
    fn has_flag(&self, args: &[String], flag: &str) -> bool {
        let flag_char = flag.trim_start_matches('-');

        // Handle long flags (--force)
        if flag.starts_with("--") {
            return args.iter().any(|a| a == flag);
        }

        // Handle short flags (-f)
        // Check exact match first
        if args.iter().any(|a| a == flag) {
            return true;
        }

        // Check combined flags (-rf contains -r and -f)
        if flag_char.len() == 1 {
            let c = flag_char.chars().next().unwrap();
            return args.iter().any(|a| {
                if a.starts_with('-') && !a.starts_with("--") {
                    a.chars().skip(1).any(|ac| ac == c)
                } else {
                    false
                }
            });
        }

        false
    }

    /// Find a suggestion for a command
    fn find_suggestion(&self, name: &str, args: &[String]) -> Option<String> {
        let full_cmd = format!("{} {}", name, args.join(" "));

        for sugg in &self.suggestions {
            // Check command prefix
            if !full_cmd.starts_with(&sugg.command) && name != sugg.command {
                continue;
            }

            // If there's a pattern, check it
            if let Some(ref pattern) = sugg.pattern {
                // Simple glob matching on the pattern
                if !glob_match(pattern, &full_cmd) {
                    continue;
                }
            }

            return Some(sugg.message.clone());
        }

        None
    }

    /// Parse permission string to enum
    fn parse_permission(&self, s: &str) -> Permission {
        match s.to_lowercase().as_str() {
            "allow" => Permission::Allow,
            "deny" => Permission::Deny,
            _ => Permission::Ask,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        // Minimal default - ask for everything if no config file
        Config {
            default: "ask".to_string(),
            rules: vec![],
            wrappers: vec![],
            suggestions: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn test_config() -> Config {
        Config::load(Path::new("config.example.toml")).expect("Failed to load test config")
    }

    #[test]
    fn test_simple_match() {
        let config = test_config();
        let result = config.check_command("ls", &["-la".into()]);
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_subcommand_match() {
        let config = test_config();
        let result = config.check_command("git", &["status".into()]);
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_flag_match() {
        let config = test_config();
        let result = config.check_command("rm", &["-rf".into(), "/tmp/foo".into()]);
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_combined_flags() {
        let config = test_config();
        // rm -rf should match "rm -r" rule
        let result = config.check_command("rm", &["-rf".into(), "/tmp".into()]);
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_suggestion() {
        let config = test_config();
        let result = config.check_command("git", &["checkout".into(), "main".into()]);
        assert!(result.suggestion.is_some());
        assert!(result.suggestion.unwrap().contains("git switch"));
    }

    #[test]
    fn test_unknown_command() {
        let config = test_config();
        let result = config.check_command("unknown_cmd", &[]);
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_git_with_path_flag() {
        let config = test_config();
        // git -C path describe should match "git describe" rule
        let result = config.check_command(
            "git",
            &["-C".into(), "~/Projects/sentry".into(), "describe".into()],
        );
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_kubectl_with_namespace() {
        let config = test_config();
        // kubectl -n namespace get pods should match "kubectl get"
        let result = config.check_command(
            "kubectl",
            &["-n".into(), "prod".into(), "get".into(), "pods".into()],
        );
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_default_config_asks() {
        let config = Config::default();
        let result = config.check_command("ls", &[]);
        assert_eq!(result.permission, Permission::Ask);
    }
}
