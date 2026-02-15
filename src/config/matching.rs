//! Pattern matching and rule checking logic

use glob_match::glob_match;

use super::{Config, Permission, PermissionResult};

impl Config {
    /// Check a command against rules with an optional cwd override
    pub fn check_command_with_cwd(
        &self,
        name: &str,
        args: &[String],
        cwd: Option<&str>,
        edit_mode: bool,
    ) -> PermissionResult {
        // First check for suggestions
        let suggestion = self.find_suggestion(name, args);

        // Then match against rules
        for rule in &self.rules {
            if let Some(result) =
                self.match_rule_with_cwd(rule, name, args, cwd, suggestion.clone(), edit_mode)
            {
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
        edit_mode: bool,
    ) -> PermissionResult {
        let suggestion = self.find_suggestion(name, args);

        for rule in &self.rules {
            if let Some(result) =
                self.match_rule_with_host(rule, name, args, host, suggestion.clone(), edit_mode)
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

    /// Match a single rule with optional cwd override
    fn match_rule_with_cwd(
        &self,
        rule: &super::Rule,
        name: &str,
        args: &[String],
        cwd: Option<&str>,
        suggestion: Option<String>,
        edit_mode: bool,
    ) -> Option<PermissionResult> {
        let effective_perm = rule.effective_permission(edit_mode);

        for pattern in &rule.commands {
            // If rule has cwd constraint, do path-resolved matching
            if let Some(ref rule_cwd) = rule.cwd {
                if self.matches_pattern_with_path_resolution(
                    pattern,
                    name,
                    args,
                    cwd,
                    rule_cwd,
                    &rule.opts_with_args,
                ) {
                    return Some(PermissionResult {
                        permission: self.parse_permission(effective_perm),
                        reason: rule.reason.clone(),
                        suggestion,
                    });
                }
            } else {
                // No cwd constraint - use simple pattern matching
                if self.matches_pattern_with_cwd(pattern, name, args, cwd, &rule.opts_with_args) {
                    return Some(PermissionResult {
                        permission: self.parse_permission(effective_perm),
                        reason: rule.reason.clone(),
                        suggestion,
                    });
                }
            }
        }
        None
    }

    /// Match pattern with path resolution for cwd-constrained rules
    /// Resolves: cwd + cmd == rule_cwd + pattern
    fn matches_pattern_with_path_resolution(
        &self,
        pattern: &str,
        name: &str,
        args: &[String],
        cwd: Option<&str>,
        rule_cwd: &str,
        rule_opts: &[String],
    ) -> bool {
        let cwd = match cwd {
            Some(c) => c,
            None => return false,
        };

        // Check if cwd is under rule_cwd (required for cwd-constrained rules)
        if !self.matches_cwd(rule_cwd, Some(cwd)) {
            return false;
        }

        // Extract command part from pattern (first word)
        let pattern_parts: Vec<&str> = pattern.split_whitespace().collect();
        if pattern_parts.is_empty() {
            return false;
        }
        let pattern_cmd = pattern_parts[0];

        // If pattern is a bare command (no path separators) and the command is also bare,
        // skip path resolution. This handles global commands on PATH (e.g., "browser-cli")
        // where cwd only restricts WHERE the command can be used, not WHERE the binary lives.
        // Local scripts like "run-tests.sh" run from the project root, so when cwd differs
        // from rule_cwd, path resolution correctly rejects them.
        if !pattern_cmd.contains('/') && !name.contains('/') {
            return self.matches_pattern(pattern, name, args, rule_opts);
        }

        // Strip glob suffixes from rule_cwd for path resolution
        let rule_cwd_base = rule_cwd
            .strip_suffix("/**")
            .or_else(|| rule_cwd.strip_suffix("/*"))
            .unwrap_or(rule_cwd);

        // Canonicalize paths to resolve symlinks
        let rule_cwd_canonical = std::path::Path::new(rule_cwd_base)
            .canonicalize()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| rule_cwd_base.to_string());
        let cwd_canonical = std::path::Path::new(cwd)
            .canonicalize()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| cwd.to_string());

        // Normalize command name (strip ./)
        let name_normalized = name.strip_prefix("./").unwrap_or(name);
        let pattern_cmd_normalized = pattern_cmd.strip_prefix("./").unwrap_or(pattern_cmd);

        // Resolve absolute paths using canonical paths
        let cmd_absolute = if name_normalized.starts_with('/') {
            name_normalized.to_string()
        } else {
            format!(
                "{}/{}",
                cwd_canonical.trim_end_matches('/'),
                name_normalized
            )
        };

        let pattern_absolute = if pattern_cmd_normalized.starts_with('/') {
            pattern_cmd_normalized.to_string()
        } else {
            format!(
                "{}/{}",
                rule_cwd_canonical.trim_end_matches('/'),
                pattern_cmd_normalized
            )
        };

        // Compare resolved paths
        if cmd_absolute != pattern_absolute {
            return false;
        }

        // If pattern has subcommands/flags, check those too
        if pattern_parts.len() > 1 {
            self.matches_pattern(pattern, name_normalized, args, rule_opts)
        } else {
            true
        }
    }

    /// Check if current working directory matches the pattern
    fn matches_cwd(&self, pattern: &str, cwd_override: Option<&str>) -> bool {
        let cwd_str = if let Some(override_cwd) = cwd_override {
            // Use the provided cwd override, canonicalizing it
            let path = std::path::Path::new(override_cwd);
            let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
            canonical.to_string_lossy().to_string()
        } else {
            // Fall back to actual current directory
            let Ok(cwd) = std::env::current_dir() else {
                return false;
            };
            let cwd = cwd.canonicalize().unwrap_or(cwd);
            let Some(s) = cwd.to_str() else {
                return false;
            };
            s.to_string()
        };

        // Expand ~ to home directory in pattern
        let expanded = if pattern.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                format!("{}{}", home, &pattern[1..])
            } else {
                pattern.to_string()
            }
        } else {
            pattern.to_string()
        };
        // Resolve symlinks in pattern path too
        let expanded = std::path::Path::new(&expanded)
            .canonicalize()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or(expanded);

        // Strip trailing /** or /* for prefix matching
        let base_path = expanded
            .strip_suffix("/**")
            .or_else(|| expanded.strip_suffix("/*"))
            .unwrap_or(&expanded);

        // Use prefix matching: cwd must equal pattern or be under it
        if cwd_str == base_path {
            return true;
        }
        let prefix = if base_path.ends_with('/') {
            base_path.to_string()
        } else {
            format!("{}/", base_path)
        };
        cwd_str.starts_with(&prefix)
    }

    /// Match a rule with host checking
    fn match_rule_with_host(
        &self,
        rule: &super::Rule,
        name: &str,
        args: &[String],
        host: Option<&str>,
        suggestion: Option<String>,
        edit_mode: bool,
    ) -> Option<PermissionResult> {
        for pattern in &rule.commands {
            if self.matches_pattern(pattern, name, args, &rule.opts_with_args) {
                // Check cwd constraint if present
                if let Some(ref cwd_pattern) = rule.cwd {
                    if !self.matches_cwd(cwd_pattern, None) {
                        continue;
                    }
                }

                let effective_perm = rule.effective_permission(edit_mode);

                // Check if this is a host-checking rule
                if effective_perm == "check_host" {
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
                    permission: self.parse_permission(effective_perm),
                    reason: rule.reason.clone(),
                    suggestion,
                });
            }
        }
        None
    }

    /// Check if a command matches a pattern, also trying relative to cwd
    fn matches_pattern_with_cwd(
        &self,
        pattern: &str,
        name: &str,
        args: &[String],
        cwd: Option<&str>,
        rule_opts: &[String],
    ) -> bool {
        // Try direct match first
        if self.matches_pattern(pattern, name, args, rule_opts) {
            return true;
        }

        // If command is absolute and pattern is relative, try matching relative to cwd
        if let Some(cwd) = cwd {
            if name.starts_with('/') && !pattern.starts_with('/') {
                let cwd_with_slash = if cwd.ends_with('/') {
                    cwd.to_string()
                } else {
                    format!("{}/", cwd)
                };
                if let Some(relative) = name.strip_prefix(&cwd_with_slash) {
                    if self.matches_pattern(pattern, relative, args, rule_opts) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if a command matches a pattern
    /// Pattern can be:
    /// - "ls" - just the command name
    /// - "git status" - command with subcommand
    /// - "rm -rf" - command with specific flag
    fn matches_pattern(
        &self,
        pattern: &str,
        name: &str,
        args: &[String],
        rule_opts: &[String],
    ) -> bool {
        let parts: Vec<&str> = pattern.split_whitespace().collect();

        if parts.is_empty() {
            return false;
        }

        // Normalize: strip leading "./" from both pattern and command
        let pattern_cmd = parts[0].strip_prefix("./").unwrap_or(parts[0]);
        let normalized_name = name.strip_prefix("./").unwrap_or(name);

        // Normalize command name to basename (e.g., /usr/bin/ls -> ls)
        let cmd_basename = normalized_name
            .rsplit('/')
            .next()
            .unwrap_or(normalized_name);

        // First part must match command name (or its basename)
        if pattern_cmd != normalized_name && pattern_cmd != cmd_basename {
            return false;
        }

        if parts.len() == 1 {
            // Just matching the command name
            return true;
        }

        // Check remaining parts against args
        // Collect all non-flag args (subcommands)
        let subcommands = self.find_subcommands(name, args, rule_opts);
        let mut subcommand_idx = 0;

        for part in &parts[1..] {
            if part.starts_with('-') {
                // This is a flag - check if it's in args
                if !self.has_flag(args, part) {
                    return false;
                }
            } else {
                // This is a subcommand - check against next subcommand in sequence
                if subcommand_idx >= subcommands.len() || subcommands[subcommand_idx] != *part {
                    return false;
                }
                subcommand_idx += 1;
            }
        }

        true
    }

    /// Find all subcommands (positional args), skipping flags and their arguments
    fn find_subcommands(
        &self,
        cmd_name: &str,
        args: &[String],
        rule_opts: &[String],
    ) -> Vec<String> {
        // Flags that take an argument for common commands (hardcoded defaults)
        let default_flags: &[&str] = match cmd_name {
            "git" => &["-C", "-c", "--git-dir", "--work-tree", "--namespace"],
            "docker" => &[
                "-H",
                "--host",
                "--config",
                "--context",
                "-c",
                "-l",
                "--log-level",
            ],
            "kubectl" => &[
                "-n",
                "--namespace",
                "--context",
                "--cluster",
                "-s",
                "--server",
            ],
            "sentry" => &["-s", "--slug"],
            _ => &[],
        };

        let mut subcommands = Vec::new();
        let mut skip_next = false;

        for arg in args {
            if skip_next {
                skip_next = false;
                continue;
            }

            if arg.starts_with('-') {
                let flag = if arg.contains('=') {
                    continue;
                } else {
                    arg.as_str()
                };

                // Check rule-specific opts first, then hardcoded defaults
                if rule_opts.iter().any(|o| o == flag) || default_flags.contains(&flag) {
                    skip_next = true;
                }
                continue;
            }

            subcommands.push(arg.clone());
        }

        subcommands
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
    pub(crate) fn parse_permission(&self, s: &str) -> Permission {
        match s.to_lowercase().as_str() {
            "allow" => Permission::Allow,
            "ask" => Permission::Ask,
            "deny" => Permission::Deny,
            _ => Permission::Passthrough,
        }
    }
}
