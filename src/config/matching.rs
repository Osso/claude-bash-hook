//! Pattern matching and rule checking logic

use glob_match::glob_match;

use super::{Config, ExecContext, Permission, PermissionResult};

impl Config {
    /// Check a command against rules with an optional cwd override
    pub fn check_command_with_cwd(
        &self,
        name: &str,
        args: &[String],
        cwd: Option<&str>,
        ctx: ExecContext,
    ) -> PermissionResult {
        // First check for suggestions
        let suggestion = self.find_suggestion(name, args);

        // Then match against rules
        for rule in &self.rules {
            if let Some(result) =
                self.match_rule_with_cwd(rule, name, args, cwd, suggestion.clone(), ctx)
            {
                return result;
            }
        }

        // Determine default permission based on context
        let (default_perm, reason, suggestion) = self.resolve_default(ctx, suggestion);

        PermissionResult {
            permission: self.parse_permission(default_perm),
            reason,
            suggestion,
        }
    }

    /// Check a command with host information
    pub fn check_command_with_host(
        &self,
        name: &str,
        args: &[String],
        host: Option<&str>,
        ctx: ExecContext,
    ) -> PermissionResult {
        let suggestion = self.find_suggestion(name, args);

        for rule in &self.rules {
            if let Some(result) =
                self.match_rule_with_host(rule, name, args, host, suggestion.clone(), ctx)
            {
                return result;
            }
        }

        let (default_perm, reason, suggestion) = self.resolve_default(ctx, suggestion);

        PermissionResult {
            permission: self.parse_permission(default_perm),
            reason,
            suggestion,
        }
    }

    /// Resolve default permission, reason, and suggestion based on context
    fn resolve_default<'a>(
        &'a self,
        ctx: ExecContext,
        suggestion: Option<String>,
    ) -> (&'a str, String, Option<String>) {
        if ctx.is_subagent {
            let perm = self.subagent_default.as_deref().unwrap_or(&self.default);
            (perm, "No matching rule".to_string(), suggestion)
        } else if let Some(ref mtd) = self.main_thread_default {
            (
                mtd.as_str(),
                "main thread bash disabled".to_string(),
                Some("Use Task() to delegate bash commands to subagents".to_string()),
            )
        } else {
            (&self.default, "No matching rule".to_string(), suggestion)
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
        ctx: ExecContext,
    ) -> Option<PermissionResult> {
        let main_thread_overriding = self.rule_main_thread_override(rule, ctx);
        let effective_perm = self.effective_rule_permission(rule, ctx);

        for pattern in &rule.commands {
            if self.rule_matches_with_cwd(rule, pattern, name, args, cwd) {
                return Some(self.rule_match_result(
                    rule,
                    effective_perm,
                    suggestion,
                    main_thread_overriding,
                ));
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
        let Some(cwd) = cwd else {
            return false;
        };
        if !self.matches_cwd(rule_cwd, Some(cwd)) {
            return false;
        }

        let pattern_parts = self.pattern_parts(pattern);
        let Some(pattern_cmd) = pattern_parts.first().copied() else {
            return false;
        };

        if !pattern_cmd.contains('/') && !name.contains('/') {
            return self.matches_pattern(pattern, name, args, rule_opts);
        }

        let name_normalized = name.strip_prefix("./").unwrap_or(name);
        let pattern_cmd_normalized = pattern_cmd.strip_prefix("./").unwrap_or(pattern_cmd);
        let cwd_canonical = self.canonical_path(cwd);
        let rule_cwd_canonical = self.canonical_path(self.strip_cwd_glob(rule_cwd));
        let cmd_absolute = self.resolve_command_path(name_normalized, &cwd_canonical);
        let pattern_absolute =
            self.resolve_command_path(pattern_cmd_normalized, &rule_cwd_canonical);
        if cmd_absolute != pattern_absolute {
            return false;
        }

        pattern_parts.len() == 1 || self.matches_pattern(pattern, name_normalized, args, rule_opts)
    }

    /// Check if current working directory matches the pattern
    fn matches_cwd(&self, pattern: &str, cwd_override: Option<&str>) -> bool {
        let Some(cwd_str) = self.current_or_override_cwd(cwd_override) else {
            return false;
        };
        let expanded = self.canonical_path(&self.expand_home(pattern));
        let base_path = self.strip_cwd_glob(&expanded);
        cwd_str == base_path || cwd_str.starts_with(&self.path_prefix(base_path))
    }

    /// Match a rule with host checking
    fn match_rule_with_host(
        &self,
        rule: &super::Rule,
        name: &str,
        args: &[String],
        host: Option<&str>,
        suggestion: Option<String>,
        ctx: ExecContext,
    ) -> Option<PermissionResult> {
        let main_thread_overriding = self.rule_main_thread_override(rule, ctx);
        let effective_perm = self.effective_rule_permission(rule, ctx);

        for pattern in &rule.commands {
            if !self.rule_matches_host_pattern(rule, pattern, name, args) {
                continue;
            }
            if main_thread_overriding {
                return Some(self.main_thread_override_result(effective_perm));
            }
            if effective_perm == "check_host" {
                return Some(self.host_checked_result(rule, host, suggestion));
            }
            return Some(self.rule_match_result(rule, effective_perm, suggestion, false));
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
        if self.matches_pattern(pattern, name, args, rule_opts) {
            return true;
        }

        let Some(relative) = self.relative_name_from_cwd(name, pattern, cwd) else {
            return false;
        };
        self.matches_pattern(pattern, &relative, args, rule_opts)
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
        let default_flags = self.default_subcommand_flags(cmd_name);
        let mut subcommands = Vec::new();
        let mut skip_next = false;

        for arg in args {
            if skip_next {
                skip_next = false;
                continue;
            }

            if arg.starts_with('-') {
                let Some(flag) = self.subcommand_flag(arg) else {
                    continue;
                };
                if rule_opts.iter().any(|opt| opt == flag) || default_flags.contains(&flag) {
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

    fn rule_main_thread_override(&self, rule: &super::Rule, ctx: ExecContext) -> bool {
        !ctx.is_subagent
            && self.main_thread_default.is_some()
            && rule.main_thread_permission.is_none()
    }

    fn effective_rule_permission<'a>(&'a self, rule: &'a super::Rule, ctx: ExecContext) -> &'a str {
        if !ctx.is_subagent && self.main_thread_default.is_some() {
            rule.main_thread_permission
                .as_deref()
                .unwrap_or(self.main_thread_default.as_deref().unwrap())
        } else {
            rule.effective_permission(ctx)
        }
    }

    fn rule_matches_with_cwd(
        &self,
        rule: &super::Rule,
        pattern: &str,
        name: &str,
        args: &[String],
        cwd: Option<&str>,
    ) -> bool {
        if let Some(rule_cwd) = rule.cwd.as_deref() {
            return self.matches_pattern_with_path_resolution(
                pattern,
                name,
                args,
                cwd,
                rule_cwd,
                &rule.opts_with_args,
            );
        }

        self.matches_pattern_with_cwd(pattern, name, args, cwd, &rule.opts_with_args)
    }

    fn rule_match_result(
        &self,
        rule: &super::Rule,
        effective_perm: &str,
        suggestion: Option<String>,
        main_thread_overriding: bool,
    ) -> PermissionResult {
        if main_thread_overriding {
            return self.main_thread_override_result(effective_perm);
        }

        PermissionResult {
            permission: self.parse_permission(effective_perm),
            reason: rule.reason.clone(),
            suggestion,
        }
    }

    fn main_thread_override_result(&self, effective_perm: &str) -> PermissionResult {
        PermissionResult {
            permission: self.parse_permission(effective_perm),
            reason: "main thread bash disabled".to_string(),
            suggestion: Some("Use Task() to delegate bash commands to subagents".to_string()),
        }
    }

    fn pattern_parts<'a>(&self, pattern: &'a str) -> Vec<&'a str> {
        pattern.split_whitespace().collect()
    }

    fn strip_cwd_glob<'a>(&self, path: &'a str) -> &'a str {
        path.strip_suffix("/**")
            .or_else(|| path.strip_suffix("/*"))
            .unwrap_or(path)
    }

    fn canonical_path(&self, path: &str) -> String {
        std::path::Path::new(path)
            .canonicalize()
            .map(|resolved| resolved.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string())
    }

    fn resolve_command_path(&self, name: &str, cwd: &str) -> String {
        if name.starts_with('/') {
            name.to_string()
        } else {
            format!("{}/{}", cwd.trim_end_matches('/'), name)
        }
    }

    fn current_or_override_cwd(&self, cwd_override: Option<&str>) -> Option<String> {
        cwd_override
            .map(|cwd| self.canonical_path(cwd))
            .or_else(|| {
                let cwd = std::env::current_dir().ok()?;
                cwd.to_str().map(|path| self.canonical_path(path))
            })
    }

    fn expand_home(&self, pattern: &str) -> String {
        if !pattern.starts_with("~/") {
            return pattern.to_string();
        }

        std::env::var("HOME")
            .map(|home| format!("{}{}", home, &pattern[1..]))
            .unwrap_or_else(|_| pattern.to_string())
    }

    fn path_prefix(&self, path: &str) -> String {
        if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        }
    }

    fn rule_matches_host_pattern(
        &self,
        rule: &super::Rule,
        pattern: &str,
        name: &str,
        args: &[String],
    ) -> bool {
        self.matches_pattern(pattern, name, args, &rule.opts_with_args)
            && rule
                .cwd
                .as_deref()
                .is_none_or(|cwd_pattern| self.matches_cwd(cwd_pattern, None))
    }

    fn host_checked_result(
        &self,
        rule: &super::Rule,
        host: Option<&str>,
        suggestion: Option<String>,
    ) -> PermissionResult {
        let Some(host) = host else {
            return PermissionResult {
                permission: Permission::Ask,
                reason: format!("{} (unknown host)", rule.reason),
                suggestion,
            };
        };

        for host_rule in &rule.host_rules {
            if glob_match(&host_rule.pattern, host) {
                return PermissionResult {
                    permission: self.parse_permission(&host_rule.permission),
                    reason: format!("{} (host: {})", rule.reason, host),
                    suggestion,
                };
            }
        }

        PermissionResult {
            permission: Permission::Ask,
            reason: format!("{} (unknown host)", rule.reason),
            suggestion,
        }
    }

    fn relative_name_from_cwd(
        &self,
        name: &str,
        pattern: &str,
        cwd: Option<&str>,
    ) -> Option<String> {
        let cwd = cwd?;
        if !name.starts_with('/') || pattern.starts_with('/') {
            return None;
        }
        let relative = name.strip_prefix(&self.path_prefix(cwd))?;
        Some(relative.to_string())
    }

    fn default_subcommand_flags(&self, cmd_name: &str) -> &[&str] {
        match cmd_name {
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
        }
    }

    fn subcommand_flag<'a>(&self, arg: &'a str) -> Option<&'a str> {
        if arg.contains('=') { None } else { Some(arg) }
    }
}
