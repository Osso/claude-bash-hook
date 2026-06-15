//! sed program analysis via a real parser.
//!
//! sed can write files (`w file`, `W file`, and the `s///w file` flag) and, on
//! GNU sed, execute shell commands (`e [cmd]`, `s///e`). A regex can't reliably
//! find these because `w`/`e` also appear inside regexes, replacements, `y///`
//! transliterations, addresses, and `a`/`i`/`c` text — all with arbitrary `s`/`y`
//! delimiters and bracket expressions. So we tokenize the script properly.
//!
//! `w`/`s///w` write targets are checked against the protected paths (only those
//! prompt); `e`/`s///e` always prompt (shell execution). `r`/`R` read files and
//! are ignored. A script from `-f file` can't be inspected, so we return `None`
//! (falling through to a prompt). `sed -i` is denied upstream as an in-place edit.

use crate::analyzer::Command;
use crate::config::{Config, Permission, PermissionResult};
use std::path::Path;

/// A side effect found in a sed script.
#[derive(Debug, PartialEq)]
enum Effect {
    /// `w file`, `W file`, or `s///w file` — write to a path.
    Write(String),
    /// `e [cmd]` or `s///e` — execute a shell command.
    Exec,
}

/// Check whether a sed command runs a side-effecting program.
pub fn check_sed_script(
    cmd: &Command,
    config: &Config,
    virtual_cwd: Option<&str>,
) -> Option<PermissionResult> {
    if cmd.name != "sed" {
        return None;
    }
    let script = extract_sed_script(cmd)?;
    let effects = parse_sed_effects(&script);

    for effect in &effects {
        if *effect == Effect::Exec {
            return Some(ask("sed e command executes a shell command"));
        }
    }
    for effect in &effects {
        if let Effect::Write(name) = effect {
            if let Some(abs) = absolute_path(name, virtual_cwd) {
                if config.is_write_protected(&abs) {
                    return Some(ask(&format!("sed writes to protected path {}", abs)));
                }
            }
        }
    }

    Some(PermissionResult {
        permission: Permission::Allow,
        reason: "read-only sed script".to_string(),
        suggestion: None,
    })
}

fn ask(reason: &str) -> PermissionResult {
    PermissionResult {
        permission: Permission::Ask,
        reason: reason.to_string(),
        suggestion: None,
    }
}

fn absolute_path(path: &str, virtual_cwd: Option<&str>) -> Option<String> {
    if path.is_empty() || path.contains('\0') || path.contains('\n') {
        return None;
    }
    if Path::new(path).is_absolute() {
        return Some(path.to_string());
    }
    virtual_cwd.map(|cwd| format!("{}/{}", cwd.trim_end_matches('/'), path))
}

/// Extract the inline sed script. Returns `None` for `-f file` (unreadable).
fn extract_sed_script(cmd: &Command) -> Option<String> {
    let mut pieces: Vec<String> = Vec::new();
    let mut first_positional: Option<String> = None;

    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-e" | "--expression" => {
                if let Some(s) = iter.next() {
                    pieces.push(s.clone());
                }
            }
            "-f" | "--file" => return None, // external script file
            "-l" | "--line-length" => {
                iter.next();
            }
            _ if arg.starts_with("--expression=") => {
                pieces.push(arg["--expression=".len()..].to_string());
            }
            _ if arg.starts_with("-e") && arg.len() > 2 => {
                pieces.push(arg[2..].to_string()); // glued -escript
            }
            _ if arg.starts_with("--file=") || arg.starts_with("-f") && arg.len() > 2 => {
                return None;
            }
            _ if arg.starts_with('-') && arg != "-" => {} // other flag (-n, -E, -s, -z, ...)
            _ => {
                if first_positional.is_none() {
                    first_positional = Some(arg.clone());
                }
            }
        }
    }

    if pieces.is_empty() {
        pieces.extend(first_positional);
    }
    (!pieces.is_empty()).then(|| {
        pieces
            .iter()
            .map(|p| strip_quotes(p))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

/// Strip one layer of matching surrounding quotes (the bash analyzer keeps the
/// shell quotes in `raw_string`/`string` args).
fn strip_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'\'' || b[0] == b'"') && b[b.len() - 1] == b[0] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Tokenize a sed script and collect its write/exec effects.
fn parse_sed_effects(script: &str) -> Vec<Effect> {
    let chars: Vec<char> = script.chars().collect();
    let mut p = Parser {
        c: &chars,
        i: 0,
        effects: Vec::new(),
    };
    p.run();
    p.effects
}

struct Parser<'a> {
    c: &'a [char],
    i: usize,
    effects: Vec<Effect>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.c.get(self.i).copied();
        if ch.is_some() {
            self.i += 1;
        }
        ch
    }

    fn run(&mut self) {
        while self.i < self.c.len() {
            self.skip_separators();
            if self.peek().is_none() {
                break;
            }
            self.skip_addresses();
            self.skip_blanks();
            self.skip_bangs();
            self.skip_blanks();
            let Some(cmd) = self.bump() else { break };
            self.dispatch(cmd);
        }
    }

    fn skip_separators(&mut self) {
        while let Some(ch) = self.peek() {
            match ch {
                ' ' | '\t' | '\n' | ';' => {
                    self.i += 1;
                }
                '#' => self.skip_to_eol(),
                _ => break,
            }
        }
    }

    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.i += 1;
        }
    }

    fn skip_bangs(&mut self) {
        loop {
            self.skip_blanks();
            if self.peek() == Some('!') {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn skip_to_eol(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == '\n' {
                break;
            }
            self.i += 1;
        }
    }

    /// Read the rest of the current logical line, honoring `\`-newline
    /// continuations, returning the text consumed.
    fn read_to_eol(&mut self) -> String {
        let mut out = String::new();
        while let Some(ch) = self.peek() {
            if ch == '\n' {
                break;
            }
            if ch == '\\' {
                self.i += 1;
                match self.bump() {
                    Some('\n') => out.push('\n'), // line continuation
                    Some(next) => out.push(next),
                    None => break,
                }
                continue;
            }
            out.push(ch);
            self.i += 1;
        }
        out
    }

    fn read_to_separator(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == '\n' || ch == ';' {
                break;
            }
            self.i += 1;
        }
    }

    fn skip_addresses(&mut self) {
        if !self.skip_one_address() {
            return;
        }
        self.skip_blanks();
        if self.peek() == Some(',') {
            self.i += 1;
            self.skip_blanks();
            self.skip_second_address();
        }
    }

    fn skip_one_address(&mut self) -> bool {
        match self.peek() {
            Some('$') => {
                self.i += 1;
                true
            }
            Some(c) if c.is_ascii_digit() => {
                self.skip_digits();
                if self.peek() == Some('~') {
                    self.i += 1;
                    self.skip_digits();
                }
                true
            }
            Some('/') => {
                self.i += 1;
                self.skip_regex('/');
                self.skip_addr_modifiers();
                true
            }
            Some('\\') => {
                self.i += 1;
                if let Some(delim) = self.bump() {
                    self.skip_regex(delim);
                    self.skip_addr_modifiers();
                }
                true
            }
            _ => false,
        }
    }

    fn skip_second_address(&mut self) {
        match self.peek() {
            Some('+') | Some('~') => {
                self.i += 1;
                self.skip_digits();
            }
            _ => {
                self.skip_one_address();
            }
        }
    }

    fn skip_addr_modifiers(&mut self) {
        while matches!(self.peek(), Some('I') | Some('M')) {
            self.i += 1;
        }
    }

    fn skip_digits(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
    }

    /// Skip a delimited regex field (first part of `s`, or an address), honoring
    /// `\`-escapes and `[...]` bracket expressions. Leaves position after delim.
    fn skip_regex(&mut self, delim: char) {
        while let Some(ch) = self.bump() {
            match ch {
                '\\' => {
                    self.bump();
                }
                '[' => self.skip_bracket(),
                c if c == delim => return,
                '\n' => return, // unterminated
                _ => {}
            }
        }
    }

    /// Skip a delimited literal field (replacement, `y` parts): escape-aware,
    /// no bracket expressions.
    fn skip_literal(&mut self, delim: char) {
        while let Some(ch) = self.bump() {
            match ch {
                '\\' => {
                    self.bump();
                }
                c if c == delim => return,
                '\n' => return,
                _ => {}
            }
        }
    }

    fn skip_bracket(&mut self) {
        // Already consumed '['. Optional leading '^' then a literal ']'.
        if self.peek() == Some('^') {
            self.i += 1;
        }
        if self.peek() == Some(']') {
            self.i += 1;
        }
        while let Some(ch) = self.bump() {
            match ch {
                ']' => return,
                '[' if matches!(self.peek(), Some(':') | Some('.') | Some('=')) => {
                    let kind = self.bump().unwrap(); // ':', '.', or '='
                    self.skip_posix_class(kind);
                }
                _ => {}
            }
        }
    }

    fn skip_posix_class(&mut self, kind: char) {
        // Consume until the matching `<kind>]`.
        while let Some(ch) = self.bump() {
            if ch == kind && self.peek() == Some(']') {
                self.i += 1;
                return;
            }
        }
    }

    fn dispatch(&mut self, cmd: char) {
        match cmd {
            '{' | '}' => {}
            's' => self.parse_s(),
            'y' => self.parse_y(),
            'w' | 'W' => {
                self.skip_blanks();
                let name = self.read_to_eol();
                let name = name.trim().to_string();
                if !name.is_empty() {
                    self.effects.push(Effect::Write(name));
                }
            }
            'r' | 'R' => {
                self.read_to_eol(); // read a file — not a write
            }
            'e' => {
                self.read_to_eol();
                self.effects.push(Effect::Exec);
            }
            'a' | 'i' | 'c' => {
                // Text command. Either GNU one-line (`a text`) or classic
                // (`a\` then text on following lines). Consume the text so it
                // isn't reparsed as commands; read_to_eol follows `\`-newline
                // continuations for multi-line text.
                self.skip_blanks();
                if self.peek() == Some('\\') {
                    self.i += 1;
                    if self.peek() == Some('\n') {
                        self.i += 1; // text begins on the next line
                    }
                }
                self.read_to_eol();
            }
            'b' | 't' | 'T' | ':' => self.read_to_separator(), // label
            'l' | 'q' | 'Q' | 'L' => {
                self.skip_blanks();
                self.skip_digits();
            }
            _ => {} // d D g G h H n N p P x z F = and the rest take no argument
        }
    }

    fn parse_s(&mut self) {
        let Some(delim) = self.bump() else { return };
        self.skip_regex(delim); // pattern
        self.skip_literal(delim); // replacement
        self.parse_s_flags();
    }

    fn parse_y(&mut self) {
        let Some(delim) = self.bump() else { return };
        self.skip_literal(delim);
        self.skip_literal(delim);
    }

    fn parse_s_flags(&mut self) {
        loop {
            match self.peek() {
                None | Some(';') | Some('\n') | Some('}') | Some('#') => return,
                Some(c) if c.is_whitespace() => return,
                Some('w') => {
                    self.i += 1;
                    self.skip_blanks();
                    let name = self.read_to_eol().trim().to_string();
                    if !name.is_empty() {
                        self.effects.push(Effect::Write(name));
                    }
                    return;
                }
                Some('e') => {
                    self.i += 1;
                    self.effects.push(Effect::Exec);
                }
                Some(_) => {
                    self.i += 1; // g p i I m M, digits, etc.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "sed".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn cfg(patterns: &[&str]) -> Config {
        let list: Vec<String> = patterns.iter().map(|s| format!("\"{}\"", s)).collect();
        toml::from_str(&format!("ask_write_paths = [{}]", list.join(", "))).expect("config")
    }

    fn perm(args: &[&str], patterns: &[&str]) -> Permission {
        check_sed_script(&make_cmd(args), &cfg(patterns), None)
            .unwrap()
            .permission
    }

    // --- read-only programs stay allowed ---

    #[test]
    fn test_plain_substitution_allowed() {
        assert_eq!(perm(&["s/a/b/"], &["/usr/*"]), Permission::Allow);
    }

    #[test]
    fn test_substitution_with_w_in_pattern_allowed() {
        // 'w' inside the regex/replacement is not a write command.
        assert_eq!(perm(&["s/w/x/g"], &["/usr/*"]), Permission::Allow);
    }

    #[test]
    fn test_replacement_containing_w_path_allowed() {
        // Replacement text mentioning a path is not a write.
        assert_eq!(perm(&["s|a|w /usr/bin/x|"], &["/usr/*"]), Permission::Allow);
    }

    #[test]
    fn test_delete_print_allowed() {
        assert_eq!(perm(&["-n", "/foo/p"], &["/usr/*"]), Permission::Allow);
    }

    #[test]
    fn test_y_transliterate_allowed() {
        assert_eq!(perm(&["y/abc/xyz/"], &["/usr/*"]), Permission::Allow);
    }

    #[test]
    fn test_bracket_with_delimiter_allowed() {
        // '/' inside a bracket expression must not end the regex early.
        assert_eq!(perm(&["s/[/]/_/g"], &["/usr/*"]), Permission::Allow);
    }

    #[test]
    fn test_write_to_unprotected_allowed() {
        assert_eq!(perm(&["w /tmp/out"], &["/usr/*"]), Permission::Allow);
    }

    #[test]
    fn test_read_file_command_allowed() {
        // r reads a file — not a write.
        assert_eq!(perm(&["r /usr/bin/x"], &["/usr/*"]), Permission::Allow);
    }

    // --- writes to protected paths prompt ---

    #[test]
    fn test_w_command_protected_asks() {
        assert_eq!(perm(&["w /usr/bin/x"], &["/usr/*"]), Permission::Ask);
    }

    #[test]
    fn test_capital_w_command_protected_asks() {
        assert_eq!(perm(&["-n", "W /etc/x"], &["/etc/*"]), Permission::Ask);
    }

    #[test]
    fn test_s_w_flag_protected_asks() {
        assert_eq!(perm(&["s/a/b/w /usr/bin/x"], &["/usr/*"]), Permission::Ask);
    }

    #[test]
    fn test_s_w_flag_after_other_flags_asks() {
        assert_eq!(
            perm(&["s/a/b/gpw /etc/passwd"], &["/etc/*"]),
            Permission::Ask
        );
    }

    #[test]
    fn test_w_command_after_address_protected_asks() {
        assert_eq!(perm(&["/foo/w /usr/bin/x"], &["/usr/*"]), Permission::Ask);
    }

    #[test]
    fn test_w_command_in_chain_protected_asks() {
        assert_eq!(
            perm(&["s/a/b/; w /usr/bin/x"], &["/usr/*"]),
            Permission::Ask
        );
    }

    // --- exec always prompts ---

    #[test]
    fn test_e_command_asks() {
        assert_eq!(
            perm(&["1e cat /etc/shadow"], &["/nonexistent/*"]),
            Permission::Ask
        );
    }

    #[test]
    fn test_s_e_flag_asks() {
        assert_eq!(perm(&["s/.*/id/e"], &["/nonexistent/*"]), Permission::Ask);
    }

    // --- extraction edge cases ---

    #[test]
    fn test_dash_e_expression_parsed() {
        assert_eq!(perm(&["-e", "w /usr/bin/x"], &["/usr/*"]), Permission::Ask);
    }

    #[test]
    fn test_program_file_returns_none() {
        let cmd = make_cmd(&["-f", "prog.sed", "data"]);
        assert!(check_sed_script(&cmd, &cfg(&["/usr/*"]), None).is_none());
    }

    #[test]
    fn test_not_sed_returns_none() {
        let cmd = Command {
            name: "awk".to_string(),
            args: vec!["{print}".to_string()],
        };
        assert!(check_sed_script(&cmd, &cfg(&["/usr/*"]), None).is_none());
    }

    #[test]
    fn test_append_text_with_w_not_a_write() {
        // Classic `a\` with the appended text on the next line: the text
        // "w /usr/bin/x" must be treated as text, not a write command.
        assert_eq!(perm(&["a\\\nw /usr/bin/x"], &["/usr/*"]), Permission::Allow);
    }

    #[test]
    fn test_append_oneline_text_allowed() {
        assert_eq!(perm(&["a hello world"], &["/usr/*"]), Permission::Allow);
    }

    #[test]
    fn test_surrounding_quotes_stripped() {
        // The bash analyzer keeps shell quotes; the parser should see clean text.
        let cmd = make_cmd(&["'w /usr/bin/x'"]);
        let result = check_sed_script(&cmd, &cfg(&["/usr/*"]), None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
        assert!(result.reason.ends_with("/usr/bin/x"), "{}", result.reason);
    }

    #[test]
    fn test_double_quoted_script_allowed() {
        let cmd = make_cmd(&["\"s/a/b/\""]);
        assert_eq!(
            check_sed_script(&cmd, &cfg(&["/usr/*"]), None)
                .unwrap()
                .permission,
            Permission::Allow
        );
    }
}
