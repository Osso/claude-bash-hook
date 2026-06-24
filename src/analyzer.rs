//! Bash command analyzer using tree-sitter-bash
//!
//! Walks the AST and extracts all commands with their arguments.

use std::collections::HashMap;
use tree_sitter::{Node, Parser};

/// Represents a single command extracted from the AST
#[derive(Debug, Clone)]
pub struct Command {
    /// The command name (e.g., "ls", "git")
    pub name: String,
    /// All arguments including flags (e.g., ["-la", "/tmp"])
    pub args: Vec<String>,
}

/// Result of analyzing a bash command
#[derive(Debug)]
pub struct AnalysisResult {
    /// All commands found (from pipelines, lists, etc.)
    pub commands: Vec<Command>,
    /// File targets of output redirects (`>`, `>>`, `&>`, ...). Input
    /// redirects (`<`) are reads and excluded.
    pub write_redirects: Vec<String>,
    /// Literal `VAR=value` assignments found in the command, mapping name to
    /// value. Only constant literals are recorded; values built from
    /// expansions or command substitution are omitted (they are not safely
    /// resolvable statically).
    pub var_values: HashMap<String, String>,
    /// Whether parsing succeeded
    pub success: bool,
    /// Error message if parsing failed
    pub error: Option<String>,
}

/// Analyze a bash command string and extract all commands
pub fn analyze(cmd: &str) -> AnalysisResult {
    let mut parser = Parser::new();

    let language = tree_sitter_bash::LANGUAGE;
    if let Err(e) = parser.set_language(&language.into()) {
        return AnalysisResult {
            commands: vec![],
            write_redirects: vec![],
            var_values: HashMap::new(),
            success: false,
            error: Some(format!("Failed to set language: {}", e)),
        };
    }

    let tree = match parser.parse(cmd, None) {
        Some(tree) => tree,
        None => {
            return AnalysisResult {
                commands: vec![],
                write_redirects: vec![],
                var_values: HashMap::new(),
                success: false,
                error: Some("Failed to parse command".to_string()),
            };
        }
    };

    let root = tree.root_node();

    // Check for syntax errors in the parse tree
    if root.has_error() {
        let error_msg = find_syntax_error(root, cmd.as_bytes());
        return AnalysisResult {
            commands: vec![],
            write_redirects: vec![],
            var_values: HashMap::new(),
            success: false,
            error: Some(error_msg),
        };
    }

    let mut commands = Vec::new();
    walk_node(root, cmd.as_bytes(), &mut commands);

    let mut write_redirects = Vec::new();
    collect_write_redirects(root, cmd.as_bytes(), &mut write_redirects);

    let mut var_values = HashMap::new();
    collect_var_values(root, cmd.as_bytes(), &mut var_values);

    AnalysisResult {
        commands,
        write_redirects,
        var_values,
        success: true,
        error: None,
    }
}

/// Recursively collect literal `VAR=value` assignments into `out` (name →
/// value). Later assignments override earlier ones, matching shell semantics.
/// Only constant literals are recorded; values containing expansions or command
/// substitution are skipped because they cannot be resolved statically.
fn collect_var_values(node: Node, source: &[u8], out: &mut HashMap<String, String>) {
    if node.kind() == "variable_assignment"
        && let Some(name) = node.child_by_field_name("name")
        && let Some(value) = node.child_by_field_name("value")
        && let Some(literal) = literal_value(value, source)
    {
        out.insert(get_text(name, source), literal);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_var_values(child, source, out);
    }
}

/// Return the constant string value of an assignment's value node, or `None`
/// when the value is not a static literal (e.g. interpolated or substituted).
fn literal_value(node: Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "word" | "number" => Some(get_text(node, source)),
        // Single-quoted: never interpolated, strip the surrounding quotes.
        "raw_string" => Some(get_text(node, source).trim_matches('\'').to_string()),
        // Double-quoted: literal only when it contains no expansions.
        "string" => literal_double_quoted(node, source),
        _ => None,
    }
}

/// Concatenate the literal segments of a double-quoted `string` node, returning
/// `None` if any child is an expansion or command substitution.
fn literal_double_quoted(node: Node, source: &[u8]) -> Option<String> {
    let mut value = String::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string_content" => value.push_str(&get_text(child, source)),
            "\"" => {}
            _ => return None,
        }
    }
    Some(value)
}

/// Recursively collect the file targets of output redirects (`>`, `>>`, `&>`,
/// `>|`, `2>`, ...). Input redirects (`<`, `<<`, `<<<`) are reads and skipped.
fn collect_write_redirects(node: Node, source: &[u8], out: &mut Vec<String>) {
    if node.kind() == "file_redirect"
        && is_write_redirect(node)
        && let Some(dest) = node.child_by_field_name("destination")
    {
        out.push(get_text(dest, source));
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_write_redirects(child, source, out);
    }
}

/// True if a `file_redirect` node uses an output (writing) operator.
fn is_write_redirect(node: Node) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| matches!(child.kind(), ">" | ">>" | "&>" | "&>>" | ">|" | ">&"))
}

/// Find the first syntax error in the tree and return a helpful message
fn find_syntax_error(node: Node, source: &[u8]) -> String {
    // Find ERROR or MISSING nodes
    if node.is_error() || node.is_missing() {
        let start = node.start_position();
        let context = get_error_context(node, source);
        return format!("Syntax error at column {}: {}", start.column + 1, context);
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.has_error() || child.is_error() || child.is_missing() {
            return find_syntax_error(child, source);
        }
    }

    "Unknown syntax error".to_string()
}

/// Get context around a syntax error
fn get_error_context(node: Node, source: &[u8]) -> String {
    let start = node.start_byte();
    let end = node.end_byte().min(source.len());

    // Get some context before and after
    let context_start = start.saturating_sub(20);
    let context_end = (end + 20).min(source.len());

    let before = String::from_utf8_lossy(&source[context_start..start]);
    let error_text = if start < end {
        String::from_utf8_lossy(&source[start..end])
    } else {
        std::borrow::Cow::Borrowed("<missing>")
    };
    let after = String::from_utf8_lossy(&source[end..context_end]);

    if node.is_missing() {
        format!(
            "expected {} near '{}▶◀{}'",
            node.kind(),
            before.trim(),
            after.trim()
        )
    } else {
        format!(
            "unexpected '{}' near '{}▶{}◀{}'",
            error_text,
            before.trim(),
            error_text,
            after.trim()
        )
    }
}

/// Recursively walk the AST and collect commands
fn walk_node(node: Node, source: &[u8], commands: &mut Vec<Command>) {
    match node.kind() {
        "command" => {
            if let Some(cmd) = extract_command(node, source) {
                commands.push(cmd);
            }
        }
        // Recurse into container nodes
        "program"
        | "list"
        | "pipeline"
        | "compound_statement"
        | "subshell"
        | "if_statement"
        | "while_statement"
        | "for_statement"
        | "case_statement"
        | "redirected_statement"
        | "negated_command"
        | "do_group" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk_node(child, source, commands);
            }
        }
        // Skip other node types
        _ => {}
    }
}

/// Extract command name and arguments from a command node
fn extract_command(node: Node, source: &[u8]) -> Option<Command> {
    let mut name = String::new();
    let mut args = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "command_name" {
            name = get_text(child, source);
            continue;
        }

        if is_inline_argument(child) {
            args.push(get_text(child, source));
        }
    }

    add_field_arguments(node, source, &mut args);

    if name.is_empty() {
        return None;
    }

    Some(Command { name, args })
}

/// Get the text content of a node
fn get_text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Substitute `$name` and `${name}` references with their literal values from
/// `vars`. Unknown variables are left untouched. Quoting is irrelevant here:
/// the argument text retains any surrounding quotes, which downstream checks
/// strip as needed.
pub fn expand_known_vars(s: &str, vars: &HashMap<String, String>) -> String {
    if vars.is_empty() || !s.contains('$') {
        return s.to_string();
    }

    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        match parse_var_ref(after) {
            Some((name, consumed)) if vars.contains_key(name) => {
                out.push_str(&vars[name]);
                rest = &after[consumed..];
            }
            _ => {
                out.push('$');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Parse a variable reference at the start of `after` (the text following a
/// `$`). Returns the variable name and the number of bytes consumed, for both
/// `${name}` and bare `$name` forms. Variable names are ASCII, so byte slicing
/// stays on char boundaries.
fn parse_var_ref(after: &str) -> Option<(&str, usize)> {
    if let Some(braced) = after.strip_prefix('{') {
        let end = braced.find('}')?;
        return Some((&braced[..end], end + 2));
    }
    let len = after
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    (len > 0).then(|| (&after[..len], len))
}

fn is_inline_argument(child: Node) -> bool {
    matches!(
        child.kind(),
        "word"
            | "string"
            | "raw_string"
            | "number"
            | "concatenation"
            | "simple_expansion"
            | "expansion"
            | "command_substitution"
    ) && child.is_named()
}

fn add_field_arguments(node: Node, source: &[u8], args: &mut Vec<String>) {
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else {
            continue;
        };
        if node.field_name_for_child(i as u32) != Some("argument") {
            continue;
        }

        let text = get_text(child, source);
        if !args.iter().any(|arg| arg == &text) {
            args.push(text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_var_values_literal_forms() {
        let result =
            analyze("a=https://api.gcdev.site; b='single'; c=\"plain text\"; n=42; curl \"$a\"");
        assert!(result.success);
        assert_eq!(
            result.var_values.get("a").map(String::as_str),
            Some("https://api.gcdev.site")
        );
        assert_eq!(
            result.var_values.get("b").map(String::as_str),
            Some("single")
        );
        assert_eq!(
            result.var_values.get("c").map(String::as_str),
            Some("plain text")
        );
        assert_eq!(result.var_values.get("n").map(String::as_str), Some("42"));
    }

    #[test]
    fn test_var_values_skips_dynamic() {
        // Interpolated value and command substitution are not static literals.
        let result = analyze("a=\"https://$h.site\"; b=$(hostname); echo hi");
        assert!(result.success);
        assert!(!result.var_values.contains_key("a"));
        assert!(!result.var_values.contains_key("b"));
    }

    #[test]
    fn test_var_values_later_wins() {
        let result = analyze("x=1; x=2; echo hi");
        assert_eq!(result.var_values.get("x").map(String::as_str), Some("2"));
    }

    #[test]
    fn test_expand_known_vars() {
        let mut vars = HashMap::new();
        vars.insert("api".to_string(), "https://api.gcdev.site".to_string());
        assert_eq!(
            expand_known_vars("\"$api/v1/x\"", &vars),
            "\"https://api.gcdev.site/v1/x\""
        );
        assert_eq!(
            expand_known_vars("${api}/v1", &vars),
            "https://api.gcdev.site/v1"
        );
        // Unknown variables and bare dollars are left untouched.
        assert_eq!(expand_known_vars("$unknown/x", &vars), "$unknown/x");
        assert_eq!(expand_known_vars("price is $5", &vars), "price is $5");
        // No prefix match: $apifoo is a different name, not $api + "foo".
        assert_eq!(expand_known_vars("$apifoo", &vars), "$apifoo");
    }

    #[test]
    fn test_simple_command() {
        let result = analyze("ls -la /tmp");
        assert!(result.success);
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].name, "ls");
        assert!(result.commands[0].args.contains(&"-la".to_string()));
    }

    #[test]
    fn test_pipeline() {
        let result = analyze("ls | grep foo");
        assert!(result.success);
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].name, "ls");
        assert_eq!(result.commands[1].name, "grep");
    }

    #[test]
    fn test_chain() {
        let result = analyze("ls && rm file");
        assert!(result.success);
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].name, "ls");
        assert_eq!(result.commands[1].name, "rm");
    }

    #[test]
    fn test_subshell() {
        let result = analyze("(ls; pwd)");
        assert!(result.success);
        assert_eq!(result.commands.len(), 2);
    }

    #[test]
    fn test_env_var() {
        let result = analyze("VAR=1 ls");
        assert!(result.success);
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].name, "ls");
    }

    #[test]
    fn test_while_loop() {
        let result = analyze("while read id; do echo $id; done");
        assert!(result.success);
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].name, "read");
        assert_eq!(result.commands[1].name, "echo");
    }

    // Syntax error tests
    #[test]
    fn test_unclosed_bracket() {
        let result = analyze("if [ $x == 1; then echo yes; fi");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_missing_do() {
        let result = analyze("for f in *.txt; echo $f; done");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_unclosed_quote() {
        let result = analyze("echo \"hello");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_bad_comparison() {
        let result = analyze("if [[ $x = 1 ]]; then echo yes; fi");
        // This is actually valid bash - single = works in [[]]
        assert!(result.success);
    }

    #[test]
    fn test_missing_then() {
        let result = analyze("if [ -f file ]; echo yes; fi");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_unmatched_paren() {
        let result = analyze("(ls; pwd");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    // Redirect capture tests

    #[test]
    fn test_redirect_truncate() {
        let result = analyze("echo hi > /usr/bin/foo");
        assert!(result.success);
        assert_eq!(result.write_redirects, vec!["/usr/bin/foo".to_string()]);
    }

    #[test]
    fn test_redirect_append() {
        let result = analyze("echo hi >> /etc/hosts");
        assert!(result.success);
        assert_eq!(result.write_redirects, vec!["/etc/hosts".to_string()]);
    }

    #[test]
    fn test_redirect_input_is_not_write() {
        let result = analyze("cat < /usr/bin/foo");
        assert!(result.success);
        assert!(result.write_redirects.is_empty());
    }

    #[test]
    fn test_redirect_stderr_to_file() {
        let result = analyze("foo 2> /var/log/x");
        assert!(result.success);
        assert_eq!(result.write_redirects, vec!["/var/log/x".to_string()]);
    }

    #[test]
    fn test_redirect_fd_dup_not_a_file() {
        // 2>&1 duplicates a descriptor; destination "1" is not a path.
        let result = analyze("foo > /tmp/out 2>&1");
        assert!(result.success);
        assert!(result.write_redirects.contains(&"/tmp/out".to_string()));
    }

    #[test]
    fn test_no_redirect() {
        let result = analyze("echo hi");
        assert!(result.success);
        assert!(result.write_redirects.is_empty());
    }
}
