//! Bash command analyzer using tree-sitter-bash
//!
//! Walks the AST and extracts all commands with their arguments.

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
            success: false,
            error: Some(error_msg),
        };
    }

    let mut commands = Vec::new();
    walk_node(root, cmd.as_bytes(), &mut commands);

    let mut write_redirects = Vec::new();
    collect_write_redirects(root, cmd.as_bytes(), &mut write_redirects);

    AnalysisResult {
        commands,
        write_redirects,
        success: true,
        error: None,
    }
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
