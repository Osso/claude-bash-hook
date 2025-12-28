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
    /// The full command text (for debugging)
    #[allow(dead_code)]
    pub text: String,
}

/// Result of analyzing a bash command
#[derive(Debug)]
pub struct AnalysisResult {
    /// All commands found (from pipelines, lists, etc.)
    pub commands: Vec<Command>,
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
            success: false,
            error: Some(format!("Failed to set language: {}", e)),
        };
    }

    let tree = match parser.parse(cmd, None) {
        Some(tree) => tree,
        None => {
            return AnalysisResult {
                commands: vec![],
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
            success: false,
            error: Some(error_msg),
        };
    }

    let mut commands = Vec::new();
    walk_node(root, cmd.as_bytes(), &mut commands);

    AnalysisResult {
        commands,
        success: true,
        error: None,
    }
}

/// Find the first syntax error in the tree and return a helpful message
fn find_syntax_error(node: Node, source: &[u8]) -> String {
    // Find ERROR or MISSING nodes
    if node.is_error() || node.is_missing() {
        let start = node.start_position();
        let context = get_error_context(node, source);
        return format!(
            "Syntax error at column {}: {}",
            start.column + 1,
            context
        );
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
        format!("expected {} near '{}▶◀{}'", node.kind(), before.trim(), after.trim())
    } else {
        format!("unexpected '{}' near '{}▶{}◀{}'", error_text, before.trim(), error_text, after.trim())
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
        "program" | "list" | "pipeline" | "compound_statement" | "subshell"
        | "if_statement" | "while_statement" | "for_statement" | "case_statement"
        | "redirected_statement" | "negated_command" | "do_group" => {
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
        match child.kind() {
            "command_name" => {
                name = get_text(child, source);
            }
            "word" | "string" | "raw_string" | "number" | "concatenation"
            | "simple_expansion" | "expansion" | "command_substitution" => {
                // These are arguments
                if child.is_named() {
                    // Check if this is actually an argument field
                    args.push(get_text(child, source));
                }
            }
            _ => {
                // Handle nested literals in arguments
                if child.is_named() {
                    // Check parent field name
                    let field_name = node.field_name_for_child(child.id() as u32);
                    if field_name == Some("argument") {
                        args.push(get_text(child, source));
                    }
                }
            }
        }
    }

    // Also check for arguments using field iteration
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(field) = node.field_name_for_child(i as u32) {
                if field == "argument" && !args.iter().any(|a| a == &get_text(child, source)) {
                    args.push(get_text(child, source));
                }
            }
        }
    }

    if name.is_empty() {
        return None;
    }

    let text = get_text(node, source);

    Some(Command { name, args, text })
}

/// Get the text content of a node
fn get_text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
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
}
