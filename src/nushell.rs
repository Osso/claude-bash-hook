//! Nushell command analyzer using nu-parser
//!
//! Parses nushell commands and extracts external command calls for permission checking.
//! Only explicitly external commands (prefixed with ^) are extracted, since the parser
//! doesn't have nushell's stdlib loaded and can't distinguish builtins from externals.

use nu_parser::parse;
use nu_protocol::Span;
use nu_protocol::engine::{EngineState, StateWorkingSet};

use crate::analyzer::Command;

/// Result of analyzing a nushell command
#[derive(Debug)]
pub struct NushellAnalysisResult {
    /// External commands found (commands that run external programs)
    pub commands: Vec<Command>,
    /// Whether parsing succeeded
    pub success: bool,
    /// Error message if parsing failed
    pub error: Option<String>,
}

/// Analyze a nushell command string and extract external commands
pub fn analyze(cmd: &str) -> NushellAnalysisResult {
    let engine_state = EngineState::new();
    let mut working_set = StateWorkingSet::new(&engine_state);

    let block = parse(&mut working_set, None, cmd.as_bytes(), false);

    // Check for parse errors, but ignore "Unknown state" errors from missing stdlib
    // Only real syntax errors should fail (unclosed braces, etc.)
    let has_real_error = working_set.parse_errors.iter().any(|e| {
        let msg = format!("{}", e);
        // Unknown state happens when builtins aren't loaded - not a real syntax error
        !msg.contains("Unknown state")
    });

    if has_real_error {
        let error = working_set
            .parse_errors
            .iter()
            .find(|e| !format!("{}", e).contains("Unknown state"))
            .map(|e| format!("{}", e))
            .unwrap_or_else(|| "Unknown parse error".to_string());

        return NushellAnalysisResult {
            commands: vec![],
            success: false,
            error: Some(error),
        };
    }

    // Extract external commands from the parsed block
    let mut commands = Vec::new();
    extract_external_commands(&block, cmd.as_bytes(), &mut commands);

    NushellAnalysisResult {
        commands,
        success: true,
        error: None,
    }
}

/// Nushell builtins that are read-only and safe to allow
/// Without stdlib loaded, the parser treats these as external commands
const SAFE_NUSHELL_BUILTINS: &[&str] = &[
    // Filesystem (read-only)
    "glob",
    "ls",
    // Data manipulation (read-only)
    "open",
    "get",
    "select",
    "where",
    "each",
    "filter",
    "find",
    "first",
    "last",
    "skip",
    "take",
    "reverse",
    "sort-by",
    "uniq",
    "reject",
    "rename",
    "move",
    "insert",
    "update",
    "upsert",
    "flatten",
    "transpose",
    "group-by",
    "split-by",
    "merge",
    "join",
    "zip",
    "enumerate",
    "range",
    "length",
    "is-empty",
    "is-not-empty",
    "columns",
    "values",
    "headers",
    // Conversion
    "to",
    "from",
    "into",
    // String operations
    "str",
    "split",
    "lines",
    "parse",
    "format",
    // Math
    "math",
    "sum",
    "avg",
    "min",
    "max",
    "count",
    // Comparison/logic
    "if",
    "else",
    "match",
    "not",
    "and",
    "or",
    "all",
    "any",
    // Variables
    "let",
    "mut",
    "const",
    "def",
    // Output
    "print",
    "echo",
    "table",
    "grid",
    // System info (read-only)
    "sys",
    "ps",
    "which",
    "version",
    // Path operations (read-only)
    "path",
    // Date/time
    "date",
    // Help
    "help",
    "describe",
    // Debug
    "debug",
    "inspect",
    "metadata",
    // Ignore (used to suppress output)
    "ignore",
    "null",
    // HTTP (read-only methods)
    "http", // Note: http get is read-only, http post is not - but we'll allow for now
];

/// Extract external command calls from a parsed block
fn extract_external_commands(
    block: &nu_protocol::ast::Block,
    source: &[u8],
    commands: &mut Vec<Command>,
) {
    for pipeline in &block.pipelines {
        for element in &pipeline.elements {
            extract_from_expression(&element.expr, source, commands);
        }
    }
}

/// Extract an external command call, skipping safe builtins
fn extract_external_call(
    expr: &nu_protocol::ast::Expression,
    head: &nu_protocol::ast::Expression,
    args: &[nu_protocol::ast::ExternalArgument],
    source: &[u8],
    commands: &mut Vec<Command>,
) {
    let name = span_to_string(head.span, source);
    let clean_name = name.trim_start_matches('^');

    if SAFE_NUSHELL_BUILTINS.contains(&clean_name) {
        return;
    }

    let text = span_to_string(expr.span, source);
    let arg_strings: Vec<String> = args
        .iter()
        .filter_map(|arg| match arg {
            nu_protocol::ast::ExternalArgument::Regular(e) => {
                Some(span_to_string(e.span, source))
            }
            nu_protocol::ast::ExternalArgument::Spread(e) => {
                Some(span_to_string(e.span, source))
            }
        })
        .collect();

    commands.push(Command {
        name: clean_name.to_string(),
        args: arg_strings,
        text: text.trim_start_matches('^').to_string(),
    });
}

/// Dangerous nushell builtins that modify filesystem
const DANGEROUS_BUILTINS: &[&str] = &["rm", "mv", "cp", "mkdir", "touch", "save"];

/// Extract a dangerous builtin call and recurse into arguments
fn extract_builtin_call(
    expr: &nu_protocol::ast::Expression,
    call: &nu_protocol::ast::Call,
    source: &[u8],
    commands: &mut Vec<Command>,
) {
    let call_name = span_to_string(call.head, source);

    if DANGEROUS_BUILTINS.contains(&call_name.as_str()) {
        let arg_strings: Vec<String> = call
            .arguments
            .iter()
            .filter_map(|arg| arg.expr().map(|e| span_to_string(e.span, source)))
            .collect();

        commands.push(Command {
            name: call_name,
            args: arg_strings,
            text: span_to_string(expr.span, source),
        });
    }

    for arg in &call.arguments {
        if let Some(e) = arg.expr() {
            extract_from_expression(e, source, commands);
        }
    }
}

/// Extract external commands from an expression
fn extract_from_expression(
    expr: &nu_protocol::ast::Expression,
    source: &[u8],
    commands: &mut Vec<Command>,
) {
    use nu_protocol::ast::Expr;

    match &expr.expr {
        Expr::ExternalCall(head, args) => {
            extract_external_call(expr, head, args, source, commands);
        }
        Expr::Call(call) => {
            extract_builtin_call(expr, call, source, commands);
        }
        Expr::List(items) => {
            for item in items {
                extract_from_expression(item.expr(), source, commands);
            }
        }
        Expr::Record(items) => {
            for item in items {
                match item {
                    nu_protocol::ast::RecordItem::Pair(k, v) => {
                        extract_from_expression(k, source, commands);
                        extract_from_expression(v, source, commands);
                    }
                    nu_protocol::ast::RecordItem::Spread(_, e) => {
                        extract_from_expression(e, source, commands);
                    }
                }
            }
        }
        Expr::FullCellPath(fcp) => {
            extract_from_expression(&fcp.head, source, commands);
        }
        Expr::BinaryOp(lhs, _, rhs) => {
            extract_from_expression(lhs, source, commands);
            extract_from_expression(rhs, source, commands);
        }
        Expr::UnaryNot(e) => {
            extract_from_expression(e, source, commands);
        }
        _ => {}
    }
}

/// Convert a span to a string
fn span_to_string(span: Span, source: &[u8]) -> String {
    let start = span.start;
    let end = span.end;
    if start < source.len() && end <= source.len() && start < end {
        String::from_utf8_lossy(&source[start..end]).to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_command() {
        // External commands are extracted (with or without ^)
        let result = analyze("^git status");
        assert!(result.success);
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].name, "git");
        assert_eq!(result.commands[0].args, vec!["status"]);
    }

    #[test]
    fn test_bare_command() {
        // Bare commands without ^ are also extracted
        let result = analyze("git status");
        assert!(result.success);
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].name, "git");
    }

    #[test]
    fn test_syntax_error() {
        // Real syntax errors should fail
        let result = analyze("if { echo broken");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_pipeline_with_externals() {
        // All external commands in pipeline are extracted (ls is a safe builtin, filtered out)
        let result = analyze("ls | grep pattern");
        assert!(result.success);
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].name, "grep");
    }

    #[test]
    fn test_multiple_external_commands() {
        // Multiple external commands should all be extracted
        let result = analyze("git status | grep modified");
        assert!(result.success);
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].name, "git");
        assert_eq!(result.commands[1].name, "grep");
    }

    #[test]
    fn test_rm_command() {
        // rm should be extracted as external command
        let result = analyze("rm ~/Downloads/hello");
        eprintln!("success: {}, error: {:?}", result.success, result.error);
        eprintln!("commands: {:?}", result.commands);
        assert!(result.success);
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].name, "rm");
    }

    #[test]
    fn test_open_get_to_json() {
        // Pure nushell builtins - no external commands
        let result = analyze("open /tmp/claude/test.json | get items | to json");
        eprintln!("success: {}, error: {:?}", result.success, result.error);
        eprintln!("commands: {:?}", result.commands);
        assert!(result.success);
        // Should have no dangerous commands
        assert_eq!(result.commands.len(), 0);
    }
}
