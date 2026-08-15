//! Pyrun permission analysis for one complete `pyrun_eval` program.
//!
//! Pyrun code is approved once, before evaluation starts. This module therefore
//! parses the complete Python program in-process and aggregates every helper
//! operation into one permission result.

use crate::analysis;
use crate::config::{Config, ExecContext, Permission, PermissionResult};
use crate::scripts::python;
use tree_sitter::{Node, Parser};

mod path;

const COMMAND_ROOTS: &[&str] = &["run", "cli"];
const PURE_NAMESPACE_ROOTS: &[&str] = &["text", "seq", "obj"];
const RG_METHODS: &[&str] = &["search", "files", "matches"];
const FD_METHODS: &[&str] = &["find", "files", "dirs"];
const RESERVED_ROOTS: &[&str] = &[
    "run", "cli", "host", "fs", "http", "tools", "kubectl", "sqlite", "pi", "tmp", "rg", "fd",
    "text", "seq", "obj", "hr",
];
const BUILDER_CWD_METHODS: &[&str] = &["cwd", "in_"];
const BUILDER_METHODS: &[&str] = &[
    "capture",
    "cwd",
    "in_",
    "env",
    "env_clear",
    "env_inherit",
    "json",
    "lines",
    "run",
    "spawn",
    "text",
    "timeout",
];

/// Analyze one complete Pyrun program without invoking the Pyrun runtime.
pub fn check_pyrun_code(
    code: &str,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> PermissionResult {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .is_err()
    {
        return deny("unable to initialize Python parser");
    }

    let Some(tree) = parser.parse(code, None) else {
        return deny("Pyrun Python parser returned no syntax tree");
    };
    if tree.root_node().has_error() {
        return deny("Pyrun code contains a Python syntax error");
    }

    let mut findings = Vec::new();
    visit_calls(
        tree.root_node(),
        code.as_bytes(),
        config,
        virtual_cwd,
        initial_cwd,
        ctx,
        &mut findings,
    );

    findings.push(python::check_python_code(code, initial_cwd));
    analysis::allow_in_bypass(most_restrictive(findings), ctx)
}

fn visit_calls(
    node: Node<'_>,
    source: &[u8],
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
    findings: &mut Vec<PermissionResult>,
) {
    if let Some(result) = analyze_reserved_alias(node, source) {
        findings.push(result);
    }
    if node.kind() == "call"
        && let Some(result) = analyze_call(node, source, config, virtual_cwd, initial_cwd, ctx)
    {
        findings.push(result);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        visit_calls(
            child,
            source,
            config,
            virtual_cwd,
            initial_cwd,
            ctx,
            findings,
        );
    }
}

fn analyze_call(
    call: Node<'_>,
    source: &[u8],
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> Option<PermissionResult> {
    let function = call.child_by_field_name("function")?;
    let arguments = call_arguments(call);
    if let Some(result) = analyze_reserved_access(function, &arguments, source) {
        return Some(result);
    }
    if let Some(result) = analyze_output_call(
        function,
        &arguments,
        source,
        config,
        virtual_cwd,
        initial_cwd,
        ctx,
    ) {
        return Some(result);
    }
    analyze_named_call(
        call,
        function,
        &arguments,
        source,
        config,
        virtual_cwd,
        initial_cwd,
        ctx,
    )
}

fn analyze_named_call(
    call: Node<'_>,
    function: Node<'_>,
    arguments: &[Node<'_>],
    source: &[u8],
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> Option<PermissionResult> {
    let Some(path) = dotted_path(function, source) else {
        return analyze_dynamic_call(function, arguments, source);
    };
    let session_cwd = virtual_cwd.or(initial_cwd);
    let command_virtual_cwd = match resolve_command_virtual_cwd(&path, call, source, session_cwd) {
        Ok(cwd) => cwd,
        Err(reason) => return Some(ask(reason)),
    };
    let effective_virtual_cwd = command_virtual_cwd.as_deref().or(virtual_cwd);
    analyze_static_call(
        &path,
        arguments,
        source,
        config,
        effective_virtual_cwd,
        initial_cwd,
        ctx,
    )
}

fn resolve_command_virtual_cwd(
    path: &[String],
    call: Node<'_>,
    source: &[u8],
    session_cwd: Option<&str>,
) -> Result<Option<String>, String> {
    let is_command = path
        .first()
        .is_some_and(|root| COMMAND_ROOTS.contains(&root.as_str()));
    if is_command {
        builder_cwd_after_call(call, source, session_cwd)
    } else {
        Ok(None)
    }
}

fn analyze_output_call(
    function: Node<'_>,
    arguments: &[Node<'_>],
    source: &[u8],
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> Option<PermissionResult> {
    let is_output = attribute_name(function, source).as_deref() == Some("output");
    let has_command_root = function
        .child_by_field_name("object")
        .and_then(|object| root_name(object, source))
        .is_some_and(|root| COMMAND_ROOTS.contains(&root.as_str()));
    if !is_output || !has_command_root {
        return None;
    }
    Some(path::analyze_output_path(
        first_literal_argument(arguments, source),
        config,
        virtual_cwd,
        initial_cwd,
        ctx,
    ))
}

fn analyze_dynamic_call(
    function: Node<'_>,
    arguments: &[Node<'_>],
    source: &[u8],
) -> Option<PermissionResult> {
    let root = root_name(function, source)?;
    if let Some(method) = attribute_name(function, source)
        && COMMAND_ROOTS.contains(&root.as_str())
    {
        if BUILDER_CWD_METHODS.contains(&method.as_str()) {
            if first_literal_argument(arguments, source).is_some() {
                return None;
            }
            return Some(ask(format!("dynamic Pyrun command {} is not safe", method)));
        }
        if BUILDER_METHODS.contains(&method.as_str()) {
            return None;
        }
    }
    RESERVED_ROOTS
        .contains(&root.as_str())
        .then(|| ask(format!("dynamic Pyrun call on {}", root)))
}

fn analyze_static_call(
    path: &[String],
    arguments: &[Node<'_>],
    source: &[u8],
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> Option<PermissionResult> {
    let root = path.first()?.as_str();
    match root {
        root if COMMAND_ROOTS.contains(&root) => Some(analyze_command_call(
            path,
            arguments,
            source,
            config,
            virtual_cwd,
            initial_cwd,
            ctx,
        )),
        "host" => Some(analyze_host_call(path)),
        "fs" => Some(path::analyze_filesystem_call(
            path.last()?.as_str(),
            arguments,
            source,
            config,
            virtual_cwd,
            initial_cwd,
            ctx,
        )),
        root if is_pure_helper_root(root) => Some(analyze_pure_helper_call(path)),
        root if RESERVED_ROOTS.contains(&root) => Some(ask(format!(
            "Pyrun helper {} requires approval",
            path.join(".")
        ))),
        _ if path.len() == 1 && BUILDER_METHODS.contains(&path[0].as_str()) => None,
        _ => None,
    }
}

fn analyze_host_call(path: &[String]) -> PermissionResult {
    match path.get(1).map(String::as_str) {
        Some("cwd") if path.len() == 2 => allow("read-only Pyrun helper host.cwd".to_string()),
        Some("cd") if path.len() == 2 => {
            ask("Pyrun host.cd changes the working directory".to_string())
        }
        _ => ask(format!(
            "Pyrun host helper {} requires approval",
            path.join(".")
        )),
    }
}

fn is_pure_helper_root(root: &str) -> bool {
    root == "rg" || root == "fd" || PURE_NAMESPACE_ROOTS.contains(&root) || root == "hr"
}

fn analyze_pure_helper_call(path: &[String]) -> PermissionResult {
    let root = path.first().map(String::as_str).unwrap_or_default();
    let is_allowed = match root {
        "rg" => path.len() == 1 || (path.len() == 2 && RG_METHODS.contains(&path[1].as_str())),
        "fd" => path.len() == 1 || (path.len() == 2 && FD_METHODS.contains(&path[1].as_str())),
        "text" | "seq" | "obj" => true,
        "hr" => path.len() == 1,
        _ => false,
    };
    if is_allowed {
        allow(format!("pure Pyrun helper {}", path.join(".")))
    } else {
        ask(format!("unknown pure Pyrun helper {}", path.join(".")))
    }
}

fn analyze_command_call(
    path: &[String],
    arguments: &[Node<'_>],
    source: &[u8],
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> PermissionResult {
    let Some(method) = path.get(1) else {
        return ask("Pyrun command root requires a program".to_string());
    };

    let (program, arg_nodes) = if method == "command" || method == "cmd" {
        let Some(program) = arguments
            .first()
            .and_then(|arg| literal_string(*arg, source))
        else {
            return ask("Pyrun command name is dynamic".to_string());
        };
        (program, &arguments[1..])
    } else {
        (method.replace('_', "-"), arguments)
    };

    let Some(args) = literal_arguments(arg_nodes, source) else {
        return ask(format!("Pyrun command {} has dynamic arguments", program));
    };

    let result =
        analysis::analyze_literal_command(&program, &args, config, ctx, virtual_cwd, initial_cwd);
    normalize_command_result(result, &program)
}

fn normalize_command_result(mut result: PermissionResult, program: &str) -> PermissionResult {
    if result.permission == Permission::Passthrough {
        result.permission = Permission::Ask;
        result.reason = format!("Pyrun command {} requires approval", program);
    }
    result
}

fn analyze_reserved_access(
    function: Node<'_>,
    arguments: &[Node<'_>],
    source: &[u8],
) -> Option<PermissionResult> {
    let path = dotted_path(function, source)?;
    if !matches!(path.as_slice(), [name] if matches!(name.as_str(), "getattr" | "setattr" | "delattr"))
    {
        return None;
    }
    let root = arguments
        .first()
        .and_then(|argument| root_name(*argument, source))?;
    RESERVED_ROOTS
        .contains(&root.as_str())
        .then(|| ask(format!("dynamic Pyrun helper access on {}", root)))
}

fn analyze_reserved_alias(node: Node<'_>, source: &[u8]) -> Option<PermissionResult> {
    if node.kind() != "assignment" {
        return None;
    }

    let target = node.child_by_field_name("left")?;
    if let Some(root) = root_name(target, source)
        && RESERVED_ROOTS.contains(&root.as_str())
    {
        return Some(ask(format!("Pyrun helper rebinding on {}", root)));
    }

    let value = node.child_by_field_name("right")?;
    if value.kind() == "call" {
        return None;
    }
    let path = dotted_path(value, source)?;
    let root = path.first()?;
    RESERVED_ROOTS
        .contains(&root.as_str())
        .then(|| ask(format!("Pyrun helper alias {}", path.join("."))))
}

fn builder_cwd_after_call(
    call: Node<'_>,
    source: &[u8],
    session_cwd: Option<&str>,
) -> Result<Option<String>, String> {
    let mut current = call;
    let mut cwd = None;
    loop {
        let Some(attribute) = current.parent() else {
            break;
        };
        if attribute.kind() != "attribute"
            || !same_node(attribute.child_by_field_name("object"), Some(current))
        {
            break;
        }
        let Some(builder_call) = attribute.parent() else {
            break;
        };
        if builder_call.kind() != "call"
            || !same_node(
                builder_call.child_by_field_name("function"),
                Some(attribute),
            )
        {
            break;
        }
        let method = attribute_name(attribute, source).unwrap_or_default();
        if BUILDER_CWD_METHODS.contains(&method.as_str()) {
            cwd = Some(builder_cwd_argument(
                builder_call,
                &method,
                source,
                session_cwd,
            )?);
        }
        current = builder_call;
    }
    Ok(cwd)
}

fn builder_cwd_argument(
    call: Node<'_>,
    method: &str,
    source: &[u8],
    session_cwd: Option<&str>,
) -> Result<String, String> {
    let path = first_literal_argument(&call_arguments(call), source)
        .ok_or_else(|| format!("dynamic Pyrun command {} is not safe", method))?;
    path::resolve_path(&path, session_cwd, None)
        .ok_or_else(|| format!("Pyrun command {} cwd cannot be resolved", method))
}

fn same_node(left: Option<Node<'_>>, right: Option<Node<'_>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
        }
        _ => false,
    }
}

fn call_arguments(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).collect()
}

fn first_literal_argument(arguments: &[Node<'_>], source: &[u8]) -> Option<String> {
    arguments
        .first()
        .and_then(|argument| literal_string(*argument, source))
}

fn literal_arguments(arguments: &[Node<'_>], source: &[u8]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| literal_string(*argument, source))
        .collect()
}

fn literal_string(node: Node<'_>, source: &[u8]) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let text = node.utf8_text(source).ok()?.trim();
    let bytes = text.as_bytes();
    if bytes.len() < 2
        || !matches!(
            (bytes[0], bytes[bytes.len() - 1]),
            (b'\'', b'\'') | (b'"', b'"')
        )
    {
        return None;
    }
    let value = &text[1..text.len() - 1];
    (!value.contains('\\')).then(|| value.to_string())
}

fn dotted_path(node: Node<'_>, source: &[u8]) -> Option<Vec<String>> {
    match node.kind() {
        "identifier" => Some(vec![node.utf8_text(source).ok()?.to_string()]),
        "attribute" => {
            let mut path = dotted_path(node.child_by_field_name("object")?, source)?;
            path.push(
                node.child_by_field_name("attribute")?
                    .utf8_text(source)
                    .ok()?
                    .to_string(),
            );
            Some(path)
        }
        "parenthesized_expression" => {
            let mut cursor = node.walk();
            dotted_path(node.named_children(&mut cursor).next()?, source)
        }
        _ => None,
    }
}

fn root_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => Some(node.utf8_text(source).ok()?.to_string()),
        "attribute" | "subscript" | "parenthesized_expression" => {
            let child = match node.kind() {
                "attribute" => node.child_by_field_name("object"),
                "subscript" => node.child_by_field_name("value"),
                _ => {
                    let mut cursor = node.walk();
                    node.named_children(&mut cursor).next()
                }
            }?;
            root_name(child, source)
        }
        "call" => root_name(node.child_by_field_name("function")?, source),
        _ => None,
    }
}

fn attribute_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    (node.kind() == "attribute")
        .then(|| node.child_by_field_name("attribute"))
        .flatten()
        .and_then(|attribute| attribute.utf8_text(source).ok())
        .map(str::to_string)
}

fn most_restrictive(findings: Vec<PermissionResult>) -> PermissionResult {
    findings
        .into_iter()
        .max_by_key(|result| result.permission)
        .unwrap_or_else(|| allow("Pyrun code contains no analyzed operations".to_string()))
}

fn allow(reason: String) -> PermissionResult {
    PermissionResult {
        permission: Permission::Allow,
        reason,
        suggestion: None,
    }
}

fn ask(reason: String) -> PermissionResult {
    PermissionResult {
        permission: Permission::Ask,
        reason,
        suggestion: None,
    }
}

fn deny(reason: &str) -> PermissionResult {
    PermissionResult {
        permission: Permission::Deny,
        reason: reason.to_string(),
        suggestion: Some("Fix the Pyrun syntax and try again".to_string()),
    }
}
