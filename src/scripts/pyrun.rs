//! Pyrun permission analysis for one complete `pyrun_eval` program.
//!
//! Pyrun code is approved once, before evaluation starts. This module therefore
//! parses the complete Python program in-process and aggregates every helper
//! operation into one permission result.

use crate::analysis;
use crate::config::{Config, ExecContext, Permission, PermissionResult};
use crate::scripts::python;
use std::collections::{HashMap, HashSet};
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
/// Placeholder target for `tmp.file`/`tmp.dir`, which create under the system
/// temporary directory (`/tmp` when `TMPDIR` is unset).
const TMP_HANDLE_PATH: &str = "/tmp/pyrun-tmp-handle";
const TMP_HANDLE_CONSTRUCTORS: &[&str] = &["file", "dir"];
const KUBERNETES_NAME_JSONPATH: &str = "jsonpath={.items[0].metadata.name}";
const KUBERNETES_RESOURCE_PLACEHOLDER: &str = "pyrun-kubernetes-resource";
const MAX_STATIC_LOOP_ITERATIONS: usize = 32;
const MAX_STATIC_ARGV_ITEMS: usize = 64;
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

    let context = VisitContext {
        source: code.as_bytes(),
        config,
        virtual_cwd,
        initial_cwd,
        execution: ctx,
    };
    let mut findings = Vec::new();
    visit_scope(tree.root_node(), context, &mut findings);

    findings.push(python::check_python_code(code, initial_cwd));
    analysis::allow_in_bypass(most_restrictive(findings), ctx)
}

#[derive(Clone)]
enum KnownArgument {
    Literal(String),
    KubernetesResourceName,
}

enum CommandCwdError {
    Dynamic,
    Invalid(String),
}

#[derive(Clone, Copy)]
struct VisitContext<'a> {
    source: &'a [u8],
    config: &'a Config,
    virtual_cwd: Option<&'a str>,
    initial_cwd: Option<&'a str>,
    execution: ExecContext,
}

#[derive(Clone, Copy)]
struct CommandCwdContext<'a> {
    virtual_cwd: Option<&'a str>,
    initial_cwd: Option<&'a str>,
    unresolved: bool,
}

#[derive(Clone, Default)]
struct ScopeState {
    obj_shadowed: bool,
    local_text_is_string: bool,
    assigned_names: HashSet<String>,
    known_arguments: HashMap<String, KnownArgument>,
    known_argument_collections: HashMap<String, Vec<Vec<KnownArgument>>>,
    known_argument_lists: HashMap<String, Vec<KnownArgument>>,
}

fn visit_scope(node: Node<'_>, context: VisitContext<'_>, findings: &mut Vec<PermissionResult>) {
    let mut state = ScopeState::default();
    visit_child_nodes(node, context, &mut state, findings);
}

fn visit_nodes(
    node: Node<'_>,
    context: VisitContext<'_>,
    state: &mut ScopeState,
    findings: &mut Vec<PermissionResult>,
) {
    if visit_control_node(node, context, state, findings) {
        return;
    }
    invalidate_used_argument_collection(node, context.source, state);
    if let Some(result) = analyze_node_call(node, context, state) {
        findings.push(result);
    }
    visit_child_nodes(node, context, state, findings);
}

fn invalidate_used_argument_collection(node: Node<'_>, source: &[u8], state: &mut ScopeState) {
    let Some(name) = identifier_name(node, source) else {
        return;
    };
    if state.known_argument_collections.contains_key(&name) {
        clear_known_argument(state, &name);
    }
}

fn visit_control_node(
    node: Node<'_>,
    context: VisitContext<'_>,
    state: &mut ScopeState,
    findings: &mut Vec<PermissionResult>,
) -> bool {
    if is_lexical_scope(node) {
        visit_scope(node, context, findings);
        return true;
    }
    if visit_static_argument_loop(node, context, state, findings) {
        return true;
    }
    if is_uncertain_control_flow(node) {
        visit_uncertain_control_flow(node, context, state, findings);
        return true;
    }
    if is_assignment(node) {
        visit_assignment(node, context, state, findings);
        return true;
    }
    false
}

fn visit_uncertain_control_flow(
    node: Node<'_>,
    context: VisitContext<'_>,
    state: &mut ScopeState,
    findings: &mut Vec<PermissionResult>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let mut branch_state = state.clone();
        visit_nodes(child, context, &mut branch_state, findings);
    }
    clear_known_state(state);
}

fn visit_static_argument_loop(
    node: Node<'_>,
    context: VisitContext<'_>,
    state: &mut ScopeState,
    findings: &mut Vec<PermissionResult>,
) -> bool {
    let Some((name, argument_lists, body)) = static_argument_loop(node, context.source, state)
    else {
        return false;
    };
    for arguments in argument_lists {
        let mut iteration_state = state.clone();
        iteration_state
            .known_argument_lists
            .insert(name.clone(), arguments);
        visit_nodes(body, context, &mut iteration_state, findings);
    }
    clear_known_state(state);
    true
}

fn static_argument_loop<'a>(
    node: Node<'a>,
    source: &[u8],
    state: &ScopeState,
) -> Option<(String, Vec<Vec<KnownArgument>>, Node<'a>)> {
    if node.kind() != "for_statement" || node.child_by_field_name("alternative").is_some() {
        return None;
    }
    let name = identifier_name(node.child_by_field_name("left")?, source)?;
    if RESERVED_ROOTS.contains(&name.as_str()) {
        return None;
    }
    let iterable = node.child_by_field_name("right")?;
    let body = node.child_by_field_name("body")?;
    let argument_lists = resolve_static_argument_lists(iterable, body, source, state)?;
    Some((name, argument_lists, body))
}

fn resolve_static_argument_lists(
    iterable: Node<'_>,
    body: Node<'_>,
    source: &[u8],
    state: &ScopeState,
) -> Option<Vec<Vec<KnownArgument>>> {
    if let Some(argument_lists) = literal_argument_lists(iterable, source) {
        return Some(argument_lists);
    }
    let name = identifier_name(iterable, source)?;
    if contains_identifier(body, &name, source) {
        return None;
    }
    state.known_argument_collections.get(&name).cloned()
}

fn contains_identifier(node: Node<'_>, name: &str, source: &[u8]) -> bool {
    if identifier_name(node, source).as_deref() == Some(name) {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| contains_identifier(child, name, source))
}

fn literal_argument_lists(iterable: Node<'_>, source: &[u8]) -> Option<Vec<Vec<KnownArgument>>> {
    if !matches!(iterable.kind(), "list" | "tuple") {
        return None;
    }
    let mut cursor = iterable.walk();
    let items: Vec<_> = iterable.named_children(&mut cursor).collect();
    if items.len() > MAX_STATIC_LOOP_ITERATIONS {
        return None;
    }
    items
        .into_iter()
        .map(|item| literal_argument_list(item, source))
        .collect()
}

fn literal_argument_list(item: Node<'_>, source: &[u8]) -> Option<Vec<KnownArgument>> {
    if item.kind() != "tuple" {
        return None;
    }
    let mut cursor = item.walk();
    let arguments: Vec<_> = item.named_children(&mut cursor).collect();
    if arguments.len() > MAX_STATIC_ARGV_ITEMS {
        return None;
    }
    arguments
        .into_iter()
        .map(|argument| literal_string(argument, source).map(KnownArgument::Literal))
        .collect()
}

fn clear_known_state(state: &mut ScopeState) {
    state.obj_shadowed = false;
    state.local_text_is_string = false;
    state.assigned_names.clear();
    state.known_arguments.clear();
    state.known_argument_collections.clear();
    state.known_argument_lists.clear();
}

fn clear_known_argument(state: &mut ScopeState, name: &str) {
    state.known_arguments.remove(name);
    state.known_argument_collections.remove(name);
    state.known_argument_lists.remove(name);
}

fn is_uncertain_control_flow(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "if_statement"
            | "for_statement"
            | "while_statement"
            | "try_statement"
            | "with_statement"
            | "match_statement"
    )
}

fn is_assignment(node: Node<'_>) -> bool {
    matches!(node.kind(), "assignment" | "augmented_assignment")
}

fn analyze_node_call(
    node: Node<'_>,
    context: VisitContext<'_>,
    state: &ScopeState,
) -> Option<PermissionResult> {
    (node.kind() == "call")
        .then(|| analyze_call(node, context, state))
        .flatten()
}

fn visit_child_nodes(
    node: Node<'_>,
    context: VisitContext<'_>,
    state: &mut ScopeState,
    findings: &mut Vec<PermissionResult>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        visit_nodes(child, context, state, findings);
    }
}

fn visit_assignment(
    node: Node<'_>,
    context: VisitContext<'_>,
    state: &mut ScopeState,
    findings: &mut Vec<PermissionResult>,
) {
    visit_child_nodes(node, context, state, findings);
    if let Some(result) = analyze_assignment(node, context.source, state) {
        findings.push(result);
    }
}

fn is_lexical_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition" | "lambda" | "class_definition"
    )
}

fn analyze_call(
    call: Node<'_>,
    context: VisitContext<'_>,
    state: &ScopeState,
) -> Option<PermissionResult> {
    let function = call.child_by_field_name("function")?;
    let arguments = call_arguments(call);
    let root = root_name(function, context.source);
    if state.obj_shadowed && root.as_deref() == Some("obj") {
        return None;
    }
    if state.local_text_is_string && root.as_deref() == Some("text") {
        return analyze_local_text_call(call, context.source, state);
    }
    if let Some(result) = analyze_reserved_access(function, &arguments, context.source) {
        return Some(result);
    }
    if let Some(result) = analyze_output_call(
        function,
        &arguments,
        context.source,
        context.config,
        context.virtual_cwd,
        context.initial_cwd,
        context.execution,
    ) {
        return Some(result);
    }
    analyze_named_call(
        call,
        function,
        &arguments,
        context.source,
        context.config,
        context.virtual_cwd,
        context.initial_cwd,
        context.execution,
        state,
    )
}

fn analyze_local_text_call(
    call: Node<'_>,
    source: &[u8],
    state: &ScopeState,
) -> Option<PermissionResult> {
    if is_safe_local_text_call(call, source, state) {
        return None;
    }
    Some(ask("unsupported call on local text string".to_string()))
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
    state: &ScopeState,
) -> Option<PermissionResult> {
    let Some(path) = dotted_path(function, source) else {
        return analyze_dynamic_call(function, arguments, source);
    };
    let session_cwd = virtual_cwd.or(initial_cwd);
    let (command_virtual_cwd, inherits_session_cwd, effective_initial_cwd, has_unresolved_cwd) =
        match resolve_command_virtual_cwd(&path, call, source, session_cwd, state) {
            Ok(cwd) => (cwd, true, initial_cwd, false),
            Err(CommandCwdError::Dynamic) => (None, false, None, true),
            Err(CommandCwdError::Invalid(reason)) => return Some(ask(reason)),
        };
    let effective_virtual_cwd = if inherits_session_cwd {
        command_virtual_cwd.as_deref().or(virtual_cwd)
    } else {
        None
    };
    let cwd_context = CommandCwdContext {
        virtual_cwd: effective_virtual_cwd,
        initial_cwd: effective_initial_cwd,
        unresolved: has_unresolved_cwd,
    };
    analyze_static_call(&path, arguments, source, config, cwd_context, ctx, state)
}

fn resolve_command_virtual_cwd(
    path: &[String],
    call: Node<'_>,
    source: &[u8],
    session_cwd: Option<&str>,
    state: &ScopeState,
) -> Result<Option<String>, CommandCwdError> {
    let is_command = path
        .first()
        .is_some_and(|root| COMMAND_ROOTS.contains(&root.as_str()));
    if is_command {
        builder_cwd_after_call(call, source, session_cwd, state)
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
    if is_command_stdout_strip_call(function, arguments, source) {
        return None;
    }
    let root = root_name(function, source)?;
    if root == "tmp" && is_tmp_handle_method(function, source) {
        return None;
    }
    if let Some(method) = attribute_name(function, source)
        && COMMAND_ROOTS.contains(&root.as_str())
    {
        if BUILDER_CWD_METHODS.contains(&method.as_str()) {
            return None;
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
    cwd: CommandCwdContext<'_>,
    ctx: ExecContext,
    state: &ScopeState,
) -> Option<PermissionResult> {
    let root = path.first()?.as_str();
    match root {
        root if COMMAND_ROOTS.contains(&root) => Some(analyze_command_call(
            path, arguments, source, config, cwd, ctx, state,
        )),
        "host" => Some(analyze_host_call(path)),
        "fs" => Some(path::analyze_filesystem_call(
            path.last()?.as_str(),
            arguments,
            source,
            config,
            cwd.virtual_cwd,
            cwd.initial_cwd,
            ctx,
        )),
        root if is_pure_helper_root(root) => Some(analyze_pure_helper_call(path)),
        "tools" | "tmp" => Some(
            analyze_write_helper_call(path, arguments, source, config, cwd, ctx).unwrap_or_else(
                || ask(format!("Pyrun helper {} requires approval", path.join("."))),
            ),
        ),
        root if RESERVED_ROOTS.contains(&root) => Some(ask(format!(
            "Pyrun helper {} requires approval",
            path.join(".")
        ))),
        _ if path.len() == 1 && BUILDER_METHODS.contains(&path[0].as_str()) => None,
        _ => None,
    }
}

/// File-editing helpers follow the same write-path policy as `fs.write`, so
/// edit mode allows them for targets under the session cwd or `/tmp`.
fn analyze_write_helper_call(
    path: &[String],
    arguments: &[Node<'_>],
    source: &[u8],
    config: &Config,
    cwd: CommandCwdContext<'_>,
    ctx: ExecContext,
) -> Option<PermissionResult> {
    let segments: Vec<&str> = path.iter().map(String::as_str).collect();
    let target = match segments.as_slice() {
        ["tools", "file", "replace"] => first_literal_argument(arguments, source),
        ["tools", "file", "patch"] if arguments.len() == 2 => {
            first_literal_argument(arguments, source)
        }
        ["tools", "file", "patch"] => {
            return Some(ask(
                "Pyrun tools.file.patch with an embedded target path requires approval".to_string(),
            ));
        }
        ["tmp", method] if TMP_HANDLE_CONSTRUCTORS.contains(method) => {
            Some(TMP_HANDLE_PATH.to_string())
        }
        _ => return None,
    };
    Some(path::analyze_write_path(
        target,
        config,
        cwd.virtual_cwd,
        cwd.initial_cwd,
        ctx,
    ))
}

/// `tmp.file(...).write(...)`-style chains act on the handle's own `/tmp`
/// path; the inner `tmp.file`/`tmp.dir` call already received the decision.
fn is_tmp_handle_method(function: Node<'_>, source: &[u8]) -> bool {
    let receiver_call = function
        .child_by_field_name("object")
        .filter(|object| object.kind() == "call");
    let constructor_path = receiver_call
        .and_then(|call| call.child_by_field_name("function"))
        .and_then(|callee| dotted_path(callee, source));
    let Some([root, method]) = constructor_path.as_deref() else {
        return false;
    };
    root == "tmp" && TMP_HANDLE_CONSTRUCTORS.contains(&method.as_str())
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
    cwd: CommandCwdContext<'_>,
    ctx: ExecContext,
    state: &ScopeState,
) -> PermissionResult {
    let Some(method) = path.get(1) else {
        return ask("Pyrun command root requires a program".to_string());
    };

    let (program, arg_nodes) = if method == "command" || method == "cmd" {
        let Some(program) = arguments
            .first()
            .and_then(|argument| resolve_static_string(*argument, source, state))
        else {
            return ask("Pyrun command name is dynamic".to_string());
        };
        (program, &arguments[1..])
    } else {
        (method.replace('_', "-"), arguments)
    };

    let Some(args) = resolve_command_arguments(&program, arg_nodes, source, state) else {
        return ask(format!("Pyrun command {} has dynamic arguments", program));
    };

    let result = if cwd.unresolved {
        analysis::analyze_literal_command_with_unresolved_cwd(&program, &args, config, ctx)
    } else {
        analysis::analyze_literal_command(
            &program,
            &args,
            config,
            ctx,
            cwd.virtual_cwd,
            cwd.initial_cwd,
        )
    };
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

fn analyze_assignment(
    node: Node<'_>,
    source: &[u8],
    state: &mut ScopeState,
) -> Option<PermissionResult> {
    let target = node.child_by_field_name("left")?;
    let Some(name) = identifier_name(target, source) else {
        return root_name(target, source)
            .filter(|root| RESERVED_ROOTS.contains(&root.as_str()))
            .map(|root| ask(format!("Pyrun helper rebinding on {}", root)));
    };
    if RESERVED_ROOTS.contains(&name.as_str()) {
        return analyze_reserved_assignment(node, source, state, &name);
    }

    let is_first_assignment = state.assigned_names.insert(name.clone());
    clear_known_argument(state, &name);
    record_known_assignment(node, source, state, name, is_first_assignment);
    assignment_alias_result(node, source)
}

fn analyze_reserved_assignment(
    node: Node<'_>,
    source: &[u8],
    state: &mut ScopeState,
    name: &str,
) -> Option<PermissionResult> {
    match name {
        "obj" if is_safe_obj_shadow_assignment(node, source) => {
            state.obj_shadowed = true;
            None
        }
        "obj" => {
            state.obj_shadowed = false;
            Some(ask("Pyrun helper rebinding on obj".to_string()))
        }
        "text" if is_proven_text_assignment(node, source, state) => {
            state.local_text_is_string = true;
            None
        }
        "text" => {
            state.local_text_is_string = false;
            Some(ask("Pyrun helper rebinding on text".to_string()))
        }
        _ => Some(ask(format!("Pyrun helper rebinding on {}", name))),
    }
}

fn record_known_assignment(
    node: Node<'_>,
    source: &[u8],
    state: &mut ScopeState,
    name: String,
    is_first_assignment: bool,
) {
    if is_first_assignment
        && let Some(collection) = known_argument_collection_from_assignment(node, source)
    {
        state
            .known_argument_collections
            .insert(name.clone(), collection);
    }
    if let Some(argument) = known_argument_from_assignment(node, source, state) {
        state.known_arguments.insert(name, argument);
    }
}

fn identifier_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    (node.kind() == "identifier")
        .then(|| node.utf8_text(source).ok().map(str::to_string))
        .flatten()
}

fn known_argument_collection_from_assignment(
    node: Node<'_>,
    source: &[u8],
) -> Option<Vec<Vec<KnownArgument>>> {
    if node.kind() != "assignment" {
        return None;
    }
    literal_argument_lists(node.child_by_field_name("right")?, source)
}

fn known_argument_from_assignment(
    node: Node<'_>,
    source: &[u8],
    state: &ScopeState,
) -> Option<KnownArgument> {
    if node.kind() != "assignment" {
        return None;
    }
    let value = node.child_by_field_name("right")?;
    if let Some(literal) = literal_string(value, source) {
        return Some(KnownArgument::Literal(literal));
    }
    is_kubernetes_resource_name_expression(value, source, state)
        .then_some(KnownArgument::KubernetesResourceName)
}

fn assignment_alias_result(node: Node<'_>, source: &[u8]) -> Option<PermissionResult> {
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

fn is_safe_obj_shadow_assignment(node: Node<'_>, source: &[u8]) -> bool {
    let Some(value) = node.child_by_field_name("right") else {
        return false;
    };
    let Some(function) = value.child_by_field_name("function") else {
        return false;
    };
    dotted_path(function, source)
        .is_some_and(|path| path == ["json".to_string(), "loads".to_string()])
}

fn is_proven_text_assignment(node: Node<'_>, source: &[u8], state: &ScopeState) -> bool {
    if node.kind() != "assignment" {
        return false;
    }
    node.child_by_field_name("right")
        .is_some_and(|value| is_proven_string_expression(value, source, state))
}

fn is_safe_local_text_call(call: Node<'_>, source: &[u8], state: &ScopeState) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let Some(receiver) = function.child_by_field_name("object") else {
        return false;
    };
    if !is_proven_string_expression(receiver, source, state) {
        return false;
    }
    let arguments = call_arguments(call);
    match attribute_name(function, source).as_deref() {
        Some("strip") => arguments.is_empty(),
        Some("endswith") => {
            matches!(arguments.as_slice(), [argument] if literal_string(*argument, source).is_some())
        }
        _ => false,
    }
}

fn is_proven_string_expression(node: Node<'_>, source: &[u8], state: &ScopeState) -> bool {
    if literal_string(node, source).is_some() {
        return true;
    }
    if identifier_name(node, source).as_deref() == Some("text") {
        return state.local_text_is_string;
    }
    is_string_transform_call(node, source, state)
}

fn is_string_transform_call(call: Node<'_>, source: &[u8], state: &ScopeState) -> bool {
    if call.kind() != "call" {
        return false;
    }
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let Some(receiver) = function.child_by_field_name("object") else {
        return false;
    };
    if !is_proven_string_expression(receiver, source, state) {
        return false;
    }
    let arguments = call_arguments(call);
    match attribute_name(function, source).as_deref() {
        Some("join") => arguments.len() == 1,
        Some("strip") => arguments.is_empty(),
        _ => false,
    }
}

fn is_command_stdout_strip_call(function: Node<'_>, arguments: &[Node<'_>], source: &[u8]) -> bool {
    if !arguments.is_empty() {
        return false;
    }
    let Some(call) = function.parent() else {
        return false;
    };
    same_node(call.child_by_field_name("function"), Some(function))
        && command_stdout_strip_source(call, source).is_some()
}

fn is_kubernetes_resource_name_expression(
    value: Node<'_>,
    source: &[u8],
    state: &ScopeState,
) -> bool {
    let Some(command_call) = command_stdout_strip_source(value, source) else {
        return false;
    };
    let Some(function) = command_call.child_by_field_name("function") else {
        return false;
    };
    let Some(path) = dotted_path(function, source) else {
        return false;
    };
    if !matches!(path.as_slice(), [root, command] if root == "cli" && command == "kubectl") {
        return false;
    }

    let arguments = call_arguments(command_call);
    let Some(arguments) = resolve_known_arguments(&arguments, source, state) else {
        return false;
    };
    let Some(arguments) = literal_known_arguments(&arguments) else {
        return false;
    };
    is_kubernetes_resource_name_query(&arguments)
}

fn command_stdout_strip_source<'a>(call: Node<'a>, source: &[u8]) -> Option<Node<'a>> {
    let stdout = zero_argument_method_receiver(call, "strip", source)?;
    let run_call = attribute_receiver(stdout, "stdout", source)?;
    let capture_call = zero_argument_method_receiver(run_call, "run", source)?;
    zero_argument_method_receiver(capture_call, "capture", source)
}

fn zero_argument_method_receiver<'a>(
    call: Node<'a>,
    method: &str,
    source: &[u8],
) -> Option<Node<'a>> {
    if call.kind() != "call" || !call_arguments(call).is_empty() {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    if attribute_name(function, source).as_deref() != Some(method) {
        return None;
    }
    function.child_by_field_name("object")
}

fn attribute_receiver<'a>(attribute: Node<'a>, name: &str, source: &[u8]) -> Option<Node<'a>> {
    if attribute.kind() != "attribute" || attribute_name(attribute, source).as_deref() != Some(name)
    {
        return None;
    }
    attribute.child_by_field_name("object")
}

fn is_kubernetes_resource_name_query(arguments: &[String]) -> bool {
    let is_get_pods = matches!(
        (
            arguments.first().map(String::as_str),
            arguments.get(1).map(String::as_str)
        ),
        (Some("get"), Some("pod" | "pods"))
    );
    is_get_pods && requests_kubernetes_name_jsonpath(arguments)
}

fn requests_kubernetes_name_jsonpath(arguments: &[String]) -> bool {
    arguments.windows(2).any(|pair| {
        matches!(pair[0].as_str(), "-o" | "--output") && is_kubernetes_name_jsonpath(&pair[1])
    }) || arguments.iter().any(|argument| {
        argument
            .strip_prefix("--output=")
            .is_some_and(is_kubernetes_name_jsonpath)
    })
}

fn is_kubernetes_name_jsonpath(value: &str) -> bool {
    value == KUBERNETES_NAME_JSONPATH
}

fn builder_cwd_after_call(
    call: Node<'_>,
    source: &[u8],
    session_cwd: Option<&str>,
    state: &ScopeState,
) -> Result<Option<String>, CommandCwdError> {
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
                state,
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
    state: &ScopeState,
) -> Result<String, CommandCwdError> {
    let arguments = call_arguments(call);
    if arguments.len() != 1 {
        return Err(CommandCwdError::Invalid(format!(
            "Pyrun command {} requires exactly one cwd argument",
            method
        )));
    }
    let path =
        first_static_string_argument(&arguments, source, state).ok_or(CommandCwdError::Dynamic)?;
    path::resolve_path(&path, session_cwd, None).ok_or_else(|| {
        CommandCwdError::Invalid(format!("Pyrun command {} cwd cannot be resolved", method))
    })
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

fn first_static_string_argument(
    arguments: &[Node<'_>],
    source: &[u8],
    state: &ScopeState,
) -> Option<String> {
    let [argument] = arguments else {
        return None;
    };
    resolve_static_string(*argument, source, state)
}

fn resolve_command_arguments(
    program: &str,
    arguments: &[Node<'_>],
    source: &[u8],
    state: &ScopeState,
) -> Option<Vec<String>> {
    let arguments = resolve_known_arguments(arguments, source, state)?;
    if let Some(literals) = literal_known_arguments(&arguments) {
        return Some(literals);
    }
    allows_kubernetes_resource_arguments(program, &arguments)
        .then(|| materialize_known_arguments(arguments))
}

fn resolve_known_arguments(
    arguments: &[Node<'_>],
    source: &[u8],
    state: &ScopeState,
) -> Option<Vec<KnownArgument>> {
    if arguments.len() == 1 && arguments[0].kind() == "list_splat" {
        return resolve_known_argument_splat(arguments[0], source, state);
    }
    arguments
        .iter()
        .map(|argument| resolve_known_argument(*argument, source, state))
        .collect()
}

fn resolve_known_argument_splat(
    splat: Node<'_>,
    source: &[u8],
    state: &ScopeState,
) -> Option<Vec<KnownArgument>> {
    let mut cursor = splat.walk();
    let value = splat.named_children(&mut cursor).next()?;
    let name = identifier_name(value, source)?;
    state.known_argument_lists.get(&name).cloned()
}

fn resolve_static_string(argument: Node<'_>, source: &[u8], state: &ScopeState) -> Option<String> {
    match resolve_known_argument(argument, source, state)? {
        KnownArgument::Literal(program) => Some(program),
        KnownArgument::KubernetesResourceName => None,
    }
}

fn resolve_known_argument(
    argument: Node<'_>,
    source: &[u8],
    state: &ScopeState,
) -> Option<KnownArgument> {
    if let Some(literal) = literal_string(argument, source) {
        return Some(KnownArgument::Literal(literal));
    }
    let name = identifier_name(argument, source)?;
    state.known_arguments.get(&name).cloned()
}

fn literal_known_arguments(arguments: &[KnownArgument]) -> Option<Vec<String>> {
    arguments
        .iter()
        .map(|argument| match argument {
            KnownArgument::Literal(value) => Some(value.clone()),
            KnownArgument::KubernetesResourceName => None,
        })
        .collect()
}

fn allows_kubernetes_resource_arguments(program: &str, arguments: &[KnownArgument]) -> bool {
    let command = program.rsplit('/').next().unwrap_or(program);
    let Some(KnownArgument::Literal(subcommand)) = arguments.first() else {
        return false;
    };
    command == "kubectl"
        && matches!(subcommand.as_str(), "logs" | "top")
        && arguments
            .iter()
            .any(|argument| matches!(argument, KnownArgument::KubernetesResourceName))
}

fn materialize_known_arguments(arguments: Vec<KnownArgument>) -> Vec<String> {
    arguments
        .into_iter()
        .map(|argument| match argument {
            KnownArgument::Literal(value) => value,
            KnownArgument::KubernetesResourceName => KUBERNETES_RESOURCE_PLACEHOLDER.to_string(),
        })
        .collect()
}

fn literal_string(node: Node<'_>, source: &[u8]) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let text = node.utf8_text(source).ok()?.trim();
    decode_python_string_body(plain_python_string_body(text)?)
}

fn plain_python_string_body(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let quote = *bytes.first()?;
    if bytes.len() < 2 || !matches!(quote, b'\'' | b'"') {
        return None;
    }
    if bytes.last().copied() != Some(quote) {
        return None;
    }
    if bytes.get(1) == Some(&quote) && bytes.get(2) == Some(&quote) {
        return None;
    }
    Some(&text[1..text.len() - 1])
}

fn decode_python_string_body(raw: &str) -> Option<String> {
    if !raw.contains('\\') {
        return Some(raw.to_string());
    }
    let mut output = String::with_capacity(raw.len());
    let mut characters = raw.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\\' {
            decode_python_escape(&mut characters, &mut output)?;
        } else {
            output.push(character);
        }
    }
    Some(output)
}

fn decode_python_escape(
    characters: &mut std::iter::Peekable<std::str::Chars<'_>>,
    output: &mut String,
) -> Option<()> {
    match characters.next()? {
        '\\' => output.push('\\'),
        '\'' => output.push('\''),
        '"' => output.push('"'),
        'a' => output.push('\u{0007}'),
        'b' => output.push('\u{0008}'),
        'f' => output.push('\u{000c}'),
        'n' => output.push('\n'),
        'r' => output.push('\r'),
        't' => output.push('\t'),
        'v' => output.push('\u{000b}'),
        '\n' => {}
        '\r' if characters.next() == Some('\n') => {}
        _ => return None,
    }
    Some(())
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
