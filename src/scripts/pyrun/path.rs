//! Pyrun filesystem and output path policy.

use super::{allow, ask, first_literal_argument, normalize_command_result};
use crate::analysis;
use crate::config::{Config, ExecContext, Permission, PermissionResult};
use std::path::{Component, Path, PathBuf};
use tree_sitter::Node;

const WRITE_METHODS: &[&str] = &[
    "write",
    "write_json",
    "write_json_lines",
    "write_jsonl",
    "write_csv",
    "write_tsv",
];
const READ_METHODS: &[&str] = &["read", "open", "exists", "glob"];

pub(super) fn analyze_filesystem_call(
    method: &str,
    arguments: &[Node<'_>],
    source: &[u8],
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> PermissionResult {
    let path = first_literal_argument(arguments, source);
    match method {
        method if WRITE_METHODS.contains(&method) => {
            analyze_write_path(path, config, virtual_cwd, initial_cwd, ctx)
        }
        "remove" => analyze_remove_path(path, config, virtual_cwd, initial_cwd, ctx),
        method if READ_METHODS.contains(&method) => {
            analyze_read_path(path, config, virtual_cwd, initial_cwd)
        }
        method => ask(format!("unknown Pyrun filesystem helper fs.{}", method)),
    }
}

pub(super) fn analyze_write_path(
    path: Option<String>,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> PermissionResult {
    let Some(path) = path else {
        return unresolved_write(ctx, "Pyrun filesystem write path is dynamic".to_string());
    };
    if has_unsupported_tilde(&path) {
        return unresolved_write(
            ctx,
            format!(
                "Pyrun filesystem write path cannot resolve tilde expansion: {}",
                path
            ),
        );
    }
    if resolve_path(&path, virtual_cwd, initial_cwd).is_none() {
        return unresolved_write(
            ctx,
            format!(
                "Pyrun filesystem write path cannot resolve safely: {}",
                path
            ),
        );
    }
    if let Some(result) = analyze_touch_target(&path, config, virtual_cwd, initial_cwd, ctx) {
        return result;
    }
    if ctx.edit_mode || is_allowed_write_path(&path, config, virtual_cwd, initial_cwd) {
        return allow(format!("Pyrun filesystem write allowed for {}", path));
    }
    ask(format!(
        "Pyrun filesystem write requires approval for {}",
        path
    ))
}

fn analyze_remove_path(
    path: Option<String>,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> PermissionResult {
    let Some(path) = path else {
        return ask("Pyrun filesystem removal path is dynamic".to_string());
    };
    if has_unsupported_tilde(&path) {
        return ask(format!(
            "Pyrun filesystem removal path cannot resolve tilde expansion: {}",
            path
        ));
    }
    if resolve_path(&path, virtual_cwd, initial_cwd).is_none() {
        return ask(format!(
            "Pyrun filesystem removal path cannot resolve safely: {}",
            path
        ));
    }
    let args = vec![path_for_command_guard(&path, virtual_cwd, initial_cwd)];
    normalize_command_result(
        analysis::analyze_literal_command("rm", &args, config, ctx, virtual_cwd, initial_cwd),
        "rm",
    )
}

fn analyze_read_path(
    path: Option<String>,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
) -> PermissionResult {
    let Some(path) = path else {
        return ask("Pyrun filesystem read path is dynamic".to_string());
    };
    if has_unsupported_tilde(&path) {
        return ask(format!(
            "Pyrun filesystem read path cannot resolve tilde expansion: {}",
            path
        ));
    }
    let Some(absolute) = resolve_path(&path, virtual_cwd, initial_cwd) else {
        return ask(format!(
            "Pyrun filesystem read path cannot resolve safely: {}",
            path
        ));
    };
    if config.is_ask_path(&absolute) {
        return ask(format!(
            "Pyrun filesystem read targets protected path {}",
            path
        ));
    }
    allow(format!("Pyrun filesystem read {}", path))
}

pub(super) fn analyze_output_path(
    path: Option<String>,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> PermissionResult {
    let Some(path) = path else {
        return unresolved_write(ctx, "Pyrun command output path is dynamic".to_string());
    };
    if has_unsupported_tilde(&path) {
        return unresolved_write(
            ctx,
            format!(
                "Pyrun command output path cannot resolve tilde expansion: {}",
                path
            ),
        );
    }
    if resolve_path(&path, virtual_cwd, initial_cwd).is_none() {
        return unresolved_write(
            ctx,
            format!("Pyrun command output path cannot resolve safely: {}", path),
        );
    }
    if let Some(result) = analyze_touch_target(&path, config, virtual_cwd, initial_cwd, ctx) {
        return result;
    }
    if ctx.edit_mode || is_allowed_write_path(&path, config, virtual_cwd, initial_cwd) {
        return allow(format!("Pyrun command output allowed for {}", path));
    }
    ask(format!(
        "Pyrun command output requires approval for {}",
        path
    ))
}

/// Edit mode approves writes the way the Write and Edit tools do. A target
/// that never resolves to a literal path cannot be matched against configured
/// path rules, so edit mode is the only signal left.
fn unresolved_write(ctx: ExecContext, ask_reason: String) -> PermissionResult {
    if ctx.edit_mode {
        return allow("Pyrun write allowed in edit mode".to_string());
    }
    ask(ask_reason)
}

fn analyze_touch_target(
    path: &str,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> Option<PermissionResult> {
    let args = vec![path_for_command_guard(path, virtual_cwd, initial_cwd)];
    let result =
        analysis::analyze_literal_command("touch", &args, config, ctx, virtual_cwd, initial_cwd);
    if result.permission == Permission::Allow {
        None
    } else {
        Some(normalize_command_result(result, "touch"))
    }
}

fn path_for_command_guard(
    path: &str,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
) -> String {
    resolve_path(path, virtual_cwd, initial_cwd).unwrap_or_else(|| path.to_string())
}

fn is_allowed_write_path(
    path: &str,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
) -> bool {
    let Some(absolute) = resolve_path(path, virtual_cwd, initial_cwd) else {
        return false;
    };
    if absolute == "/tmp" || absolute.starts_with("/tmp/") {
        return true;
    }
    if config.is_write_allowed(&absolute) {
        return true;
    }
    [virtual_cwd, initial_cwd]
        .into_iter()
        .flatten()
        .filter_map(|cwd| resolve_path(cwd, None, None))
        .any(|cwd| is_same_or_child_path(&absolute, &cwd))
}

pub(super) fn resolve_path(
    path: &str,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
) -> Option<String> {
    if path.is_empty()
        || path.contains('\0')
        || path.contains('\n')
        || has_unsupported_tilde(path)
        || has_parent_dir_component(path)
    {
        return None;
    }
    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        let cwd = virtual_cwd.or(initial_cwd)?;
        Path::new(cwd).join(path)
    };
    let normalized = normalize_absolute_path(&candidate)?;
    resolve_existing_ancestors(Path::new(&normalized))
}

fn normalize_absolute_path(path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Prefix(_) => return None,
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if normalized != Path::new("/") {
                    normalized.pop();
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized.to_str().map(str::to_owned)
}

fn has_unsupported_tilde(path: &str) -> bool {
    path.split('/')
        .next()
        .is_some_and(|component| component.starts_with('~'))
}

fn has_parent_dir_component(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn resolve_existing_ancestors(path: &Path) -> Option<String> {
    let mut unresolved = Vec::new();
    let mut existing = path.to_path_buf();

    loop {
        if let Ok(canonical) = existing.canonicalize() {
            let mut resolved = canonical;
            for component in unresolved.iter().rev() {
                resolved.push(component);
            }
            return resolved.to_str().map(str::to_owned);
        }
        if std::fs::symlink_metadata(&existing)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return None;
        }

        let component = existing.file_name()?.to_os_string();
        unresolved.push(component);
        if !existing.pop() {
            return None;
        }
    }
}

fn is_same_or_child_path(path: &str, cwd: &str) -> bool {
    path == cwd || path.starts_with(&format!("{}/", cwd.trim_end_matches('/')))
}
