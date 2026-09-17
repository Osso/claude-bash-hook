# Pyrun permissions

Pyrun permission analysis defines the PreToolUse decision for a complete `pyrun_eval` program before Pyrun evaluates it. The contract is exercised by tests in [`src/tool_handlers/tests/pyrun.rs`](../../src/tool_handlers/tests/pyrun.rs); implementation references are [`src/scripts/pyrun.rs`](../../src/scripts/pyrun.rs) and [`src/scripts/pyrun/path.rs`](../../src/scripts/pyrun/path.rs).

## What it must do

### Approval boundary

- [ ] Make one whole-tool permission decision for each `pyrun_eval` call before evaluation; do not invoke the hook binary or request nested approvals for individual AST calls.
- [x] Deny syntactically invalid Python/Pyrun code before helper analysis.
- [x] Aggregate findings from the complete program instead of approving only the first helper call.

### Commands and context

- [x] Analyze `run.*` and `cli.*` commands with the existing literal-command policy, including configured command permissions and main-thread restrictions.
- [x] Resolve same-scope, source-ordered local string assignments when used directly as a command program or argument; later, augmented, conditional, or unknown reassignment invalidates the value.
- [x] Allow a Kubernetes resource name only when it comes from the exact read-only `kubectl get pod(s) -o jsonpath={.items[0].metadata.name}` captured-stdout `.strip()` flow, and only as an argument to `kubectl logs` or `kubectl top`.
- [x] Unroll at most 32 iterations of literal-string argv tuples when a `for` loop uses either an inline literal list/tuple or a first, same-scope, source-ordered assignment of that bounded collection; the loop variable must be the sole direct `*args` command argument, and each expanded command still receives its normal policy decision.
- [x] Require inline literal or proven same-scope static-string command names. Decode ordinary unprefixed single/double-quoted Python strings before policy, supporting `\\`, escaped quotes, `\\a`, `\\b`, `\\f`, `\\n`, `\\r`, `\\t`, `\\v`, and physical LF/CRLF continuations. Other escape forms and string syntaxes ask.
- [x] Named argv collections are single-use loop provenance: aliases, reassignment, augmented assignment, other reads/escapes, body references, computed iterables or members, and unsupported literals ask.
- [x] Resolve a builder `cwd`/`in_` value when it is an inline literal or proven same-scope static string. A single unresolved value discards the builder cwd and evaluates literal command arguments under global/no-cwd policy, but recognized relative filesystem write targets ask before a global Allow can apply. Global Ask/Deny remains authoritative and cwd-scoped rules cannot match. Malformed calls and statically invalid paths ask.
- [x] Classify literal `kubectl wait` as a read-only/watch operation through command policy.
- [x] Resolve relative command working directories from the Pyrun session context and reanalyze the command under the proven builder cwd.
- [x] Preserve the distinction between the tool-provided virtual cwd and the hook's initial cwd when resolving command and path policy.
- [x] Apply aggregation ordering `deny > ask > allow` with a behavioral test covering a deny and ask in the same program.

### Filesystem and output paths

- [x] Allow safe literal filesystem reads unless the resolved path is protected by `ask_paths`.
- [x] Treat filesystem writes and removals as modifying operations subject to existing path and command policy.
- [x] Allow writes and command output under `/tmp` and the resolved project/session cwd when no stricter policy denies them.
- [x] Honor configured write-allow paths for writes and output, `ask_paths` for reads and all modifying operations, and `ask_write_paths` for modifying operations.
- [x] Analyze `cli.*.output(...)` as a write to the session cwd; a builder cwd does not change output-path resolution.
- [x] Ask when unresolved builder cwd leaves a recognized relative write target for `cp`/`mv`-family commands, path-creating and in-place commands, `rm`, `tee`, or `tar`; absolute write targets and resolved builder cwd continue through normal policy.
- [x] Ask when paths are dynamic, contain parent-directory traversal, use unsupported tilde expansion, cannot be safely resolved, or traverse broken/out-of-tree symlinks.
- [x] Reuse the existing `touch` policy for filesystem writes and command output, and the existing `rm` policy for filesystem removal.
- [x] Analyze `tools.file.replace(path, ...)`, two-argument `tools.file.patch(path, patch)`, and `tmp.file`/`tmp.dir` (as `/tmp` targets, including chained handle methods) with the same write-path policy as `fs.write`, so edit mode allows in-cwd and `/tmp` targets. Single-argument `tools.file.patch` with an embedded target path asks.

### Helpers and fail-closed behavior

- [x] Allow only the tested read-only helper surface for `rg`, `fd`, `text`, `seq`, `obj`, and `hr`.
- [x] Allow a local `obj` assigned from static `json.loads(...)` to shadow Pyrun's pure `obj` namespace within the same lexical scope and only after that assignment, so ordinary read-only dictionary calls and chained `.get()` calls do not prompt.
- [x] Allow local `text` to shadow Pyrun's pure `text` namespace only after assignment from a proven built-in string expression; permit the required literal-separator `join` → zero-argument `strip` → literal `endswith` flow.
- [x] Restore `Ask` after arbitrary or unsafe reassignment of local `obj` or `text`; unsupported calls on proven local `text` strings, including introspection, also ask. Genuine unshadowed Pyrun helpers remain governed by their helper policy.
- [x] Ask for network, privileged, bridge, command-adjacent, or otherwise side-effecting helper roots such as `http`, `tools`, `kubectl`, `sqlite`, `pi`, and `tmp`, except the file-editing helpers covered by the write-path rule above.
- [x] Ask for dynamic access, reserved-helper rebinding or aliasing, unknown helper methods, and unsupported helper literals, except for the static `json.loads(...)` local-`obj` shadowing rule above.
- [x] Ask for every statically unknown Pyrun command and filesystem method with dedicated behavioral coverage.

## How it works

- [`src/scripts/pyrun.rs`](../../src/scripts/pyrun.rs) owns the Pyrun-specific AST permission contract.
- [`src/scripts/pyrun/path.rs`](../../src/scripts/pyrun/path.rs) owns filesystem and command-output path policy.
- [`src/analysis.rs`](../../src/analysis.rs) owns literal command and shared permission-policy reuse.
- [`src/tool_handlers.rs`](../../src/tool_handlers.rs) connects `pyrun_eval` to the single PreToolUse decision.

## Implementation inventory

- `src/scripts/pyrun.rs` — parses one complete Pyrun program, classifies helper calls, and aggregates permission findings.
- `src/scripts/pyrun/path.rs` — applies filesystem and command-output path policy.
- `src/tool_handlers.rs` — recognizes Pyrun tool names, supplies cwd/context, and emits the hook decision.
- `src/analysis.rs` — analyzes literal commands, command output targets, and permission-mode effects reused by Pyrun.
- `src/config/mod.rs` — provides command rules and protected/read/write path matching.
- `src/scripts/mod.rs` — registers the Pyrun analyzer module.
- `Cargo.toml` / `Cargo.lock` — provide the Python tree-sitter parser dependency.

## Tests asserting this spec

- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_syntax_error_denies`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_run_git_diff_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_run_rm_etc_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_literal_run_command_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_dynamic_command_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_unknown_command_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_cli_relative_cwd_resolves_from_session_cwd`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_cli_literal_cwd_reanalyzes_relative_command`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_host_cd_invalidates_relative_path_context`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_safe_fs_read_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_protected_fs_read_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_tmp_write_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_protected_write_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_protected_remove_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_unknown_filesystem_method_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_cli_output_protected_path_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_http_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_tools_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_pi_bridge_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_selects_most_restrictive_call`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_deny_wins_over_ask`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_rebinding_reserved_helper_target_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_json_loaded_obj_shadow_allows_reported_read_only_shape`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_json_loaded_obj_shadow_is_scope_and_order_aware`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_unshadowed_obj_namespace_stays_allowed`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_reported_local_text_shadow_allows_read_only_scan`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_local_text_shadow_remains_fail_closed`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_reported_static_mysql_query_variable_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_static_prod_rw_select_variable_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_reported_kubectl_resource_name_flow_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_reported_kubectl_wait_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_reported_literal_loop_command_splat_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_reported_string_escape_jsonpath_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_supported_string_escapes_preserve_policy`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_unsupported_string_escape_forms_fail_closed`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_reported_static_loop_collection_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_static_loop_collection_remains_fail_closed`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_static_loop_collection_mutation_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_static_loop_collection_preserves_command_policy`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_static_loop_collection_limits_ask`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_literal_loop_splat_preserves_command_policy`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_reported_static_command_name_with_loop_splat_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_static_command_name_preserves_command_policy`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_reported_static_variable_cwd_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_static_variable_in_cwd_allows`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_reported_cwd_after_if_uses_global_git_policy`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_dynamic_cwd_relative_write_targets_ask`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_dynamic_cwd_absolute_write_targets_use_global_policy`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_resolved_cwd_relative_write_target_uses_global_policy`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_cli_dynamic_cwd_preserves_global_ask`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_cli_dynamic_in_uses_global_allow_policy`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_dynamic_cwd_cannot_satisfy_cwd_scoped_rule`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_dynamic_cwd_preserves_global_deny`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_dynamic_cwd_does_not_allow_dynamic_commands_or_arguments`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_malformed_cwd_call_asks`
- `src/tool_handlers/tests/pyrun.rs::test_pyrun_eval_dynamic_cwd_preserves_git_safeguards`
- Remaining `test_pyrun_eval_*` cases in `src/tool_handlers/tests/pyrun.rs` cover dynamic access, reassignment, aliases, unsupported literals and splats, path normalization, symlinks, and pure-helper allowlists.

## Known gaps (current cycle)

- [ ] Add an integration test asserting the emitted PreToolUse result for a `pyrun_eval` call, proving the whole program receives one hook decision.
- [ ] Add a project-level wiki page if implementation details need documentation beyond this contract.

## Out of scope

- Nested Pi/Pyrun approval or continuation protocols for individual helper calls.
- Full semantic proof of arbitrary Python behavior, including full Python lexical, control-flow, and name-resolution analysis; trusted argument bindings are cleared across uncertain control flow.
- Auto-allowing arbitrary dynamic, computed, aliased, or f-string command, argument, filesystem, or output-path values. An unresolved builder cwd is not trusted as a path, cannot satisfy cwd-scoped policy, and cannot auto-allow recognized relative filesystem write targets; other literal commands retain their global/no-cwd decision.
- Raw, bytes, Unicode-prefixed, f-string, triple-quoted, concatenated, octal, hexadecimal, Unicode, named-Unicode, and unknown escape forms remain unsupported and fail closed.
- Unknown local rebinding remains fail-closed and restores `Ask`; only documented static string arguments, Kubernetes resource-name provenance, static `json.loads(...)` local-`obj` shadowing, and proven built-in-string local-`text` shadowing are exempt.
- Simulating `host.cd` as execution flow; `host.cd` asks instead.
- Changes to Pyrun, Pi, command configuration format, or unrelated hook analyzers.
