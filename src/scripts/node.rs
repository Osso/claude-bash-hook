//! Node.js inline script analysis for `node -e` / `node -p` (`--eval`/`--print`).
//!
//! Node's API is too large to allowlist, so we use a denylist: inline code that
//! writes/deletes files, opens the network, or evals code is routed to `ask`.
//!
//! Process execution is handled one level deeper: instead of blindly asking on
//! any `child_process` use, we extract the argv of every `execFile`/`spawn`-family
//! call and re-check each spawned command through the normal config rule engine.
//! A script that only shells out to commands the config already allows (e.g.
//! `code-index`) is therefore allowed too. Shell-string forms (`exec`/`execSync`),
//! aliased/dynamic spawns, and anything we cannot fully resolve fall back to
//! `ask`. Code we cannot extract returns `None`, falling through to a prompt.

use crate::analyzer::Command;
use crate::config::{Config, ExecContext, Permission, PermissionResult};
use regex::Regex;
use std::sync::OnceLock;

/// Side effects we cannot reason about — any occurrence forces a prompt.
/// Substring match (JS is case-sensitive).
const OPAQUE_PATTERNS: &[&str] = &[
    // File writes / deletion (fs.*)
    "writeFile",
    "appendFile",
    "createWriteStream",
    "unlink",
    "rmdir",
    "rmSync",
    ".rm(",
    "mkdir",
    "mkdtemp",
    "rename",
    "truncate",
    "chmod",
    "chown",
    "symlink",
    "copyFile",
    "utimes",
    "writeSync",
    // Code execution
    "eval(",
    "Function(",
    "import(",
    // Network
    "require('http",
    "require(\"http",
    "require('net')",
    "require(\"net\")",
    "require('dgram",
    "require(\"dgram",
    "node:http",
    "node:net",
    "node:dgram",
    ".request(",
    ".createServer(",
    ".connect(",
    "fetch(",
    // Process execution we cannot introspect: a shell-string command line
    // (`exec`/`execSync`/RegExp `.exec(`) or a raw signal.
    "execSync",
    ".exec(",
    "process.kill",
];

/// Spawn calls whose argv we *can* extract: `fn("bin", ["arg", ...])`.
/// Ordered longest-first so `execFileSync` wins over `execFile`.
fn call_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:execFileSync|execFile|spawnSync|spawn)\s*\(").unwrap())
}

/// Outcome of scanning for process-spawning calls.
enum ExecScan {
    /// No process execution at all — the script is read-only.
    None,
    /// Every spawn site resolved to a literal `(binary, args)`.
    Calls(Vec<(String, Vec<String>)>),
    /// Spawn-like usage we could not fully resolve (dynamic/aliased/shell form).
    Unparseable,
}

/// Extract all `-e`/`--eval`/`-p`/`--print` code fragments.
fn extract_node_code(cmd: &Command) -> Option<String> {
    let mut pieces: Vec<String> = Vec::new();
    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-e" | "--eval" | "-p" | "--print" => {
                if let Some(code) = iter.next() {
                    pieces.push(code.clone());
                }
            }
            _ => {
                for prefix in ["--eval=", "--print=", "-e", "-p"] {
                    if let Some(code) = arg.strip_prefix(prefix) {
                        if !code.is_empty() {
                            pieces.push(code.to_string());
                        }
                        break;
                    }
                }
            }
        }
    }

    (!pieces.is_empty()).then(|| pieces.join("\n"))
}

/// Minimal JS-literal scanner positioned just inside a spawn call's `(`.
struct CallParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> CallParser<'a> {
    fn new(code: &'a str, start: usize) -> Self {
        CallParser {
            b: code.as_bytes(),
            i: start,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(c) if (c as char).is_whitespace()) {
            self.i += 1;
        }
    }

    /// Read a `'...'`, `"..."`, or plain `` `...` `` literal. Rejects template
    /// interpolation (`${`) since the value is then dynamic.
    fn read_string(&mut self) -> Option<String> {
        let quote = self.peek()?;
        if !matches!(quote, b'\'' | b'"' | b'`') {
            return None;
        }
        self.i += 1;
        let start = self.i;
        while let Some(c) = self.peek() {
            match c {
                b'\\' => {
                    self.i += 2;
                    continue;
                }
                b'$' if quote == b'`' && self.b.get(self.i + 1) == Some(&b'{') => return None,
                c if c == quote => {
                    let raw = String::from_utf8_lossy(&self.b[start..self.i]).into_owned();
                    self.i += 1;
                    return Some(unescape(&raw));
                }
                _ => self.i += 1,
            }
        }
        None
    }

    /// Read a `[ "a", "b" ]` array of string literals. Any non-literal element
    /// makes the call unresolvable.
    fn read_string_array(&mut self) -> Option<Vec<String>> {
        if self.peek() != Some(b'[') {
            return None;
        }
        self.i += 1;
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            match self.peek()? {
                b']' => {
                    self.i += 1;
                    return Some(out);
                }
                b',' => self.i += 1,
                b'\'' | b'"' | b'`' => out.push(self.read_string()?),
                _ => return None,
            }
        }
    }

    /// Parse `("bin")`, `("bin", ["args"])`, or `("bin", <opts>)`. Returns the
    /// command argv, or `None` if the binary isn't a literal we can resolve.
    fn parse(&mut self) -> Option<(String, Vec<String>)> {
        self.skip_ws();
        let binary = self.read_string()?;
        self.skip_ws();
        match self.peek() {
            Some(b')') => Some((binary, Vec::new())),
            Some(b',') => {
                self.i += 1;
                self.skip_ws();
                // A literal argv array gives us the real arguments; any other
                // second argument (options object, variable) leaves argv empty,
                // which still lets a broad bare-command rule match.
                if self.peek() == Some(b'[') {
                    let args = self.read_string_array()?;
                    Some((binary, args))
                } else {
                    Some((binary, Vec::new()))
                }
            }
            _ => None,
        }
    }
}

/// Resolve `\\`-escapes in a string literal body (enough for command argv).
fn unescape(raw: &str) -> String {
    if !raw.contains('\\') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn scan_exec_calls(code: &str) -> ExecScan {
    let mut calls = Vec::new();
    let mut found = false;
    for m in call_regex().find_iter(code) {
        found = true;
        match CallParser::new(code, m.end()).parse() {
            Some(call) => calls.push(call),
            None => return ExecScan::Unparseable,
        }
    }
    if found {
        return ExecScan::Calls(calls);
    }
    // The module is imported but no call site was recognized: the spawn must be
    // aliased or built dynamically, which we can't vet.
    if code.contains("child_process") {
        return ExecScan::Unparseable;
    }
    ExecScan::None
}

/// Is `bin args...` allowed by config in either the virtual or initial cwd?
fn command_allowed(
    config: &Config,
    bin: &str,
    args: &[String],
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> bool {
    if config
        .check_command_with_cwd(bin, args, virtual_cwd, ctx)
        .permission
        == Permission::Allow
    {
        return true;
    }
    if initial_cwd != virtual_cwd
        && config
            .check_command_with_cwd(bin, args, initial_cwd, ctx)
            .permission
            == Permission::Allow
    {
        return true;
    }
    false
}

fn allow(reason: &str) -> PermissionResult {
    PermissionResult {
        permission: Permission::Allow,
        reason: reason.to_string(),
        suggestion: None,
    }
}

fn ask(reason: &str) -> PermissionResult {
    PermissionResult {
        permission: Permission::Ask,
        reason: reason.to_string(),
        suggestion: None,
    }
}

/// Check whether a node command runs side-effecting inline code.
pub fn check_node_script(
    cmd: &Command,
    config: &Config,
    virtual_cwd: Option<&str>,
    initial_cwd: Option<&str>,
    ctx: ExecContext,
) -> Option<PermissionResult> {
    if cmd.name != "node" && cmd.name != "nodejs" {
        return None;
    }
    let code = extract_node_code(cmd)?;

    if OPAQUE_PATTERNS.iter().any(|p| code.contains(p)) {
        return Some(ask("Node script may have side effects"));
    }

    Some(match scan_exec_calls(&code) {
        ExecScan::None => allow("read-only Node script"),
        ExecScan::Unparseable => ask("Node script spawns an unrecognized command"),
        ExecScan::Calls(calls) => {
            if calls.iter().all(|(bin, args)| {
                command_allowed(config, bin, args, virtual_cwd, initial_cwd, ctx)
            }) {
                allow("Node script only spawns allowed commands")
            } else {
                ask("Node script spawns a command requiring approval")
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "node".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Config that allows `code-index` (and the `code-index list` subcommand).
    fn config_allowing(commands: &[&str]) -> Config {
        let list = commands
            .iter()
            .map(|c| format!("\"{}\"", c))
            .collect::<Vec<_>>()
            .join(", ");
        let toml = format!(
            r#"
            default = "ask"
            [[rules]]
            commands = [{}]
            permission = "allow"
            reason = "test allow"
        "#,
            list
        );
        toml::from_str(&toml).unwrap()
    }

    fn check(cmd: &Command, config: &Config) -> PermissionResult {
        check_node_script(cmd, config, None, None, ExecContext::default()).unwrap()
    }

    #[test]
    fn test_console_log_allowed() {
        let cmd = make_cmd(&["-e", "console.log(1+1)"]);
        assert_eq!(
            check(&cmd, &config_allowing(&[])).permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_read_file_allowed() {
        let cmd = make_cmd(&[
            "-e",
            "console.log(require('fs').readFileSync('/etc/hosts','utf8'))",
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&[])).permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_write_file_asks() {
        let cmd = make_cmd(&["-e", "require('fs').writeFileSync('/usr/bin/evil','x')"]);
        assert_eq!(
            check(&cmd, &config_allowing(&[])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_unlink_asks() {
        let cmd = make_cmd(&["-e", "require('fs').unlinkSync('/usr/bin/foo')"]);
        assert_eq!(
            check(&cmd, &config_allowing(&[])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_fetch_asks() {
        let cmd = make_cmd(&["-e", "fetch('http://example.com')"]);
        assert_eq!(
            check(&cmd, &config_allowing(&[])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_print_flag_extracted() {
        let cmd = make_cmd(&["-p", "require('fs').writeFileSync('/usr/x','y')"]);
        assert_eq!(
            check(&cmd, &config_allowing(&[])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_eval_long_flag_extracted() {
        let cmd = make_cmd(&["--eval", "console.log(process.version)"]);
        assert_eq!(
            check(&cmd, &config_allowing(&[])).permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_glued_eval_extracted() {
        let cmd = make_cmd(&["-econsole.log(1)"]);
        assert_eq!(
            check(&cmd, &config_allowing(&[])).permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_no_inline_code_returns_none() {
        let cmd = make_cmd(&["script.js"]);
        assert!(
            check_node_script(
                &cmd,
                &config_allowing(&[]),
                None,
                None,
                ExecContext::default()
            )
            .is_none()
        );
    }

    #[test]
    fn test_not_node_returns_none() {
        let cmd = Command {
            name: "ruby".to_string(),
            args: vec!["-e".to_string(), "puts 1".to_string()],
        };
        assert!(
            check_node_script(
                &cmd,
                &config_allowing(&[]),
                None,
                None,
                ExecContext::default()
            )
            .is_none()
        );
    }

    // --- process-execution introspection ---

    #[test]
    fn test_execfilesync_allowed_command_allows() {
        let cmd = make_cmd(&[
            "-e",
            r#"const cp=require("child_process"); cp.execFileSync("code-index",["list","--kind","function"]);"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index"])).permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_execfilesync_disallowed_command_asks() {
        let cmd = make_cmd(&[
            "-e",
            r#"require("child_process").execFileSync("rm",["-rf","/"]);"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index"])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_subcommand_rule_matches_argv() {
        // Rule allows only the `code-index list` subcommand.
        let cmd = make_cmd(&[
            "-e",
            r#"require("child_process").execFileSync("code-index",["list"]);"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index list"])).permission,
            Permission::Allow
        );
        let other = make_cmd(&[
            "-e",
            r#"require("child_process").execFileSync("code-index",["untested"]);"#,
        ]);
        assert_eq!(
            check(&other, &config_allowing(&["code-index list"])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_multiple_calls_all_allowed() {
        let cmd = make_cmd(&[
            "-e",
            r#"const cp=require("child_process");
               cp.execFileSync("code-index",["list"]);
               cp.execFileSync("code-index",["untested"]);"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index"])).permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_one_disallowed_among_many_asks() {
        let cmd = make_cmd(&[
            "-e",
            r#"const cp=require("child_process");
               cp.execFileSync("code-index",["list"]);
               cp.execFileSync("curl",["http://evil"]);"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index"])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_execsync_shell_string_asks() {
        let cmd = make_cmd(&[
            "-e",
            r#"require("child_process").execSync("code-index list");"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index"])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_dynamic_binary_asks() {
        let cmd = make_cmd(&[
            "-e",
            r#"const b="code-index"; require("child_process").execFileSync(b,["list"]);"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index"])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_template_interpolation_binary_asks() {
        let cmd = make_cmd(&[
            "-e",
            r#"require("child_process").execFileSync(`code-${x}`,["list"]);"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index"])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_non_literal_arg_element_asks() {
        let cmd = make_cmd(&[
            "-e",
            r#"require("child_process").execFileSync("code-index",["list",userInput]);"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index"])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_child_process_imported_but_aliased_asks() {
        let cmd = make_cmd(&[
            "-e",
            r#"const e=require("child_process").execFileSync; runIt(e);"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index"])).permission,
            Permission::Ask
        );
    }

    #[test]
    fn test_spawnsync_allowed() {
        let cmd = make_cmd(&[
            "-e",
            r#"require("child_process").spawnSync("code-index",["list"]);"#,
        ]);
        assert_eq!(
            check(&cmd, &config_allowing(&["code-index"])).permission,
            Permission::Allow
        );
    }
}
