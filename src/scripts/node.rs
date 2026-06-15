//! Node.js inline script analysis for `node -e` / `node -p` (`--eval`/`--print`).
//!
//! Node's API is too large to allowlist, so we use a denylist: inline code that
//! spawns processes, writes/deletes files, or opens the network is routed to
//! `ask`; otherwise it is read-only and allowed. Code we cannot extract returns
//! `None`, falling through to normal handling (a prompt).

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Side-effecting Node.js patterns. Substring match (JS is case-sensitive).
const DANGEROUS_PATTERNS: &[&str] = &[
    // Process execution
    "child_process",
    ".exec(",
    "execSync",
    ".spawn(",
    "spawnSync",
    "execFile",
    "process.kill",
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
    "import(",
];

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

fn has_side_effect(code: &str) -> bool {
    DANGEROUS_PATTERNS.iter().any(|p| code.contains(p))
}

/// Check whether a node command runs side-effecting inline code.
pub fn check_node_script(cmd: &Command) -> Option<PermissionResult> {
    if cmd.name != "node" && cmd.name != "nodejs" {
        return None;
    }
    let code = extract_node_code(cmd)?;

    if has_side_effect(&code) {
        Some(PermissionResult {
            permission: Permission::Ask,
            reason: "Node script may have side effects".to_string(),
            suggestion: None,
        })
    } else {
        Some(PermissionResult {
            permission: Permission::Allow,
            reason: "read-only Node script".to_string(),
            suggestion: None,
        })
    }
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

    #[test]
    fn test_console_log_allowed() {
        let cmd = make_cmd(&["-e", "console.log(1+1)"]);
        assert_eq!(
            check_node_script(&cmd).unwrap().permission,
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
            check_node_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_write_file_asks() {
        let cmd = make_cmd(&["-e", "require('fs').writeFileSync('/usr/bin/evil','x')"]);
        assert_eq!(check_node_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_unlink_asks() {
        let cmd = make_cmd(&["-e", "require('fs').unlinkSync('/usr/bin/foo')"]);
        assert_eq!(check_node_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_child_process_asks() {
        let cmd = make_cmd(&["-e", "require('child_process').execSync('rm -rf /')"]);
        assert_eq!(check_node_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_fetch_asks() {
        let cmd = make_cmd(&["-e", "fetch('http://example.com')"]);
        assert_eq!(check_node_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_print_flag_extracted() {
        let cmd = make_cmd(&["-p", "require('fs').writeFileSync('/usr/x','y')"]);
        assert_eq!(check_node_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_eval_long_flag_extracted() {
        let cmd = make_cmd(&["--eval", "console.log(process.version)"]);
        assert_eq!(
            check_node_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_glued_eval_extracted() {
        let cmd = make_cmd(&["-econsole.log(1)"]);
        assert_eq!(
            check_node_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_no_inline_code_returns_none() {
        let cmd = make_cmd(&["script.js"]);
        assert!(check_node_script(&cmd).is_none());
    }

    #[test]
    fn test_not_node_returns_none() {
        let cmd = Command {
            name: "ruby".to_string(),
            args: vec!["-e".to_string(), "puts 1".to_string()],
        };
        assert!(check_node_script(&cmd).is_none());
    }
}
