//! Ruby inline script analysis for `ruby -e` commands.
//!
//! Ruby's API is too large to allowlist, so we use a denylist: inline code that
//! spawns processes, writes/deletes files, or opens the network is routed to
//! `ask`; otherwise it is read-only and allowed. Code we cannot extract returns
//! `None`, falling through to normal handling (a prompt).

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use regex::Regex;

/// Side-effecting Ruby patterns (substring match, Ruby is case-sensitive).
const DANGEROUS_PATTERNS: &[&str] = &[
    // Process execution
    "IO.popen",
    "Open3",
    "Process.spawn",
    "Kernel.system",
    "%x(",
    "%x{",
    "%x[",
    // File writes / deletion
    "File.write",
    "IO.write",
    "File.delete",
    "File.unlink",
    "File.rename",
    "File.truncate",
    "File.chmod",
    "File.chown",
    "File.symlink",
    "File.link",
    "Dir.mkdir",
    "Dir.rmdir",
    "Dir.delete",
    "FileUtils",
    // Code execution
    "eval(",
    "instance_eval",
    "class_eval",
    "module_eval",
    // Network
    "Net::",
    "TCPSocket",
    "UDPSocket",
    "TCPServer",
    "Socket.",
    "URI.open",
    "open-uri",
    "open_uri",
];

/// Extract all `-e` inline code fragments from a ruby invocation.
fn extract_ruby_code(cmd: &Command) -> Option<String> {
    let mut pieces: Vec<String> = Vec::new();
    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-e" {
            if let Some(code) = iter.next() {
                pieces.push(code.clone());
            }
        } else if let Some(code) = arg.strip_prefix("-e") {
            // Glued -e'code'; exclude long flags like "--encoding" (start with --).
            if !arg.starts_with("--") && !code.is_empty() {
                pieces.push(code.to_string());
            }
        }
    }

    (!pieces.is_empty()).then(|| pieces.join("\n"))
}

fn has_side_effect(code: &str) -> bool {
    if code.contains('`') {
        return true; // backtick command execution
    }
    if DANGEROUS_PATTERNS.iter().any(|p| code.contains(p)) {
        return true;
    }
    // `system`/`exec`/`spawn`/`fork` as bare calls (word boundaries).
    let bare = Regex::new(r"\b(system|exec|spawn|fork)\b").expect("valid ruby builtin regex");
    if bare.is_match(code) {
        return true;
    }
    // File.open with a write/append mode string.
    let write_open =
        Regex::new(r#"File\.open\b[^)]*["'][waA]"#).expect("valid ruby File.open regex");
    write_open.is_match(code)
}

/// Check whether a ruby command runs side-effecting inline code.
pub fn check_ruby_script(cmd: &Command) -> Option<PermissionResult> {
    if cmd.name != "ruby" {
        return None;
    }
    let code = extract_ruby_code(cmd)?;

    if has_side_effect(&code) {
        Some(PermissionResult {
            permission: Permission::Ask,
            reason: "Ruby script may have side effects".to_string(),
            suggestion: None,
        })
    } else {
        Some(PermissionResult {
            permission: Permission::Allow,
            reason: "read-only Ruby script".to_string(),
            suggestion: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "ruby".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_puts_allowed() {
        let cmd = make_cmd(&["-e", "puts 1+1"]);
        assert_eq!(
            check_ruby_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_read_file_allowed() {
        let cmd = make_cmd(&["-e", "puts File.read('/etc/hosts')"]);
        assert_eq!(
            check_ruby_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_file_write_asks() {
        let cmd = make_cmd(&["-e", "File.write('/usr/bin/evil','x')"]);
        assert_eq!(check_ruby_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_file_open_write_mode_asks() {
        let cmd = make_cmd(&["-e", "File.open('/usr/bin/evil','w'){|f| f.puts 1}"]);
        assert_eq!(check_ruby_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_file_open_read_allowed() {
        let cmd = make_cmd(&["-e", "File.open('/etc/hosts'){|f| puts f.read}"]);
        assert_eq!(
            check_ruby_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_system_asks() {
        let cmd = make_cmd(&["-e", "system('rm -rf /')"]);
        assert_eq!(check_ruby_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_backtick_asks() {
        let cmd = make_cmd(&["-e", "x = `ls`"]);
        assert_eq!(check_ruby_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_file_delete_asks() {
        let cmd = make_cmd(&["-e", "File.delete('/usr/bin/foo')"]);
        assert_eq!(check_ruby_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_net_http_asks() {
        let cmd = make_cmd(&["-e", "require 'net/http'; Net::HTTP.get(uri)"]);
        assert_eq!(check_ruby_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_multiple_e_flags_joined() {
        let cmd = make_cmd(&["-e", "x=1", "-e", "File.write('/usr/x', x)"]);
        assert_eq!(check_ruby_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_glued_code_extracted() {
        let cmd = make_cmd(&["-eputs(2)"]);
        assert_eq!(
            check_ruby_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_no_inline_code_returns_none() {
        let cmd = make_cmd(&["script.rb"]);
        assert!(check_ruby_script(&cmd).is_none());
    }

    #[test]
    fn test_not_ruby_returns_none() {
        let cmd = Command {
            name: "node".to_string(),
            args: vec!["-e".to_string(), "1".to_string()],
        };
        assert!(check_ruby_script(&cmd).is_none());
    }
}
