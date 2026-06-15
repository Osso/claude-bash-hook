//! AWK program analysis for `awk`/`gawk`/`mawk`.
//!
//! AWK can write files (`print > "file"`, `>> "file"`), pipe to a shell command
//! (`print | "cmd"`, `"cmd" | getline`), and run `system()`. Such programs are
//! routed to `ask`; pure text-processing programs are read-only and allowed. A
//! program supplied via `-f file` can't be inspected, so we return `None`
//! (falling through to a prompt).

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use regex::Regex;

/// Extract the inline AWK program text. Returns `None` when the program comes
/// from a `-f`/`--file` script (which we can't read).
fn extract_awk_program(cmd: &Command) -> Option<String> {
    let mut pieces: Vec<String> = Vec::new();
    let mut first_positional: Option<String> = None;
    let mut from_file = false;

    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-e" | "--source" => {
                if let Some(code) = iter.next() {
                    pieces.push(code.clone());
                }
            }
            "-f" | "--file" => {
                from_file = true;
                iter.next();
            }
            "-v" | "--assign" | "-F" | "--field-separator" => {
                iter.next(); // option value, not the program
            }
            _ if arg.starts_with("--") => {
                if let Some(code) = arg.strip_prefix("--source=") {
                    pieces.push(code.to_string());
                }
            }
            _ if arg.starts_with('-') && arg.len() > 1 => {
                if let Some(code) = arg.strip_prefix("-e") {
                    if !code.is_empty() {
                        pieces.push(code.to_string());
                    }
                }
                // Other glued short flags (-F:, -v x=1) carry no program text.
            }
            _ => {
                if first_positional.is_none() {
                    first_positional = Some(arg.clone());
                }
            }
        }
    }

    if pieces.is_empty() {
        if from_file {
            return None; // program is an external file
        }
        pieces.extend(first_positional);
    }
    (!pieces.is_empty()).then(|| pieces.join("\n"))
}

/// True if the AWK program writes files, pipes to a command, or runs system().
fn has_side_effect(program: &str) -> bool {
    let patterns = [
        r"system\s*\(",  // system("cmd")
        r#">>?\s*""#,    // print ... > "file" / >> "file"
        r#"\|\s*""#,     // print ... | "cmd"
        r"\|\s*getline", // "cmd" | getline
    ];
    patterns
        .iter()
        .any(|p| Regex::new(p).expect("valid awk pattern").is_match(program))
}

/// Check whether an awk command runs a side-effecting program.
pub fn check_awk_script(cmd: &Command) -> Option<PermissionResult> {
    if !matches!(cmd.name.as_str(), "awk" | "gawk" | "mawk") {
        return None;
    }
    let program = extract_awk_program(cmd)?;

    if has_side_effect(&program) {
        Some(PermissionResult {
            permission: Permission::Ask,
            reason: "awk program may have side effects".to_string(),
            suggestion: None,
        })
    } else {
        Some(PermissionResult {
            permission: Permission::Allow,
            reason: "read-only awk program".to_string(),
            suggestion: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "awk".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_print_field_allowed() {
        let cmd = make_cmd(&["{print $1}"]);
        assert_eq!(
            check_awk_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_field_separator_program_allowed() {
        let cmd = make_cmd(&["-F:", "{print $1}"]);
        assert_eq!(
            check_awk_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_logical_or_comparison_allowed() {
        // String comparison with || must not be flagged as a pipe.
        let cmd = make_cmd(&["$1 == \"a\" || $2 == \"b\""]);
        assert_eq!(
            check_awk_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_write_redirect_asks() {
        let cmd = make_cmd(&["BEGIN{print 1 > \"/usr/bin/x\"}"]);
        assert_eq!(check_awk_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_append_redirect_asks() {
        let cmd = make_cmd(&["{print >> \"/etc/hosts\"}"]);
        assert_eq!(check_awk_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_pipe_to_command_asks() {
        let cmd = make_cmd(&["{print | \"sh\"}"]);
        assert_eq!(check_awk_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_getline_from_command_asks() {
        let cmd = make_cmd(&["BEGIN{\"id\" | getline x; print x}"]);
        assert_eq!(check_awk_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_system_asks() {
        let cmd = make_cmd(&["BEGIN{system(\"rm -rf /\")}"]);
        assert_eq!(check_awk_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_source_flag_extracted() {
        let cmd = make_cmd(&["-e", "BEGIN{print 1 > \"/usr/x\"}"]);
        assert_eq!(check_awk_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_program_file_returns_none() {
        let cmd = make_cmd(&["-f", "prog.awk", "data.txt"]);
        assert!(check_awk_script(&cmd).is_none());
    }

    #[test]
    fn test_gawk_name_handled() {
        let mut cmd = make_cmd(&["{print > \"/usr/x\"}"]);
        cmd.name = "gawk".to_string();
        assert_eq!(check_awk_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_not_awk_returns_none() {
        let cmd = Command {
            name: "sed".to_string(),
            args: vec!["s/a/b/".to_string()],
        };
        assert!(check_awk_script(&cmd).is_none());
    }
}
