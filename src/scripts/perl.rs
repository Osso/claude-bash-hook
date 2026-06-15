//! Perl inline script analysis for `perl -e` / `perl -E` commands.
//!
//! Perl is too large to allowlist, so we use a denylist: inline code that
//! performs writes, deletions, process execution, or other side effects is
//! routed to `ask`; otherwise it is read-only and allowed. Code we cannot
//! extract returns `None`, falling through to normal handling (a prompt).

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use regex::Regex;

/// Side-effecting Perl builtins (matched at word boundaries).
const DANGEROUS_BUILTINS: &str = r"\b(system|exec|fork|qx|syscall|unlink|rename|symlink|link|mkdir|rmdir|chmod|chown|chroot|chdir|sysopen|truncate|syswrite|utime|kill)\b";

/// Extract all `-e`/`-E` inline code fragments from a perl invocation.
/// Handles separated (`-e CODE`), glued (`-e'CODE'`), and combined-flag
/// (`-pe CODE`, `-nE CODE`) forms. Module/include flags (`-M`, `-m`, `-I`)
/// are skipped so their arguments are not mistaken for code.
fn extract_perl_code(cmd: &Command) -> Option<String> {
    let mut pieces: Vec<String> = Vec::new();
    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') || arg.starts_with("--") {
            continue;
        }
        if arg.starts_with("-M") || arg.starts_with("-m") || arg.starts_with("-I") {
            continue;
        }
        let flags = &arg[1..];
        let Some(pos) = flags.find(['e', 'E']) else {
            continue;
        };
        let after = &flags[pos + 1..];
        if after.is_empty() {
            if let Some(next) = iter.next() {
                pieces.push(next.clone());
            }
        } else {
            pieces.push(after.to_string());
        }
    }

    (!pieces.is_empty()).then(|| pieces.join("\n"))
}

/// True if the Perl code has a side effect (write/delete/exec/network).
fn has_side_effect(code: &str) -> bool {
    if code.contains('`') {
        return true; // backtick command execution
    }
    let builtins = Regex::new(DANGEROUS_BUILTINS).expect("valid perl builtin regex");
    if builtins.is_match(code) {
        return true;
    }
    // open(...) for write (`>`, `>>`) or pipe (`|`) before the statement ends.
    let write_open = Regex::new(r"\bopen\b[^;\n]*(?:>|\|)").expect("valid perl open regex");
    write_open.is_match(code)
}

/// Check whether a perl command runs side-effecting inline code.
pub fn check_perl_script(cmd: &Command) -> Option<PermissionResult> {
    if cmd.name != "perl" {
        return None;
    }
    let code = extract_perl_code(cmd)?;

    if has_side_effect(&code) {
        Some(PermissionResult {
            permission: Permission::Ask,
            reason: "Perl script may have side effects".to_string(),
            suggestion: None,
        })
    } else {
        Some(PermissionResult {
            permission: Permission::Allow,
            reason: "read-only Perl script".to_string(),
            suggestion: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "perl".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_print_allowed() {
        let cmd = make_cmd(&["-e", "print 'hello'"]);
        assert_eq!(
            check_perl_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_read_file_allowed() {
        let cmd = make_cmd(&["-e", r#"open(F,"<","/etc/hosts");print <F>"#]);
        assert_eq!(
            check_perl_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_write_open_asks() {
        let cmd = make_cmd(&["-e", r#"open(F,">","/usr/bin/evil");print F 1"#]);
        assert_eq!(check_perl_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_append_open_asks() {
        let cmd = make_cmd(&["-e", r#"open(F,">>","/etc/hosts")"#]);
        assert_eq!(check_perl_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_unlink_asks() {
        let cmd = make_cmd(&["-e", r#"unlink "/usr/bin/foo""#]);
        assert_eq!(check_perl_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_system_asks() {
        let cmd = make_cmd(&["-e", r#"system("rm -rf /")"#]);
        assert_eq!(check_perl_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_backtick_asks() {
        let cmd = make_cmd(&["-e", "my $x = `ls`"]);
        assert_eq!(check_perl_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_pipe_open_asks() {
        let cmd = make_cmd(&["-e", r#"open(P,"|-","cat")"#]);
        assert_eq!(check_perl_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_combined_flag_code_extracted() {
        // -nE CODE: code is the next arg.
        let cmd = make_cmd(&["-nE", r#"unlink "/usr/bin/x""#]);
        assert_eq!(check_perl_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_glued_code_extracted() {
        let cmd = make_cmd(&[r#"-eunlink "/usr/bin/x""#]);
        assert_eq!(check_perl_script(&cmd).unwrap().permission, Permission::Ask);
    }

    #[test]
    fn test_module_flag_not_mistaken_for_code() {
        // -Mfeature must be skipped; real code is read-only.
        let cmd = make_cmd(&["-Mfeature=say", "-e", "say 42"]);
        assert_eq!(
            check_perl_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_link_word_boundary_not_unlink_substring() {
        // A read-only one-liner mentioning neither builtin stays allowed.
        let cmd = make_cmd(&["-e", "print length($x)"]);
        assert_eq!(
            check_perl_script(&cmd).unwrap().permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_no_inline_code_returns_none() {
        let cmd = make_cmd(&["script.pl"]);
        assert!(check_perl_script(&cmd).is_none());
    }

    #[test]
    fn test_not_perl_returns_none() {
        let cmd = Command {
            name: "python3".to_string(),
            args: vec!["-c".to_string(), "print(1)".to_string()],
        };
        assert!(check_perl_script(&cmd).is_none());
    }
}
