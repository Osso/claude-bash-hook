//! ssh wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Strip surrounding single or double quotes from a string
fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Unwrap ssh command
/// ssh [options] [user@]hostname [command]
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let mut host = None;
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_host = false;

    let opts_with_args = [
        "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p",
        "-Q", "-R", "-S", "-W", "-w",
    ];

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if !found_host {
            if is_ssh_option(arg) {
                skip_next = ssh_option_consumes_next(arg, &opts_with_args);
                continue;
            }

            found_host = true;
            host = Some(extract_host(arg));
            continue;
        }

        inner_parts.push(arg.clone());
    }

    Some(UnwrapResult {
        inner_command: join_remote_command(&inner_parts),
        host,
        wrapper: "ssh".to_string(),
    })
}

fn is_ssh_option(arg: &str) -> bool {
    arg.starts_with('-')
}

fn ssh_option_consumes_next(arg: &str, opts_with_args: &[&str]) -> bool {
    if arg.len() != 2 {
        return false;
    }

    opts_with_args.contains(&arg)
}

fn extract_host(arg: &str) -> String {
    arg.split_once('@')
        .map(|(_, host)| host)
        .unwrap_or(arg)
        .to_string()
}

fn join_remote_command(inner_parts: &[String]) -> Option<String> {
    match inner_parts {
        [] => None,
        [single] => Some(strip_quotes(single)),
        _ => Some(inner_parts.join(" ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "ssh".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_ssh_with_command() {
        let cmd = make_cmd(&["user@host", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_ssh_with_options() {
        let cmd = make_cmd(&["-p", "22", "-i", "key.pem", "host", "whoami"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
        assert_eq!(result.inner_command, Some("whoami".to_string()));
    }

    #[test]
    fn test_ssh_no_command() {
        let cmd = make_cmd(&["user@myhost"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("myhost".to_string()));
        assert_eq!(result.inner_command, None);
    }

    #[test]
    fn test_ssh_quoted_command() {
        let cmd = make_cmd(&["host", "\"systemctl status foo\""]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
        assert_eq!(
            result.inner_command,
            Some("systemctl status foo".to_string())
        );
    }
}
