//! scp wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap scp command - extract destination host
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let mut host = None;

    for arg in &cmd.args {
        if arg.starts_with('-') {
            continue;
        }
        if let Some(colon_pos) = arg.find(':') {
            let before_colon = &arg[..colon_pos];
            let h = if let Some(at_pos) = before_colon.find('@') {
                &before_colon[at_pos + 1..]
            } else {
                before_colon
            };
            if !h.starts_with('/') && !h.starts_with('.') {
                host = Some(h.to_string());
                break;
            }
        }
    }

    Some(UnwrapResult {
        inner_command: None,
        host,
        wrapper: "scp".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "scp".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_scp_to_remote() {
        let cmd = make_cmd(&["file.txt", "user@host:/path/"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
    }

    #[test]
    fn test_scp_from_remote() {
        let cmd = make_cmd(&["user@myserver:/remote/file", "local/"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("myserver".to_string()));
    }

    #[test]
    fn test_scp_local_only() {
        let cmd = make_cmd(&["/local/file", "/another/local/"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, None);
    }
}
