//! rsync wrapper handling

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

/// Unwrap rsync command - extract destination host
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    let mut host = None;

    for arg in &cmd.args {
        if arg.starts_with('-') {
            continue;
        }
        if let Some(colon_pos) = arg.find(':') {
            let before_colon = &arg[..colon_pos];
            if before_colon.starts_with('/') || before_colon.starts_with('.') {
                continue;
            }
            let h = if let Some(at_pos) = before_colon.find('@') {
                &before_colon[at_pos + 1..]
            } else {
                before_colon
            };
            host = Some(h.to_string());
            break;
        }
    }

    Some(UnwrapResult {
        inner_command: None,
        host,
        wrapper: "rsync".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "rsync".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_rsync_to_remote() {
        let cmd = make_cmd(&["-avz", "local/", "user@host:/remote/"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("host".to_string()));
    }

    #[test]
    fn test_rsync_from_remote() {
        let cmd = make_cmd(&["-avz", "user@server:/remote/", "local/"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("server".to_string()));
    }

    #[test]
    fn test_rsync_local_only() {
        let cmd = make_cmd(&["-av", "/src/", "/dest/"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, None);
    }
}
