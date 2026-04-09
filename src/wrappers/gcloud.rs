//! gcloud compute ssh wrapper handling

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

/// Unwrap gcloud compute ssh command
/// gcloud compute ssh [options] INSTANCE [-- COMMAND]
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    if !is_gcloud_compute_ssh(cmd) {
        return None;
    }

    let (host, inner_parts) = split_gcloud_ssh_args(&cmd.args[2..]);

    Some(UnwrapResult {
        inner_command: join_remote_command(&inner_parts),
        host,
        wrapper: "gcloud compute ssh".to_string(),
    })
}

fn is_gcloud_compute_ssh(cmd: &Command) -> bool {
    cmd.args.len() >= 2 && cmd.args[0] == "compute" && cmd.args[1] == "ssh"
}

fn is_command_separator(arg: &str) -> bool {
    arg == "--"
}

fn is_gcloud_option(arg: &str, opts_with_args: &[&str]) -> bool {
    arg.starts_with('-') && !is_command_separator(arg) && !opts_with_args.contains(&arg)
        || opts_with_args.iter().any(|opt| arg.starts_with(opt))
}

fn option_consumes_next(arg: &str, opts_with_args: &[&str]) -> bool {
    !arg.contains('=') && opts_with_args.iter().any(|opt| arg.starts_with(opt))
}

fn split_gcloud_ssh_args(args: &[String]) -> (Option<String>, Vec<String>) {
    let opts_with_args = [
        "--zone",
        "--project",
        "--tunnel-through-iap",
        "--internal-ip",
        "--ssh-key-file",
        "--ssh-flag",
        "--command",
    ];
    let mut host = None;
    let mut inner_parts = Vec::new();
    let mut skip_next = false;
    let mut found_separator = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if found_separator {
            inner_parts.push(arg.clone());
            continue;
        }
        if is_command_separator(arg) {
            found_separator = true;
            continue;
        }
        if is_gcloud_option(arg, &opts_with_args) {
            skip_next = option_consumes_next(arg, &opts_with_args);
            continue;
        }
        host.get_or_insert_with(|| arg.clone());
    }

    (host, inner_parts)
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
            name: "gcloud".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_gcloud_compute_ssh_with_command() {
        let cmd = make_cmd(&["compute", "ssh", "my-instance", "--", "ls", "-la"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("my-instance".to_string()));
        assert_eq!(result.inner_command, Some("ls -la".to_string()));
    }

    #[test]
    fn test_gcloud_compute_ssh_with_zone() {
        let cmd = make_cmd(&[
            "compute",
            "ssh",
            "--zone",
            "us-central1-a",
            "my-instance",
            "--",
            "whoami",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("my-instance".to_string()));
        assert_eq!(result.inner_command, Some("whoami".to_string()));
    }

    #[test]
    fn test_gcloud_compute_ssh_no_command() {
        let cmd = make_cmd(&["compute", "ssh", "my-instance"]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("my-instance".to_string()));
        assert_eq!(result.inner_command, None);
    }

    #[test]
    fn test_gcloud_compute_ssh_with_project() {
        let cmd = make_cmd(&[
            "compute",
            "ssh",
            "--project=my-project",
            "--zone=us-east1-b",
            "instance-1",
            "--",
            "docker",
            "ps",
        ]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.host, Some("instance-1".to_string()));
        assert_eq!(result.inner_command, Some("docker ps".to_string()));
    }

    #[test]
    fn test_not_gcloud_compute_ssh() {
        let cmd = make_cmd(&["compute", "instances", "list"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_gcloud_other_command() {
        let cmd = make_cmd(&["auth", "list"]);
        let result = unwrap(&cmd);
        assert!(result.is_none());
    }
}
