use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use crate::sql;

pub fn check_profile(cmd: &Command, piped_query: Option<&str>) -> Option<PermissionResult> {
    if cmd.name != "mysql-gc" {
        return None;
    }

    let server = server_from_args(&cmd.args)?;

    if is_write_server(&server) {
        return Some(check_write_server_query(cmd, piped_query, &server));
    }

    is_auto_approved_server(&server).then(|| PermissionResult {
        permission: Permission::Allow,
        reason: format!("mysql-gc {server} profile matches approved MySQL aliases"),
        suggestion: None,
    })
}

fn check_write_server_query(
    cmd: &Command,
    piped_query: Option<&str>,
    server: &str,
) -> PermissionResult {
    sql::check_mysql_query(cmd)
        .or_else(|| piped_query.map(sql::check_piped_query))
        .unwrap_or_else(|| PermissionResult {
            permission: Permission::Ask,
            reason: format!("mysql-gc {server} SQL source is not visible to analyzer"),
            suggestion: None,
        })
}

fn server_from_args(args: &[String]) -> Option<String> {
    let mut args = args.iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--" => break,
            "-s" | "--server" => return args.next().cloned(),
            value if value.starts_with("--server=") => {
                return value.strip_prefix("--server=").map(String::from);
            }
            _ => {}
        }
    }

    Some("local".to_string())
}

fn is_auto_approved_server(server: &str) -> bool {
    matches!(
        server,
        "local" | "prod" | "external" | "do-managed" | "replication" | "replication-root" | "rocks"
    )
}

fn is_write_server(server: &str) -> bool {
    matches!(server, "prod-rw" | "prod-root")
}
