//! SQL query analysis for mysql/mariadb/sqlite3 commands

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Strip surrounding quotes from a query string
fn strip_quotes(query: &str) -> &str {
    let query = query.trim();
    let query = query.strip_prefix('"').unwrap_or(query);
    let query = query.strip_suffix('"').unwrap_or(query);
    let query = query.strip_prefix('\'').unwrap_or(query);
    query.strip_suffix('\'').unwrap_or(query)
}

/// Check if a SQL query is read-only
fn check_query_readonly(query: &str) -> PermissionResult {
    // Read-only SQL statements
    let read_only_prefixes = [
        "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "USE", "PRAGMA",
        // SQLite3 dot commands (read-only)
        ".SCHEMA", ".TABLES", ".INDICES", ".INDEXES", ".DUMP", ".MODE",
        ".HEADERS", ".SEPARATOR", ".WIDTH", ".PRINT", ".SHOW", ".DATABASES",
    ];

    // Split by semicolons and check ALL statements
    for statement in query.split(';') {
        let trimmed = statement.trim().to_uppercase();
        if trimmed.is_empty() {
            continue;
        }
        if !read_only_prefixes.iter().any(|p| trimmed.starts_with(p)) {
            return PermissionResult {
                permission: Permission::Ask,
                reason: "SQL write operation".to_string(),
                suggestion: None,
            };
        }
    }

    PermissionResult {
        permission: Permission::Allow,
        reason: "read-only SQL query".to_string(),
        suggestion: None,
    }
}

/// Extract query from mysql/mariadb command
fn extract_mysql_query(cmd: &Command) -> Option<&str> {
    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-e" || arg == "--execute" {
            return iter.next().map(|s| s.as_str());
        } else if arg.starts_with("-e") {
            return Some(&arg[2..]);
        } else if arg.starts_with("--execute=") {
            return Some(&arg[10..]);
        }
    }
    None
}

/// Extract query from sqlite3 command
fn extract_sqlite3_query(cmd: &Command) -> Option<&str> {
    let opts_with_args = ["-cmd", "-init", "-separator", "-nullvalue", "-newline"];

    let mut positional = Vec::new();
    let mut skip_next = false;

    for arg in &cmd.args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.starts_with('-') {
            if opts_with_args.iter().any(|o| arg == *o) {
                skip_next = true;
            }
            continue;
        }
        positional.push(arg.as_str());
    }

    // Need at least database and query
    if positional.len() >= 2 {
        Some(positional[1])
    } else {
        None
    }
}

/// Check if a mysql/mariadb command has a read-only query
pub fn check_mysql_query(cmd: &Command) -> Option<PermissionResult> {
    let query = extract_mysql_query(cmd)?;
    Some(check_query_readonly(strip_quotes(query)))
}

/// Check if a sqlite3 command has a read-only query
pub fn check_sqlite3_query(cmd: &Command) -> Option<PermissionResult> {
    let query = extract_sqlite3_query(cmd)?;
    Some(check_query_readonly(strip_quotes(query)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        Command {
            name: name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("{} {}", name, args.join(" ")),
        }
    }

    // MySQL tests

    #[test]
    fn test_select_allowed() {
        let cmd = make_cmd("mysql", &["-u", "root", "-e", "SELECT * FROM users"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_select_with_quotes_allowed() {
        let cmd = make_cmd("mysql", &["-e", "\"SELECT * FROM users\""]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_show_allowed() {
        let cmd = make_cmd("mariadb", &["-e", "SHOW DATABASES"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_describe_allowed() {
        let cmd = make_cmd("mysql", &["-e", "DESCRIBE users"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_insert_asks() {
        let cmd = make_cmd("mysql", &["-e", "INSERT INTO users VALUES (1, 'test')"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_delete_asks() {
        let cmd = make_cmd("mariadb", &["-e", "DELETE FROM users WHERE id = 1"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_update_asks() {
        let cmd = make_cmd("mysql", &["-e", "UPDATE users SET name = 'foo'"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_no_query_returns_none() {
        let cmd = make_cmd("mysql", &["-u", "root", "dbname"]);
        let result = check_mysql_query(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_execute_long_form() {
        let cmd = make_cmd("mysql", &["--execute", "SELECT 1"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_execute_equals_form() {
        let cmd = make_cmd("mysql", &["--execute=SHOW TABLES"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_multi_statement_bypass_blocked() {
        let cmd = make_cmd("mysql", &["-e", "SELECT 1; DROP TABLE users;"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_multi_statement_all_readonly() {
        let cmd = make_cmd("mysql", &["-e", "SELECT 1; SHOW TABLES; DESCRIBE users;"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    // SQLite3 tests

    #[test]
    fn test_sqlite3_select_allowed() {
        let cmd = make_cmd("sqlite3", &["/data/db.sqlite3", "SELECT * FROM users"]);
        let result = check_sqlite3_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sqlite3_select_with_quotes() {
        let cmd = make_cmd("sqlite3", &["/data/db.sqlite3", "\"SELECT uuid FROM orgs;\""]);
        let result = check_sqlite3_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sqlite3_pragma_allowed() {
        let cmd = make_cmd("sqlite3", &["db.sqlite", "PRAGMA table_info(users)"]);
        let result = check_sqlite3_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sqlite3_insert_asks() {
        let cmd = make_cmd("sqlite3", &["db.sqlite", "INSERT INTO users VALUES (1)"]);
        let result = check_sqlite3_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_sqlite3_no_query_returns_none() {
        let cmd = make_cmd("sqlite3", &["db.sqlite"]);
        let result = check_sqlite3_query(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_sqlite3_schema_allowed() {
        let cmd = make_cmd("sqlite3", &["db.sqlite", ".schema users"]);
        let result = check_sqlite3_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sqlite3_tables_allowed() {
        let cmd = make_cmd("sqlite3", &["db.sqlite", ".tables"]);
        let result = check_sqlite3_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
