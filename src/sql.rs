//! SQL query analysis for mysql/mariadb/sqlite3/clickhouse commands

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Strip surrounding quotes from a query string (including escaped quotes)
fn strip_quotes(query: &str) -> String {
    let query = query.trim();
    // Handle escaped quotes first
    let query = query.strip_prefix("\\\"").unwrap_or(query);
    let query = query.strip_suffix("\\\"").unwrap_or(query);
    // Then regular quotes
    let query = query.strip_prefix('"').unwrap_or(query);
    let query = query.strip_suffix('"').unwrap_or(query);
    let query = query.strip_prefix('\'').unwrap_or(query);
    let query = query.strip_suffix('\'').unwrap_or(query);
    query.to_string()
}

/// Strip SQL comments from a query
fn strip_sql_comments(query: &str) -> String {
    let mut result = String::new();
    let mut chars = query.chars().peekable();
    let mut state = CommentState::Normal;

    while let Some(c) = chars.next() {
        match state {
            CommentState::Normal if c == '-' && chars.peek() == Some(&'-') => {
                chars.next();
                state = CommentState::SingleLine;
            }
            CommentState::Normal if c == '/' && chars.peek() == Some(&'*') => {
                chars.next();
                state = CommentState::MultiLine;
            }
            CommentState::SingleLine if c == '\n' => {
                result.push('\n');
                state = CommentState::Normal;
            }
            CommentState::MultiLine if c == '*' && chars.peek() == Some(&'/') => {
                chars.next();
                state = CommentState::Normal;
            }
            CommentState::Normal => result.push(c),
            CommentState::SingleLine | CommentState::MultiLine => {}
        }
    }

    result
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommentState {
    Normal,
    SingleLine,
    MultiLine,
}

/// Read-only SQL statement prefixes (SQL keywords and SQLite3 dot commands)
const READ_ONLY_PREFIXES: &[&str] = &[
    "SELECT",
    "SHOW",
    "DESCRIBE",
    "DESC",
    "EXPLAIN",
    "USE",
    "PRAGMA",
    ".SCHEMA",
    ".TABLES",
    ".INDICES",
    ".INDEXES",
    ".DUMP",
    ".MODE",
    ".HEADERS",
    ".SEPARATOR",
    ".WIDTH",
    ".PRINT",
    ".SHOW",
    ".DATABASES",
];

/// Check if a single SQL statement (no semicolons) is read-only
fn is_statement_readonly(statement: &str) -> bool {
    let trimmed = statement.trim().to_uppercase();
    trimmed.is_empty() || READ_ONLY_PREFIXES.iter().any(|p| trimmed.starts_with(p))
}

/// Check if a SQL query is read-only
fn check_query_readonly(query: &str) -> PermissionResult {
    let query = strip_sql_comments(query);
    let all_readonly = query.split(';').all(is_statement_readonly);
    if all_readonly {
        PermissionResult {
            permission: Permission::Allow,
            reason: "read-only SQL query".to_string(),
            suggestion: None,
        }
    } else {
        PermissionResult {
            permission: Permission::Ask,
            reason: "SQL write operation".to_string(),
            suggestion: None,
        }
    }
}

/// Extract query from mysql/mariadb command
fn extract_mysql_query(cmd: &Command) -> Option<String> {
    let mut iter = cmd.args.iter().enumerate();
    while let Some((idx, arg)) = iter.next() {
        if arg == "-e" || arg == "--execute" {
            // Check if next arg starts with escaped quote - if so, join until closing quote
            if let Some(next) = cmd.args.get(idx + 1) {
                if next.starts_with("\\\"") || next.starts_with("\"") {
                    // Join all args from here until we find one ending with escaped quote
                    let remaining: Vec<&str> =
                        cmd.args[idx + 1..].iter().map(|s| s.as_str()).collect();
                    return Some(remaining.join(" "));
                }
                return Some(next.clone());
            }
            return None;
        } else if arg.starts_with("-e") {
            return Some(arg[2..].to_string());
        } else if arg.starts_with("--execute=") {
            return Some(arg[10..].to_string());
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
    Some(check_query_readonly(&strip_quotes(&query)))
}

/// Check if a raw SQL query string is read-only (for piped queries)
pub fn check_piped_query(query: &str) -> PermissionResult {
    check_query_readonly(&strip_quotes(query))
}

/// Check if a sqlite3 command has a read-only query
pub fn check_sqlite3_query(cmd: &Command) -> Option<PermissionResult> {
    let query = extract_sqlite3_query(cmd)?;
    Some(check_query_readonly(&strip_quotes(query)))
}

/// Extract query from clickhouse-client command
fn extract_clickhouse_query(cmd: &Command) -> Option<String> {
    let mut iter = cmd.args.iter().enumerate();
    while let Some((idx, arg)) = iter.next() {
        if arg == "-q" || arg == "--query" {
            // Check if next arg starts with escaped quote - if so, join until closing quote
            if let Some(next) = cmd.args.get(idx + 1) {
                if next.starts_with("\\\"") || next.starts_with("\"") {
                    // Join all args from here until we find one ending with escaped quote
                    let remaining: Vec<&str> =
                        cmd.args[idx + 1..].iter().map(|s| s.as_str()).collect();
                    return Some(remaining.join(" "));
                }
                return Some(next.clone());
            }
            return None;
        } else if arg.starts_with("-q") && arg.len() > 2 {
            // Handle -q"query" (no space)
            return Some(arg[2..].to_string());
        } else if arg.starts_with("--query=") {
            return Some(arg[8..].to_string());
        }
    }
    None
}

/// Check if a positional SQL command has a read-only query.
/// Expects cmd.args[0] = subcommand, cmd.args[1] = SQL query.
pub fn check_positional_sql_query(cmd: &Command) -> Option<PermissionResult> {
    let query = cmd.args.get(1)?;
    Some(check_query_readonly(&strip_quotes(query)))
}

/// Check if a clickhouse-client command has a read-only query
pub fn check_clickhouse_query(cmd: &Command) -> Option<PermissionResult> {
    let query = extract_clickhouse_query(cmd)?;
    Some(check_query_readonly(&strip_quotes(&query)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_command;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        make_command(name, args)
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
        let cmd = make_cmd(
            "sqlite3",
            &["/data/db.sqlite3", "\"SELECT uuid FROM orgs;\""],
        );
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

    #[test]
    fn test_escaped_quotes() {
        // Simulating what happens after SSH unwraps: mariadb -e \"SHOW MASTER STATUS\"
        let cmd = make_cmd("mariadb", &["-e", "\\\"SHOW", "MASTER", "STATUS\\\""]);
        let result = check_mysql_query(&cmd);
        assert!(result.is_some());
        assert_eq!(result.unwrap().permission, Permission::Allow);
    }

    #[test]
    fn test_single_line_comment_allowed() {
        let cmd = make_cmd(
            "mysql",
            &["-e", "-- This is a comment\nSELECT * FROM users"],
        );
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_multiline_comment_allowed() {
        let cmd = make_cmd("mysql", &["-e", "/* Check users */ SELECT * FROM users"]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_comment_with_complex_select() {
        let query = "-- Check when Dart guests were created\n   SELECT DATE_FORMAT(create_date, '%Y-%m') AS month FROM guests";
        let cmd = make_cmd("mysql", &["-e", query]);
        let result = check_mysql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    // ClickHouse tests

    #[test]
    fn test_clickhouse_select_allowed() {
        let cmd = make_cmd("clickhouse-client", &["-q", "SELECT * FROM users"]);
        let result = check_clickhouse_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_clickhouse_select_with_quotes() {
        let cmd = make_cmd(
            "clickhouse-client",
            &["-q", "\"SELECT count() FROM users\""],
        );
        let result = check_clickhouse_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_clickhouse_show_allowed() {
        let cmd = make_cmd("clickhouse-client", &["--query", "SHOW DATABASES"]);
        let result = check_clickhouse_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_clickhouse_describe_allowed() {
        let cmd = make_cmd("clickhouse-client", &["-q", "DESCRIBE TABLE users"]);
        let result = check_clickhouse_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_clickhouse_insert_asks() {
        let cmd = make_cmd(
            "clickhouse-client",
            &["-q", "INSERT INTO users VALUES (1, 'test')"],
        );
        let result = check_clickhouse_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_clickhouse_drop_asks() {
        let cmd = make_cmd("clickhouse-client", &["-q", "DROP TABLE users"]);
        let result = check_clickhouse_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_clickhouse_no_query_returns_none() {
        let cmd = make_cmd("clickhouse-client", &["--host", "localhost"]);
        let result = check_clickhouse_query(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_clickhouse_query_equals_form() {
        let cmd = make_cmd("clickhouse-client", &["--query=SHOW TABLES"]);
        let result = check_clickhouse_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_clickhouse_union_all_allowed() {
        let query = "SELECT 'a' as tbl, count() FROM a UNION ALL SELECT 'b', count() FROM b";
        let cmd = make_cmd("clickhouse-client", &["-q", query]);
        let result = check_clickhouse_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    // Positional SQL command tests

    #[test]
    fn test_positional_sql_select_allowed() {
        let cmd = make_cmd(
            "groundcover-cli",
            &["sql-clickhouse", "SELECT * FROM users"],
        );
        let result = check_positional_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_positional_sql_insert_asks() {
        let cmd = make_cmd(
            "groundcover-cli",
            &["sql-clickhouse", "INSERT INTO users VALUES (1)"],
        );
        let result = check_positional_sql_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_positional_sql_no_query_returns_none() {
        let cmd = make_cmd("groundcover-cli", &["sql-clickhouse"]);
        let result = check_positional_sql_query(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_clickhouse_multiline_select_allowed() {
        let query = "
   SELECT 'activity_tracking' as tbl, countIf(utm_id IS NOT NULL) as ch_with_utm FROM activity_tracking
   UNION ALL SELECT 'sessions', countIf(utm_id IS NOT NULL) FROM sessions
   ";
        let cmd = make_cmd("clickhouse-client", &["-q", query]);
        let result = check_clickhouse_query(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
