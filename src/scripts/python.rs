//! Python inline script analysis for `python -c` and heredoc commands

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};
use crate::sql::check_piped_query;
use regex::Regex;

/// Safe modules for __import__() calls. Anything not listed here triggers "ask".
const SAFE_IMPORT_MODULES: &[&str] = &[
    "os",
    "sys",
    "json",
    "struct",
    "re",
    "math",
    "collections",
    "itertools",
    "functools",
    "datetime",
    "time",
    "hashlib",
    "base64",
    "binascii",
    "codecs",
    "csv",
    "string",
    "textwrap",
    "difflib",
    "pathlib",
    "glob",
    "fnmatch",
    "stat",
    "posixpath",
    "ntpath",
    "io",
    "abc",
    "copy",
    "pprint",
    "decimal",
    "fractions",
    "random",
    "bisect",
    "heapq",
    "enum",
    "dataclasses",
    "typing",
    "operator",
    "contextlib",
];

/// Dangerous Python functions/modules that have side effects
const DANGEROUS_PATTERNS: &[&str] = &[
    // Command execution
    "subprocess",
    "os.system",
    "os.popen",
    "os.spawn",
    "os.exec",
    "commands.",
    // Code execution
    "eval(",
    "exec(",
    "compile(",
    // File writing
    "open(", // We'll check for write modes separately
    "file(",
    // File operations
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.mkdir",
    "os.makedirs",
    "os.rename",
    "os.replace",
    "os.truncate",
    "os.write",
    "shutil.",
    "pathlib.Path.write",
    "pathlib.Path.mkdir",
    "pathlib.Path.rmdir",
    "pathlib.Path.unlink",
    "pathlib.Path.rename",
    "pathlib.Path.touch",
    // Network
    "socket.",
    "urllib.request.urlopen",
    "http.client",
    "ftplib",
    "smtplib",
    "requests.",
    "httpx.",
    "aiohttp.",
    // Database (sqlite3.connect is checked separately — allowed if all execute() calls are read-only)
    "psycopg",
    "pymysql",
    "mysql.connector",
    // Process control
    "signal.",
    "os.kill",
    "os.killpg",
    // Environment modification
    "os.putenv",
    "os.unsetenv",
    "os.environ[",
    "os.chdir",
    "os.fchdir",
];

/// Extract Python code from python -c command
fn extract_python_code(cmd: &Command) -> Option<&str> {
    let mut iter = cmd.args.iter();

    while let Some(arg) = iter.next() {
        if arg == "-c" {
            // Next arg is the code
            return iter.next().map(|s| s.as_str());
        }
        // Handle -c"code" (no space)
        if let Some(code) = arg.strip_prefix("-c") {
            if !code.is_empty() {
                return Some(code);
            }
        }
    }

    None
}

/// Check if open() is used in read-only mode
fn has_write_open(code: &str) -> bool {
    // Look for open() calls and check if they have write modes
    let code_lower = code.to_lowercase();

    // Find all open( occurrences
    let mut pos = 0;
    while let Some(idx) = code_lower[pos..].find("open(") {
        let start = pos + idx;
        // Look at the content after open(
        let after_open = &code[start + 5..];

        // Find the closing paren (simple heuristic)
        if let Some(close) = after_open.find(')') {
            let args = &after_open[..close];
            // Check for write modes: 'w', 'a', 'x', 'r+', 'w+', 'a+'
            // But not just 'r' or 'rb'
            if args.contains("'w")
                || args.contains("\"w")
                || args.contains("'a")
                || args.contains("\"a")
                || args.contains("'x")
                || args.contains("\"x")
                || args.contains("'+")
                || args.contains("\"+")
                || args.contains("mode='w")
                || args.contains("mode=\"w")
                || args.contains("mode='a")
                || args.contains("mode=\"a")
            {
                return true;
            }
        }
        pos = start + 5;
    }

    false
}

/// Check if Python code only uses read-only operations
fn has_safe_subprocess_git_readonly(code: &str) -> bool {
    let safe_calls = ["run", "check_output", "call"];
    let safe_git_invocations = [
        "['git', 'diff']",
        "[\"git\", \"diff\"]",
        "['git', 'log']",
        "[\"git\", \"log\"]",
        "['git', 'show']",
        "[\"git\", \"show\"]",
    ];

    for call in safe_calls {
        for git_args in safe_git_invocations {
            let direct = format!("subprocess.{call}({git_args}");
            let imported = format!("__import__('subprocess').{call}({git_args}");
            let imported_alt = format!("__import__(\"subprocess\").{call}({git_args}");

            if code.contains(&direct) || code.contains(&imported) || code.contains(&imported_alt)
            {
                return true;
            }
        }
    }

    false
}

/// Check if all __import__() calls use safe modules
fn has_safe_imports_only(code: &str) -> bool {
    let mut pos = 0;
    while let Some(idx) = code[pos..].find("__import__") {
        let start = pos + idx + "__import__".len();
        // Find the opening paren and extract module name
        let rest = &code[start..];
        if let Some(paren) = rest.find('(') {
            let after_paren = &rest[paren + 1..];
            if let Some(module) = extract_string_arg(after_paren) {
                if !SAFE_IMPORT_MODULES.contains(&module.as_str()) {
                    return false;
                }
            } else {
                // Can't determine module — not safe
                return false;
            }
        }
        pos = start;
    }
    true
}

fn is_readonly_python(code: &str) -> bool {
    let code_lower = code.to_lowercase();
    for pattern in DANGEROUS_PATTERNS {
        if contains_dangerous_python_pattern(code, &code_lower, pattern) {
            return false;
        }
    }

    // Check __import__() calls against safe module whitelist
    if code.contains("__import__") && !has_safe_imports_only(code) {
        return false;
    }

    if code.contains("subprocess") && !has_safe_subprocess_git_readonly(code) {
        return false;
    }

    // sqlite3 is allowed only if all execute*() calls run read-only SQL
    if code.contains("sqlite3") && !sqlite_calls_are_readonly(code) {
        return false;
    }

    true
}

/// Verify every .execute(), .executemany(), .executescript() call passes a
/// literal read-only SQL string as its first argument. Unrecognized callers or
/// non-literal queries fail closed.
fn sqlite_calls_are_readonly(code: &str) -> bool {
    for method in [".execute(", ".executemany(", ".executescript("] {
        let mut pos = 0;
        while let Some(idx) = code[pos..].find(method) {
            let start = pos + idx + method.len();
            let Some(query) = extract_string_arg(&code[start..]) else {
                return false;
            };
            if check_piped_query(&query).permission != Permission::Allow {
                return false;
            }
            pos = start;
        }
    }
    true
}

fn contains_dangerous_python_pattern(code: &str, code_lower: &str, pattern: &str) -> bool {
    if pattern == "open(" {
        return code_lower.contains("open(") && has_write_open(code);
    }

    let pattern_lower = pattern.to_lowercase();
    if pattern.ends_with('(') {
        return contains_bare_python_call(code_lower, &pattern_lower);
    }

    code_lower.contains(&pattern_lower)
}

fn contains_bare_python_call(code_lower: &str, pattern_lower: &str) -> bool {
    let mut search_from = 0;

    while let Some(idx) = code_lower[search_from..].find(pattern_lower) {
        let abs_idx = search_from + idx;
        if is_bare_python_call(code_lower.as_bytes(), abs_idx) {
            return true;
        }
        search_from = abs_idx + pattern_lower.len();
    }

    false
}

fn is_bare_python_call(bytes: &[u8], index: usize) -> bool {
    if index == 0 {
        return true;
    }

    let prev = bytes[index - 1];
    !prev.is_ascii_alphanumeric() && prev != b'_' && prev != b'.'
}

/// Extract Python code from a heredoc in the full command
fn extract_heredoc_code(full_command: &str) -> Option<String> {
    // Match heredoc patterns: << 'EOF', << "EOF", <<EOF, <<-EOF, etc.
    // First find the delimiter
    let delim_re = Regex::new(r#"<<-?\s*['"]?(\w+)['"]?\s*\n"#).ok()?;

    let caps = delim_re.captures(full_command)?;
    let delimiter = caps.get(1)?.as_str();
    let delim_end = caps.get(0)?.end();

    // Find where the delimiter appears on its own line (possibly indented)
    let rest = &full_command[delim_end..];
    let end_re = Regex::new(&format!(r"\n[ \t]*{}", regex::escape(delimiter))).ok()?;
    let m = end_re.find(rest)?;
    Some(rest[..m.start()].to_string())
}

/// Extract file paths from open() calls with write modes
fn extract_write_paths(code: &str) -> Vec<String> {
    let mut paths = Vec::new();

    // Find all open() calls with write modes
    let mut pos = 0;
    while let Some(idx) = code[pos..].find("open(") {
        let start = pos + idx + 5;
        if let Some(close) = code[start..].find(')') {
            let args = &code[start..start + close];

            // Check if this is a write mode
            if args.contains("'w")
                || args.contains("\"w")
                || args.contains("'a")
                || args.contains("\"a")
                || args.contains("'x")
                || args.contains("\"x")
                || args.contains("'+")
                || args.contains("\"+")
                || args.contains("mode='w")
                || args.contains("mode=\"w")
                || args.contains("mode='a")
                || args.contains("mode=\"a")
            {
                // Extract the file path (first argument)
                if let Some(path) = extract_string_arg(args) {
                    paths.push(path);
                }
            }
        }
        pos = start;
    }

    paths
}

/// Extract a string argument from function args
fn extract_string_arg(args: &str) -> Option<String> {
    // Find first string literal (single or double quoted)
    let args = args.trim();

    // Try single quotes first
    if let Some(start) = args.find('\'') {
        if let Some(end) = args[start + 1..].find('\'') {
            return Some(args[start + 1..start + 1 + end].to_string());
        }
    }

    // Try double quotes
    if let Some(start) = args.find('"') {
        if let Some(end) = args[start + 1..].find('"') {
            return Some(args[start + 1..start + 1 + end].to_string());
        }
    }

    None
}

/// Check if all write paths are within allowed directories
fn all_writes_allowed(paths: &[String], cwd: Option<&str>) -> bool {
    for path in paths {
        let is_tmp = path.starts_with("/tmp/") || path == "/tmp";
        let is_in_project = cwd.is_some_and(|c| path.starts_with(c));
        // Relative paths resolve within cwd (the project directory)
        let is_relative = !path.starts_with('/') && cwd.is_some();

        if !is_tmp && !is_in_project && !is_relative {
            return false;
        }
    }
    true
}

/// Check if a python command is read-only or writes only to allowed paths
pub fn check_python_script(
    cmd: &Command,
    full_command: Option<&str>,
    cwd: Option<&str>,
) -> Option<PermissionResult> {
    // Match python, python3, python3.x
    if !cmd.name.starts_with("python") {
        return None;
    }

    // Try -c flag first
    let code = if let Some(code) = extract_python_code(cmd) {
        code.to_string()
    } else if let Some(full_cmd) = full_command {
        // Try heredoc extraction
        extract_heredoc_code(full_cmd)?
    } else {
        return None;
    };

    if is_readonly_python(&code) {
        return Some(PermissionResult {
            permission: Permission::Allow,
            reason: "read-only Python script".to_string(),
            suggestion: None,
        });
    }

    // Check if writes are only to allowed paths (project dir or /tmp)
    let write_paths = extract_write_paths(&code);
    if !write_paths.is_empty() && all_writes_allowed(&write_paths, cwd) {
        return Some(PermissionResult {
            permission: Permission::Allow,
            reason: "Python script writes to project dir or /tmp".to_string(),
            suggestion: None,
        });
    }

    Some(PermissionResult {
        permission: Permission::Ask,
        reason: "Python script may have side effects".to_string(),
        suggestion: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_command;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        make_command(name, args)
    }

    #[test]
    fn test_print_allowed() {
        let cmd = make_cmd("python3", &["-c", "print('hello')"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_json_loads_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import json; print(json.loads('{\"a\": 1}'))"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sys_version_allowed() {
        let cmd = make_cmd("python", &["-c", "import sys; print(sys.version)"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_base64_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import base64; print(base64.b64decode('aGVsbG8='))"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_os_path_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import os.path; print(os.path.basename('/tmp/foo'))"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_read_file_allowed() {
        let cmd = make_cmd("python3", &["-c", "print(open('/etc/hosts').read())"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_read_file_explicit_mode_allowed() {
        let cmd = make_cmd("python3", &["-c", "print(open('/etc/hosts', 'r').read())"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_write_to_tmp_allowed() {
        // Writes to /tmp are allowed
        let cmd = make_cmd("python3", &["-c", "open('/tmp/test', 'w').write('data')"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_append_to_tmp_allowed() {
        // Appends to /tmp are allowed
        let cmd = make_cmd("python3", &["-c", "open('/tmp/test', 'a').write('data')"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_write_to_project_dir_allowed() {
        // Writes to project dir are allowed when cwd is set
        let cmd = make_cmd(
            "python3",
            &[
                "-c",
                "open('/home/user/project/file.txt', 'w').write('data')",
            ],
        );
        let result = check_python_script(&cmd, None, Some("/home/user/project")).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_write_relative_path_allowed() {
        // Relative paths resolve within cwd, so they're allowed when cwd is set
        let cmd = make_cmd(
            "python3",
            &["-c", "open('phpstan-baseline.neon', 'w').write('data')"],
        );
        let result = check_python_script(&cmd, None, Some("/home/user/project")).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_write_relative_path_no_cwd_asks() {
        // Relative paths without cwd should ask
        let cmd = make_cmd(
            "python3",
            &["-c", "open('phpstan-baseline.neon', 'w').write('data')"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_write_outside_project_asks() {
        // Writes outside project dir should ask
        let cmd = make_cmd("python3", &["-c", "open('/etc/passwd', 'w').write('data')"]);
        let result = check_python_script(&cmd, None, Some("/home/user/project")).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_subprocess_asks() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import subprocess; subprocess.run(['ls'])"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_subprocess_git_diff_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import subprocess; subprocess.run(['git', 'diff'])"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_subprocess_git_log_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import subprocess; subprocess.run(['git', 'log'])"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_subprocess_git_show_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import subprocess; subprocess.run(['git', 'show'])"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_check_output_git_diff_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import subprocess; subprocess.check_output(['git', 'diff'])"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_check_output_git_log_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import subprocess; subprocess.check_output(['git', 'log'])"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_check_output_git_show_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import subprocess; subprocess.check_output(['git', 'show'])"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_os_system_asks() {
        let cmd = make_cmd("python3", &["-c", "import os; os.system('ls')"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_os_remove_asks() {
        let cmd = make_cmd("python3", &["-c", "import os; os.remove('/tmp/test')"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_eval_asks() {
        let cmd = make_cmd("python3", &["-c", "eval('print(1)')"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_exec_asks() {
        let cmd = make_cmd("python3", &["-c", "exec('print(1)')"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_shutil_asks() {
        let cmd = make_cmd("python3", &["-c", "import shutil; shutil.copy('a', 'b')"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_requests_asks() {
        let cmd = make_cmd(
            "python3",
            &["-c", "import requests; requests.get('http://example.com')"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_not_python_returns_none() {
        let cmd = Command {
            name: "ruby".to_string(),
            args: vec!["-e".to_string(), "puts 'hello'".to_string()],
        };
        let result = check_python_script(&cmd, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_python_without_c_returns_none() {
        let cmd = make_cmd("python3", &["script.py"]);
        let result = check_python_script(&cmd, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_complex_readonly_allowed() {
        let cmd = make_cmd(
            "python3",
            &[
                "-c",
                "import json, sys; data = json.loads(sys.stdin.read()); print(len(data))",
            ],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_heredoc_readonly_allowed() {
        let cmd = make_cmd("python3", &[]);
        let full_cmd = "python3 << 'EOF'\nprint('hello')\nEOF";
        let result = check_python_script(&cmd, Some(full_cmd), None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_heredoc_write_to_project_allowed() {
        let cmd = make_cmd("python3", &[]);
        let full_cmd =
            "python3 << 'EOF'\nwith open('/project/file.txt', 'w') as f:\n    f.write('data')\nEOF";
        let result = check_python_script(&cmd, Some(full_cmd), Some("/project")).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_heredoc_indented_delimiter_allowed() {
        let cmd = make_cmd("python3", &[]);
        let full_cmd = "python3 << 'PYEOF'\nimport csv\nprint('hello')\n      PYEOF";
        let result = check_python_script(&cmd, Some(full_cmd), None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_heredoc_tab_indented_delimiter_allowed() {
        let cmd = make_cmd("python3", &[]);
        let full_cmd = "python3 <<- 'EOF'\n\tprint('hello')\n\tEOF";
        let result = check_python_script(&cmd, Some(full_cmd), None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_heredoc_write_outside_project_asks() {
        let cmd = make_cmd("python3", &[]);
        let full_cmd =
            "python3 << 'EOF'\nwith open('/etc/passwd', 'w') as f:\n    f.write('data')\nEOF";
        let result = check_python_script(&cmd, Some(full_cmd), Some("/project")).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_dunder_import_safe_module_allowed() {
        let cmd = make_cmd(
            "python3",
            &[
                "-c",
                "size = __import__('os').path.getsize('/tmp/foo'); print(size)",
            ],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_dunder_import_struct_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "__import__('struct').unpack('<I', data)"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_dunder_import_subprocess_asks() {
        let cmd = make_cmd("python3", &["-c", "__import__('subprocess').run(['ls'])"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_dunder_import_subprocess_git_diff_allowed() {
        let cmd = make_cmd(
            "python3",
            &["-c", "__import__('subprocess').run(['git', 'diff'])"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_dunder_import_unknown_module_asks() {
        let cmd = make_cmd("python3", &["-c", "__import__('ctypes').cdll"]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_re_compile_allowed() {
        // re.compile() should not be flagged as dangerous compile()
        let cmd = make_cmd(
            "python",
            &[
                "-u",
                "-c",
                "import sys,time,re; s=time.monotonic(); pat=re.compile(r'test'); [sys.stdout.write(f'{time.monotonic()-s:.3f} {l}') for l in sys.stdin if pat.search(l)]",
            ],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_bare_compile_still_asks() {
        let cmd = make_cmd(
            "python3",
            &["-c", "compile('print(1)', '<string>', 'exec')"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_sqlite3_select_allowed() {
        let cmd = make_cmd(
            "python3",
            &[
                "-c",
                "import sqlite3; c=sqlite3.connect('/tmp/db.sqlite'); print(c.execute('SELECT 1 FROM t WHERE x=?',(1,)).fetchone())",
            ],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sqlite3_walk_and_select_allowed() {
        // Mirrors the real-world script: os.walk + read open() + sqlite3 SELECTs
        let code = "import hashlib, os, sqlite3; \
root='/tmp/x'; \
res=sqlite3.connect('/tmp/a.sqlite'); \
local=sqlite3.connect('/tmp/b.sqlite'); \
out=[]
for dirpath,_,files in os.walk(root):
    for name in files:
        p=os.path.join(dirpath,name); rel=os.path.relpath(p,root)
        if local.execute('select 1 from t where lower_path=?',(rel.lower(),)).fetchone(): continue
        h=hashlib.md5(open(p,'rb').read()).digest(); rows=res.execute('select fdid from resolution where content_key=? limit 1',(h,)).fetchall()
        if not rows: out.append(rel)
print('\\n'.join(out))";
        let cmd = make_cmd("python3", &["-c", code]);
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_sqlite3_insert_asks() {
        let cmd = make_cmd(
            "python3",
            &[
                "-c",
                "import sqlite3; c=sqlite3.connect('/tmp/db.sqlite'); c.execute('INSERT INTO t VALUES (1)')",
            ],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_sqlite3_executemany_update_asks() {
        let cmd = make_cmd(
            "python3",
            &[
                "-c",
                "import sqlite3; c=sqlite3.connect(':memory:'); c.executemany('UPDATE t SET x=? WHERE id=?', rows)",
            ],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_sqlite3_executescript_mixed_asks() {
        let cmd = make_cmd(
            "python3",
            &[
                "-c",
                "import sqlite3; sqlite3.connect(':memory:').executescript('SELECT 1; DROP TABLE t;')",
            ],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_sqlite3_execute_variable_query_asks() {
        // Non-literal query — can't verify it's read-only, fail closed
        let cmd = make_cmd(
            "python3",
            &[
                "-c",
                "import sqlite3, sys; sqlite3.connect(':memory:').execute(sys.argv[1])",
            ],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_ast_literal_eval_allowed() {
        // ast.literal_eval() should not be flagged as dangerous eval()
        let cmd = make_cmd(
            "python3",
            &["-c", "import ast; ast.literal_eval('[1,2,3]')"],
        );
        let result = check_python_script(&cmd, None, None).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
