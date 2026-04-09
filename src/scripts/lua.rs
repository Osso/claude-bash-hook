//! Lua inline script analysis for `lua -e` commands

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Dangerous Lua patterns that indicate side effects
const DANGEROUS_PATTERNS: &[&str] = &[
    // Command execution
    "os.execute",
    "io.popen",
    // File system modification
    "os.remove",
    "os.rename",
    "os.tmpname",
    // File writing (io.open checked separately for mode)
    "io.open",
    "io.output",
    "io.write(",
    // Code loading from strings/files
    "loadfile(",
    "dofile(",
    "load(",
    "loadstring(",
    // Network (luasocket)
    "socket.connect",
    "socket.tcp",
    "socket.udp",
    "socket.http",
    "http.request",
    // Process/environment
    "os.exit(",
    "os.setlocale",
    "os.getenv", // read-only but often used before setenv in C modules
    // Debug library (can modify behavior)
    "debug.sethook",
    "debug.setmetatable",
    "debug.setupvalue",
    "debug.setlocal",
    "debug.setfenv",
    // FFI (LuaJIT)
    "ffi.cdef",
    "ffi.load",
    "ffi.new",
    "ffi.cast",
    "ffi.C.",
];

/// Safe Lua patterns - if io.open is used, check for read-only mode
fn has_write_io_open(code: &str) -> bool {
    let code_lower = code.to_lowercase();
    let mut pos = 0;

    while let Some(idx) = code_lower[pos..].find("io.open(") {
        let start = pos + idx + 8; // skip "io.open("
        let after = &code[start..];

        if let Some(close) = after.find(')') {
            let args = &after[..close];
            // io.open(path, mode) - check mode argument
            // Write modes: "w", "a", "w+", "a+", "r+"
            // Read modes: "r", "rb" (or no mode = default "r")
            if args.contains("\"w")
                || args.contains("'w")
                || args.contains("\"a")
                || args.contains("'a")
                || args.contains("\"r+")
                || args.contains("'r+")
            {
                return true;
            }
        }
        pos = start;
    }

    false
}

/// Check if Lua code only uses read-only operations
fn is_readonly_lua(code: &str) -> bool {
    let code_lower = code.to_lowercase();

    for pattern in DANGEROUS_PATTERNS {
        let pattern_lower = pattern.to_lowercase();

        // Special handling for io.open - check mode
        if *pattern == "io.open" {
            if code_lower.contains("io.open(") && has_write_io_open(code) {
                return false;
            }
            continue;
        }

        if code_lower.contains(&pattern_lower) {
            return false;
        }
    }

    true
}

/// Extract Lua code from lua -e command
fn extract_lua_code(cmd: &Command) -> Option<&str> {
    let mut iter = cmd.args.iter();

    while let Some(arg) = iter.next() {
        if arg == "-e" {
            return iter.next().map(|s| s.as_str());
        }
        // Handle -e"code" (no space)
        if let Some(code) = arg.strip_prefix("-e") {
            if !code.is_empty() {
                return Some(code);
            }
        }
    }

    None
}

/// Check if a lua command is read-only
pub fn check_lua_script(cmd: &Command) -> Option<PermissionResult> {
    if cmd.name != "lua" && cmd.name != "luajit" {
        return None;
    }

    let code = extract_lua_code(cmd)?;

    if is_readonly_lua(code) {
        Some(PermissionResult {
            permission: Permission::Allow,
            reason: "read-only Lua script".to_string(),
            suggestion: None,
        })
    } else {
        Some(PermissionResult {
            permission: Permission::Ask,
            reason: "Lua script may have side effects".to_string(),
            suggestion: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "lua".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn make_luajit_cmd(args: &[&str]) -> Command {
        Command {
            name: "luajit".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_print_allowed() {
        let cmd = make_cmd(&["-e", "print('hello')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_require_and_method_calls_allowed() {
        let cmd = make_cmd(&[
            "-e",
            r#"
            local wowless = require('wowless')
            local env = wowless.CreateEnv()
            local parent = env.CreateFrame('Frame', 'TestParent')
            local frame = env.CreateFrame('Frame', 'TestChild', parent)
            print('Got:', frame:GetName())
            "#,
        ]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_string_operations_allowed() {
        let cmd = make_cmd(&["-e", "print(string.format('%s %d', 'hello', 42))"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_table_operations_allowed() {
        let cmd = make_cmd(&["-e", "local t = {1,2,3}; table.insert(t, 4); print(#t)"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_math_allowed() {
        let cmd = make_cmd(&["-e", "print(math.sqrt(144))"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_io_read_allowed() {
        let cmd = make_cmd(&[
            "-e",
            "local f = io.open('/etc/hosts', 'r'); print(f:read('*a')); f:close()",
        ]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_io_open_default_mode_allowed() {
        // Default mode is "r"
        let cmd = make_cmd(&["-e", "local f = io.open('/etc/hosts'); print(f:read('*a'))"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_os_execute_asks() {
        let cmd = make_cmd(&["-e", "os.execute('rm -rf /')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_io_popen_asks() {
        let cmd = make_cmd(&["-e", "local f = io.popen('ls'); print(f:read('*a'))"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_io_open_write_asks() {
        let cmd = make_cmd(&[
            "-e",
            "local f = io.open('/tmp/test', 'w'); f:write('data'); f:close()",
        ]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_io_open_append_asks() {
        let cmd = make_cmd(&["-e", "local f = io.open('/tmp/test', 'a'); f:write('data')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_os_remove_asks() {
        let cmd = make_cmd(&["-e", "os.remove('/tmp/test')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_os_rename_asks() {
        let cmd = make_cmd(&["-e", "os.rename('old', 'new')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_loadfile_asks() {
        let cmd = make_cmd(&["-e", "loadfile('evil.lua')()"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_dofile_asks() {
        let cmd = make_cmd(&["-e", "dofile('script.lua')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_load_asks() {
        let cmd = make_cmd(&["-e", "load('print(1)')()"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_io_write_asks() {
        let cmd = make_cmd(&["-e", "io.write('hello')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_ffi_asks() {
        let cmd = make_cmd(&[
            "-e",
            "local ffi = require('ffi'); ffi.cdef[[ int printf(const char *fmt, ...); ]]",
        ]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_debug_sethook_asks() {
        let cmd = make_cmd(&["-e", "debug.sethook(function() end, 'c')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_luajit_allowed() {
        let cmd = make_luajit_cmd(&["-e", "print('hello from luajit')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_luajit_dangerous_asks() {
        let cmd = make_luajit_cmd(&["-e", "os.execute('whoami')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_not_lua_returns_none() {
        let cmd = Command {
            name: "python".to_string(),
            args: vec!["-c".to_string(), "print('hello')".to_string()],
        };
        let result = check_lua_script(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_lua_without_e_returns_none() {
        let cmd = make_cmd(&["script.lua"]);
        let result = check_lua_script(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_e_no_space() {
        let cmd = make_cmd(&["-eprint('hello')"]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_os_clock_and_time_allowed() {
        let cmd = make_cmd(&[
            "-e",
            "print(os.clock()); print(os.time()); print(os.date())",
        ]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_pcall_allowed() {
        let cmd = make_cmd(&[
            "-e",
            "local ok, err = pcall(function() error('test') end); print(ok, err)",
        ]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_complex_readonly_allowed() {
        let cmd = make_cmd(&[
            "-e",
            r#"
            local json = require('cjson')
            local data = json.decode('{"key": "value"}')
            for k, v in pairs(data) do
                print(string.format("%s = %s", tostring(k), tostring(v)))
            end
            "#,
        ]);
        let result = check_lua_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
