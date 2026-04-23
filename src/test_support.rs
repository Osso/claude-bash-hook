use crate::analyzer::Command;
use std::sync::{LazyLock, Mutex, MutexGuard};

pub fn make_command(name: &str, args: &[&str]) -> Command {
    Command {
        name: name.to_string(),
        args: args.iter().map(|arg| arg.to_string()).collect(),
    }
}

/// Guard that serializes tests mutating process-global env vars (HOME, PATH).
/// Cargo runs tests in parallel by default; env vars are per-process, so
/// concurrent `set_var` calls race. Acquire this before touching env vars.
static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
