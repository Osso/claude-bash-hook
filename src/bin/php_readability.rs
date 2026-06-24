use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

const SCRIPT_PATH: &str = "/home/osso/AgentConfig/skills/php-readability/scripts/audit-repo.py";
const PYTHON: &str = "/usr/bin/python3";

fn main() {
    let script = Path::new(SCRIPT_PATH);
    if !script.is_file() {
        eprintln!("php-readability: script not found: {}", script.display());
        std::process::exit(127);
    }

    let err = Command::new(PYTHON)
        .arg(script)
        .args(std::env::args_os().skip(1))
        .exec();

    eprintln!("php-readability: failed to exec {PYTHON}: {err}");
    std::process::exit(127);
}
