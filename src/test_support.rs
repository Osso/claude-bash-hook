use crate::analyzer::Command;

pub fn make_command(name: &str, args: &[&str]) -> Command {
    Command {
        name: name.to_string(),
        args: args.iter().map(|arg| arg.to_string()).collect(),
    }
}
