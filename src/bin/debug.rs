use tree_sitter::Parser;

fn main() {
    let mut parser = Parser::new();
    
    let language = tree_sitter_bash::LANGUAGE;
    match parser.set_language(&language.into()) {
        Ok(_) => println!("Language set successfully"),
        Err(e) => {
            println!("Failed to set language: {}", e);
            return;
        }
    }
    
    let cmd = "ls -la /tmp";
    match parser.parse(cmd, None) {
        Some(tree) => {
            let root = tree.root_node();
            println!("Root kind: {}", root.kind());
            println!("Has error: {}", root.has_error());
            println!("S-expr:\n{}", root.to_sexp());
        }
        None => println!("Failed to parse"),
    }
}
