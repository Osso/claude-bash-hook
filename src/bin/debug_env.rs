use tree_sitter::Parser;

fn main() {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_bash::LANGUAGE.into()).unwrap();
    
    let cmd = "env VAR=1 rm -rf /tmp";
    let tree = parser.parse(cmd, None).unwrap();
    
    println!("S-expr:\n{}", tree.root_node().to_sexp());
}
