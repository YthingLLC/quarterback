mod repl;
use crate::repl::repl_base;
fn main() {
    println!("REPL Test:");
    println!();

    repl_base(eval);
}

fn eval(input: &str) -> Option<()> {
    println!("{input}");
    Some(())
}
