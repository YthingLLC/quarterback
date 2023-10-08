mod repl;
use crate::repl::repl_base;
fn main() {
    println!("REPL Test:");
    println!();

    let _ = repl_base(eval);
}

fn eval(input: &str) -> Option<()> {
    println!("{input}");
    println!();
    Some(())
}
