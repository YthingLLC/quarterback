use std::io;
use std::io::Write;

pub fn repl_base(evaluator: impl Fn(&str) -> Option<()>) {
    loop {
        let mut input = String::new();

        print!("> ");

        io::stdout()
            .flush()
            .expect("flush to stdout should not fail!");

        io::stdin()
            .read_line(&mut input)
            .expect("failed to read line!");

        match evaluator(input.as_str()) {
            Some(_) => continue,
            None => break,
        }
    }
}
