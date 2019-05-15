use std::io::stdout;
use std::io::Write;
use std::io::BufRead;

#[cfg(test)]
fn get_stdin() -> &'static [u8] {
    unsafe { super::test::TEST_STDIN }
}

#[cfg(not(test))]
fn get_stdin() -> Stdin {
    std::io::stdin()
}

pub fn prompt(prompt: &str) -> String {
    print!("{} ", prompt);
    stdout().flush().unwrap();
    let mut input = String::new();
    
    let mut stdin_source = get_stdin();
    
    let res = stdin_source.read_line(&mut input);
    if res.is_err() {
        eprintln!("No input received");
        std::process::exit(1);
    }

    input
}

pub fn menu(prompt_str: &str, options: &[&str], default: Option<usize>) -> usize {
    loop {
        println!("{}", prompt_str);

        let mut index = 0;
        while index < options.len() {
            let is_default = if default.is_none() {
                false
            } else {
                &index == default.as_ref().unwrap()
            };

            let default_str = if is_default { "[default]" } else { "" };
            println!("[ {} ]: {} {}", index + 1, options[index], default_str);
            index += 1;
        }

        let choice_full = prompt("> ");
        let choice = choice_full.trim();
        if choice.is_empty() && default.is_some() {
            return default.unwrap();
        }

        let usize_parse = choice.parse::<usize>();
        if usize_parse.is_err() {
            eprintln!("Unable to parse input, please try again!");
            continue;
        }

        let num_choice = usize_parse.unwrap();
        if 0 < num_choice && num_choice > options.len() {
            eprintln!("Choice is out of bounds, please try again!");
            continue;
        }

        return num_choice - 1;
    }
}
