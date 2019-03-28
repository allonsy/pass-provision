mod command;
mod key;

fn main() {
    let keys = key::parse_keys();
    if keys.is_err() {
        println!("Key read error: {}", keys.err().unwrap());
        return;
    }
    let key_vec = keys.unwrap();

    for key_var in key_vec {
        key_var.print_key();
    }

    println!("present_keys: {:?}", key::get_key_ids());
}
