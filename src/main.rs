mod command;
mod key;
mod prompt;
mod config;

use gpgme::Context;
use std::collections::HashSet;

fn main() {
    let (conf, mut context) = init();
    let default_key = context.get_key(conf.get_default_key());
    if default_key.is_err() {
        eprintln!("Unable to locate default key: {} in keyring", conf.get_default_key());
        std::process::exit(1);
    }
    let signer_res = context.add_signer(&default_key.unwrap());
    if signer_res.is_err() {
        eprintln!("Unable to add default key as a signer");
        std::process::exit(1);
    }

    let keys_res = key::get_keys(&mut context);
    if keys_res.is_err() {
        eprintln!("Unable to read gpg keys!");
        std::process::exit(1);
    }
    let mut keys = keys_res.unwrap();
    sync(&mut context, &mut keys);
}

fn sync(context: &mut Context, keys: &mut Vec<key::Key>) {
    check_keys_to_import(context, keys);
    add_fresh_sigs(context);
    write_missing_keys(context, keys);
}

fn check_keys_to_import(context: &mut Context, keys: &mut Vec<key::Key>) {
    let keys_in_folder = key::get_key_ids();
    for key in keys_in_folder {
        let mut found = false;
        for present_key in keys.iter() {
            if present_key.get_fingerprint() == key {
                found = true;
            }
        }
        if !found {
            let new_key = key::import_key(context, key);
            if new_key.is_some() {
                let actual_new_key = new_key.unwrap();
                actual_new_key.write_key(context);
                keys.push(actual_new_key);
                println!("Imported key");
            }
        }
    }
}

fn add_fresh_sigs(context: &mut Context) {
    let keys_in_folder = key::get_key_ids();

    for fpr in keys_in_folder {
        let key = key::get_key(context, &fpr);
        if key.is_none() {
            eprintln!("Unable to find key: {} in keyring", fpr);
            continue;
        }
        let key = key.unwrap();
        key.write_key(context);
    }
}

fn write_missing_keys(context: &mut Context, keys: &Vec<key::Key>) {
    let gpgs = key::gpg_id::get_all_gpgs();

    let written_keys = key::get_key_ids();

    for gpg in gpgs {
        for key in keys {
            if key.get_identity() == gpg {
                let mut found = false;
                for written_key in written_keys.iter() {
                    if written_key == key.get_fingerprint() {
                        found = true;
                    }
                }
                if !found {
                    println!("Writing key for identity: {}", key.get_identity());
                    key.write_key(context);
                }
            }
        }
    }
}

fn init() -> (config::Config, Context) {
    let context = Context::from_protocol(gpgme::Protocol::OpenPgp);
    if context.is_err() {
        eprintln!("Unable to get gpg context. Do you have gpgme installed?");
        std::process::exit(1);
    }
    let mut context = context.unwrap();
    context.set_armor(true);
    context.clear_signers();


    let config_path = config::get_config_file_location();
    if config_path.exists() {
        let conf = config::Config::parse_config();
        if conf.is_some() {
            return (conf.unwrap(), context);
        }
    }

    let mut key_options = Vec::new();
    let keys = key::get_secret_keys(&mut context);
    if keys.is_err() {
        eprintln!("Unable to read keys from GPG");
        std::process::exit(1);
    }
    let keys = keys.unwrap();
    let mut seen_before = HashSet::new();
    let mut key_index = Vec::new();
    for key_val in keys {
        if key_val.has_secret_key() {
            key_options.push(format!("<{}> ({})", key_val.get_identity(), key_val.get_short_fingerprint()));
            seen_before.insert(key_val.get_fingerprint().to_string());
            key_index.push(key_val.get_fingerprint().to_string());
        }
    }
    key_options.push("Create new key".to_string());

    loop {
        println!("It looks like you haven't yet set up pass-provision");
        let choice = prompt::menu("Please select which key you use to decrypt for pass", &(key_options.iter().map(String::as_str).collect::<Vec<&str>>()), Some(0));
        println!("choice is: {}", choice);
        if choice == key_options.len() - 1 {
            let res = command::oneshot_command("gpg", &["--full-gen-key"]);
            if res.is_err() {
                eprintln!("Failed key gen");
                eprintln!("Please try again");
                continue;
            }

            let new_keys = key::get_keys(&mut context);
            if new_keys.is_err() {
                eprintln!("Unable to read keys from GPG");
                std::process::exit(1);
            }
            let new_keys = new_keys.unwrap();
            for new_key in new_keys {
                if new_key.has_secret_key() {
                    if !seen_before.contains(new_key.get_fingerprint()) {
                        let conf = config::Config::new(new_key.get_fingerprint().to_string());
                        conf.write_config();
                        return (conf, context);
                    }
                }
            }
            eprintln!("Unable to locate newly created key!");
            std::process::exit(1);
        } else {
            let conf = config::Config::new(key_index[choice].to_string());
            conf.write_config();
            return (conf, context);
        }
    }
}
