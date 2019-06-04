mod command;
mod config;
mod key;
mod prompt;
#[cfg(test)]
mod test;
use gpgme::Context;

use gpgme::KeyListMode;
use std::collections::HashSet;
use std::env;

fn main() {
    let (conf, mut context) = init();
    let default_key = context.get_key(conf.get_default_key());
    if default_key.is_err() {
        eprintln!(
            "Unable to locate default key: {} in keyring",
            conf.get_default_key()
        );
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

    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        sync(&mut context, &mut keys);
        return;
    }

    match args[1].as_str() {
        "sync" => {
            sync(&mut context, &mut keys);
        }
        "gpg-add" => {
            add_gpgs(&args[2..], &mut context, &conf);
        }
        "reencrypt" => {
            reencrypt_cmd(&args[2..]);
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn sync(context: &mut Context, keys: &mut Vec<key::Key>) {
    check_keys_to_import(context);
    add_fresh_sigs(context);
    write_missing_keys(context, keys);
}

fn check_keys_to_import(context: &mut Context) {
    let keys_in_folder = key::get_key_ids();
    for key in keys_in_folder {
        key::import_key(context, key);
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

fn write_missing_keys(context: &mut Context, keys: &[key::Key]) {
    let gpgs = key::gpg_id::get_all_gpgs();

    let written_keys = key::get_key_ids();

    for gpg in gpgs {
        println!("found gpg: {}", gpg);
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

fn add_gpgs(gpgs: &[String], context: &mut Context, config: &config::Config) {
    let mut new_gpgs = Vec::new();
    let mut path = key::get_pass_dir();
    let mut sub_path = None;
    if gpgs.is_empty() {
        let default_key = key::get_key(context, config.get_default_key());
        if default_key.is_none() {
            eprintln!("No GPG ids provided and unable to find default key");
            std::process::exit(1);
        }
        let default_key = default_key.unwrap();
        new_gpgs.push(default_key.get_identity().to_string());
    } else if gpgs[0] == "-p" {
        if gpgs.len() == 1 {
            eprintln!("No path provided to -p argument");
            std::process::exit(1);
        }
        path = path.join(&gpgs[1]);
        sub_path = Some(gpgs[1].to_string());
        for gpg in &gpgs[2..] {
            new_gpgs.push(gpg.to_string());
        }
    } else {
        for gpg in gpgs {
            new_gpgs.push(gpg.to_string());
        }
    }

    let mut old_gpgs = key::gpg_id::get_gpgs_for_dir(&path);

    let mut changed = false;
    for new_gpg in new_gpgs {
        if !old_gpgs.contains(&new_gpg) {
            changed = true;
            old_gpgs.insert(new_gpg);
        }
    }

    if changed {
        key::gpg_id::write_gpg_ids(&path, &old_gpgs);
        reencrypt(sub_path);
    }
}

fn reencrypt_cmd(args: &[String]) {
    if args.is_empty() {
        reencrypt(None);
        return;
    }
    reencrypt(Some(args[0].clone()));
}

fn reencrypt(path: Option<String>) {
    let mut args = Vec::new();
    args.push("init");
    let path_str = if path.is_some() {
        path.as_ref().unwrap().clone()
    } else {
        String::new()
    };

    let base_path = key::get_pass_dir();
    let mut gpgs: Vec<String> = if path.is_some() {
        let joined_path = base_path.join(path.as_ref().unwrap());
        key::gpg_id::get_base_gpgs_for_dir(&joined_path)
            .into_iter()
            .collect()
    } else {
        key::gpg_id::get_base_gpgs_for_dir(&base_path)
            .into_iter()
            .collect()
    };
    gpgs.sort();

    if path.is_some() {
        args.push("-p");
        args.push(&path_str);
    }
    for gpg in &gpgs {
        args.push(gpg);
    }
    let res = command::oneshot_command("pass", &args);
    if res.is_err() {
        println!("Reencrypt failed");
        std::process::exit(1);
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
    let mut key_list_mode = KeyListMode::empty();
    key_list_mode.insert(KeyListMode::LOCAL);
    key_list_mode.insert(KeyListMode::SIGS);
    let list_mode_set_result = context.set_key_list_mode(key_list_mode);
    if list_mode_set_result.is_err() {
        eprintln!("Unable to read signatures from gpg context");
        std::process::exit(1);
    }

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
            key_options.push(format!(
                "<{}> ({})",
                key_val.get_identity(),
                key_val.get_short_fingerprint()
            ));
            seen_before.insert(key_val.get_fingerprint().to_string());
            key_index.push(key_val.get_fingerprint().to_string());
        }
    }
    key_options.push("Create new key".to_string());

    loop {
        println!("It looks like you haven't yet set up pass-provision");
        let choice = prompt::menu(
            "Please select which key you use to decrypt for pass",
            &(key_options
                .iter()
                .map(String::as_str)
                .collect::<Vec<&str>>()),
            Some(0),
        );
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
                if new_key.has_secret_key() && !seen_before.contains(new_key.get_fingerprint()) {
                    let conf = config::Config::new(new_key.get_fingerprint().to_string());
                    conf.write_config();
                    return (conf, context);
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
