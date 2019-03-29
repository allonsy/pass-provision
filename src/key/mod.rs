mod folder;
pub mod gpg_id;
mod parser;
use super::command;
use super::prompt;
pub use folder::get_key_ids;

pub fn get_keys() -> Result<Vec<Key>, String> {
    let parser = parser::get_parser();
    let list_key_output = command::get_command_output("gpg", &["--list-keys"]);
    if list_key_output.is_err() {
        return Err("unable to get list key output".to_string());
    }
    let list_key_str = list_key_output.unwrap();
    let mut lines = list_key_str.lines();
    lines.next();
    lines.next();
    let pub_keys_res = parser::parse_keys(parser.as_ref(), lines);
    if pub_keys_res.is_err() {
        return Err(pub_keys_res.err().unwrap());
    }
    let mut pub_keys = pub_keys_res.unwrap();

    let secret_key_output = command::get_command_output("gpg", &["--list-secret-keys"]);
    if secret_key_output.is_err() {
        return Err("Unable to retrieve secret key listings".to_string());
    }
    let secret_key_str = secret_key_output.unwrap();
    let mut sec_lines = secret_key_str.lines();
    sec_lines.next();
    sec_lines.next();

    let sec_keys_res = parser::parse_keys(parser.as_ref(), sec_lines);
    if sec_keys_res.is_err() {
        return Err(sec_keys_res.err().unwrap());
    }

    let sec_keys = sec_keys_res.unwrap();

    for key in &mut pub_keys {
        for sec_key in &sec_keys {
            if key.get_fingerprint() == sec_key.get_fingerprint() {
                key.set_has_secret_key(true);
            }
        }
    }

    Ok(pub_keys)
}

pub fn get_key(fingerprint: &str) -> Option<Key> {
    let parser = parser::get_parser();
    let list_key_output = command::get_command_output("gpg", &["--list-key", &fingerprint]);
    if list_key_output.is_err() {
        return None;
    }

    let unwrapped_output = list_key_output.unwrap();
    let lines = unwrapped_output.lines();
    let key_res = parser.parse_key(lines);
    if key_res.is_err() {
        return None;
    }
    let key_opt = key_res.unwrap();
    if key_opt.is_none() {
        return None;
    }

    let (key, _) = key_opt.unwrap();
    if !key.is_trusted() {
        return None;
    }
    
    Some(key)
}

pub fn get_default_key() -> Key {
    let keys = get_keys();
    if keys.is_err() {
        eprintln!("No default key available, please run init first");
        std::process::exit(1);
    }
    let actual_keys = keys.unwrap();
    if actual_keys.is_empty() {
        eprintln!("No default key available, please run init first");
        std::process::exit(1);
    }

    for key in actual_keys {
        return key;
    }

    panic!("No default key found");
}

pub fn import_key(fingerprint: String) -> Option<Key> {
    let keys_res = get_keys();
    if keys_res.is_err() {
        eprintln!("Unable to retrieve list of keys");
        return None;
    }
    let key_list = keys_res.unwrap();

    let keys_dir = folder::get_keys_dir();
    let key_path = keys_dir.join(fingerprint.clone() + ".asc");
    if !key_path.exists() {
        eprintln!("Unable to find pubkey file for key: {}", fingerprint);
        return None;
    }
    let key_path_str = format!("{}", key_path.display());
    let res = command::oneshot_command("gpg", &["--import", &key_path_str]);
    if res.is_err() {
        eprintln!("Importing key failed");
        return None;
    }

    let imported_key_opt = get_key(&fingerprint);
    if imported_key_opt.is_none() {
        eprintln!("Import key failure or fraud detected");
        return None;
    }
    let imported_key = imported_key_opt.unwrap();

    let sig_output = command::get_command_output("gpg", &["--check-signatures", &fingerprint]);
    if sig_output.is_err() {
        eprintln!("Unable to check signatures for key: {}", fingerprint);
        return None;
    }

    let parser = parser::get_parser();
    let sigs = parser.parse_sigs(sig_output.unwrap());

    let mut good_signatures = Vec::new();
    for sig in sigs.iter() {
        let (short_fingerprint, uid) = sig;
        let mut good = false;
        if short_fingerprint != imported_key.get_short_fingerprint() || uid == imported_key.get_identity() {
            for key in key_list.iter() {
                if short_fingerprint == key.get_short_fingerprint() && uid == key.get_identity() {
                    good = true;
                }
            }
        }
        if good {
            good_signatures.push(sig);
        }
    }

    if good_signatures.is_empty() {
        let prompt_str = format!("No recognized signatures found. Would you like to sign key for: {}?", imported_key.get_identity());
        let choice = prompt::menu(&prompt_str, &["Yes", "No"], Some(1));
        println!("Choice is: {}", choice);
        if choice == 0 {
            println!("Please verify the following signature: {}", imported_key.get_pretty_fingerprint());
            let confirm = prompt::menu("Are you sure that you want to sign?", &["Yes", "No"], Some(1));
            if confirm == 1 {
                eprintln!("Key: {} not signed", fingerprint);
                return None;
            } else {
                let default_key = get_default_key();
                let res = command::oneshot_command("gpg", &["-u", &default_key.get_fingerprint(), "--sign-key", &imported_key.get_fingerprint()]);
                if res.is_err() {
                    eprintln!("Unable to sign key: {}", fingerprint);
                    return None;
                } else {
                    return Some(imported_key);
                }
            }
        } else {
            eprintln!("Key: {} not signed", fingerprint);
            return None;
        }
    }

    println!("The Key: <{}> is signed by the following verified signatures: ", imported_key.get_identity());
    
    for (_, identity) in good_signatures {
        println!("\t{}", identity);
    }
    let choice = prompt::menu("Would you like to sign the key?", &["Yes", "No"], Some(0));

    if choice == 0 {
        let default_key = get_default_key();
        let res = command::oneshot_command("gpg", &["-u", &default_key.get_fingerprint(), "--sign-key", &imported_key.get_fingerprint()]);
        if res.is_err() {
            eprintln!("Unable to sign key");
            return None;
        } else {
            return Some(imported_key);
        }
    } else {
        eprintln!("Didn't sign key");
        return None;
    }



}

pub struct Key {
    identity: String,
    fingerprint: String,
    has_secret_key: bool,
    is_trusted: bool,
}

impl Key {
    pub fn new(identity: String, fingerprint: String, has_secret_key: bool, is_trusted: bool) -> Key {
        Key {
            identity,
            fingerprint,
            has_secret_key,
            is_trusted,
        }
    }

    pub fn get_fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn get_pretty_fingerprint(&self) -> String {
        let mut pretty = String::new();
        let mut start = 0;
        let fingerprint = &self.fingerprint;
        let fingerprint_len = fingerprint.len();
        while start < fingerprint_len {
            let mut end = start + 4;
            if end > fingerprint_len {
                end = fingerprint_len;
            }
            pretty += &fingerprint[start..end];
            if end != fingerprint_len {
                pretty += " ";
            }
            start += 4;
        }

        pretty
    }

    pub fn get_identity(&self) -> &str {
        &self.identity
    }

    pub fn has_secret_key(&self) -> bool {
        self.has_secret_key
    }

    pub fn get_short_fingerprint(&self) -> &str {
        let fingerprint_len = self.fingerprint.len();
        let start_index = fingerprint_len - 16;
        &self.fingerprint[start_index..fingerprint_len]
    }

    pub fn set_has_secret_key(&mut self, has_secret_key: bool) {
        self.has_secret_key = has_secret_key;
    }

    pub fn is_trusted(&self) -> bool {
        self.is_trusted
    }

    pub fn write_key(&self) {
        let keys_dir = folder::get_keys_dir();
        let fname = format!("{}.asc", self.fingerprint);
        let abs_path = keys_dir.join(fname);
        let full_output_path = format!("{}", abs_path.display());
        let success = command::oneshot_command(
            "gpg",
            &[
                "--armor",
                "--output",
                &full_output_path,
                "--export",
                &self.fingerprint,
            ],
        );
        if success.is_err() {
            eprintln!("Error writing key file for key: {}", self.identity);
        }
    }

    pub fn print_key(&self) {
        println!(
            "Key ident: {}, fpr: {}, secret key: {}",
            self.identity,
            self.fingerprint,
            self.has_secret_key()
        );
    }
}
