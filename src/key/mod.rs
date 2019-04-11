mod folder;
pub mod gpg_id;
use super::prompt;
pub use folder::get_key_ids;
use gpgme::Context;
use std::fs;

pub fn get_keys(context: &mut Context) -> Result<Vec<Key>, String> {
    let mut pub_keys = Vec::new();
    let key_iterator = context.keys();
    if key_iterator.is_err() {
        return Err(key_iterator.err().unwrap().description().to_string());
    }

    for key in key_iterator.unwrap() {
        if key.is_err() {
            eprintln!("Unable to read key");
            continue;
        }
        let key = key.unwrap();

        let parsed_key = Key::parse_key(&key)?;
        pub_keys.push(parsed_key);
    }

    Ok(pub_keys)
}

pub fn get_secret_keys(context: &mut Context) -> Result<Vec<Key>, String> {
    let mut priv_keys = Vec::new();
    let key_iterator = context.secret_keys();
    if key_iterator.is_err() {
        return Err(key_iterator.err().unwrap().description().to_string());
    }

    for key in key_iterator.unwrap() {
        if key.is_err() {
            eprintln!("Unable to read secret key");
            continue;
        }
        let key = key.unwrap();

        let parsed_key = Key::parse_key(&key)?;
        priv_keys.push(parsed_key);
    }

    Ok(priv_keys)
}

pub fn get_key(context: &mut Context, fingerprint: &str) -> Option<Key> {
    let gpg_key = context.get_key(fingerprint);
    if gpg_key.is_err() {
        return None;
    }

    let key = Key::parse_key(&gpg_key.unwrap());
    if key.is_err() {
        return None;
    }

    Some(key.unwrap())
}

pub fn import_key(context: &mut Context, fingerprint: String) -> Option<Key> {
    let keys_dir = folder::get_keys_dir();
    let key_path = keys_dir.join(fingerprint.clone() + ".asc");
    if !key_path.exists() {
        eprintln!("Unable to find pubkey file for key: {}", fingerprint);
        return None;
    }
    let key_contents = fs::read_to_string(&key_path);
    if key_contents.is_err() {
        eprintln!("Unable to read key: {}", fingerprint);
        return None;
    }

    let import_result = context.import(key_contents.unwrap());
    if import_result.is_err() {
        eprintln!("Unable to import key for fingerprint: {}", fingerprint);
        return None;
    }
    let import_result = import_result.unwrap();

    let imported_gpg_key = context.get_key(&fingerprint);

    if imported_gpg_key.is_err() {
        eprintln!(
            "FRAUD DETECTED ON IMPORT, PLEASE DOUBLE CHECK KEY AT: {}",
            fingerprint
        );
        return None;
    }
    let imported_gpg_key = imported_gpg_key.unwrap();
    let imported_key = Key::parse_key(&imported_gpg_key);
    if imported_key.is_err() {
        return None;
    }
    let imported_key = imported_key.unwrap();

    let key_imports = import_result.imports();
    let mut should_check_sigs = false;
    for key_import in key_imports {
        if key_import.fingerprint().unwrap() != fingerprint {
            println!("FRAUD DETECTED ON IMPORT OF: {}", fingerprint);
        }
        if key_import.status() == gpgme::ImportFlags::NEW {
            should_check_sigs = true;
        }
    }
    if !should_check_sigs {
        return Some(imported_key);
    }

    let mut good_signatures = Vec::new();

    for user_id in imported_gpg_key.user_ids() {
        for sig in user_id.signatures() {
            if sig.is_invalid() || sig.is_expired() || sig.is_revocation() {
                continue;
            }
            if sig.status() == gpgme::Error::NO_ERROR {
                let good_uid = sig.signer_user_id();
                if good_uid.is_ok() {
                    good_signatures.push(good_uid.unwrap().to_string());
                }
            }
        }
    }

    if good_signatures.is_empty() {
        let prompt_str = format!(
            "No recognized signatures found. Would you like to sign key for: {}?",
            imported_key.get_identity()
        );
        let choice = prompt::menu(&prompt_str, &["Yes", "No"], Some(1));
        println!("Choice is: {}", choice);
        if choice == 0 {
            println!(
                "Please verify the following signature: {}",
                imported_key.get_pretty_fingerprint()
            );
            let confirm = prompt::menu(
                "Are you sure that you want to sign?",
                &["Yes", "No"],
                Some(1),
            );
            if confirm == 1 {
                eprintln!("Key: {} not signed", fingerprint);
                return None;
            } else {
                let res = context.sign_key(&imported_gpg_key, vec![&imported_key.identity], None);
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

    println!(
        "The Key: <{}> is signed by the following verified signatures: ",
        imported_key.get_identity()
    );

    for identity in good_signatures {
        println!("\t{}", identity);
    }
    let choice = prompt::menu("Would you like to sign the key?", &["Yes", "No"], Some(0));

    if choice == 0 {
        let res = context.sign_key(&imported_gpg_key, vec![&imported_key.identity], None);
        if res.is_err() {
            eprintln!("Unable to sign key");
            None
        } else {
            Some(imported_key)
        }
    } else {
        eprintln!("Didn't sign key");
        None
    }
}

pub struct Key {
    identity: String,
    fingerprint: String,
    has_secret_key: bool,
}

impl Key {
    pub fn parse_key(key: &gpgme::Key) -> Result<Key, String> {
        let mut identity = String::new();
        for user_id in key.user_ids() {
            let identity_result = user_id.email();
            if identity_result.is_err() {
                eprintln!("Unable to read userid identity");
                continue;
            }
            identity = identity_result.unwrap().to_string();
        }
        if identity.is_empty() {
            return Err("No userids found for key".to_string());
        }

        let fingerprint = key.fingerprint();
        if fingerprint.is_err() {
            return Err(format!(
                "Unable to read key fingerpring for id: {}",
                identity
            ));
        }
        let fingerprint = fingerprint.unwrap().to_string();

        let has_secret_key = key.has_secret();
        Ok(Key {
            identity,
            fingerprint,
            has_secret_key,
        })
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

    pub fn write_key(&self, context: &mut Context) {
        let keys_dir = folder::get_keys_dir();
        let fname = format!("{}.asc", self.fingerprint);
        let abs_path = keys_dir.join(fname);
        let mut exported_bytes = Vec::new();

        let key_to_export = context.get_key(&self.fingerprint);
        if key_to_export.is_err() {
            eprintln!(
                "Unable to locate key for exporting for fingerprint: {}",
                self.fingerprint
            );
            std::process::exit(1);
        }
        let export_res = context.export_keys(
            vec![&key_to_export.unwrap()],
            gpgme::ExportMode::empty(),
            &mut exported_bytes,
        );
        if export_res.is_err() {
            eprintln!("Unable to export key for fingerprint: {}", self.fingerprint);
            std::process::exit(1);
        }

        let write_res = fs::write(&abs_path, exported_bytes);
        if write_res.is_err() {
            eprintln!(
                "Unable to write exported key for fingerprint: {}",
                self.fingerprint
            );
            std::process::exit(1);
        }
    }
}
