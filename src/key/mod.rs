mod folder;
mod gpg_id;
mod parser;
use super::command;
pub use folder::get_key_ids;

pub fn parse_keys() -> Result<Vec<Key>, String> {
    let gpg_version = parser::get_gpg_version();

    let parser = if gpg_version.is_none() {
        parser::ParserV2::new()
    } else {
        let gpg_version_str = gpg_version.unwrap();
        match gpg_version_str.as_str() {
            "2.1.4" => parser::ParserV2::new(),
            _ => {
                eprintln!("WARNING: UNSUPPORTED GPG VERSION: {}", gpg_version_str);
                parser::ParserV2::new()
            }
        }
    };
    let list_key_output = command::get_command_output("gpg", &["--list-keys"]);
    if list_key_output.is_err() {
        return Err("unable to get list key output".to_string());
    }
    let list_key_str = list_key_output.unwrap();
    let mut lines = list_key_str.lines();
    lines.next();
    lines.next();
    let pub_keys_res = parser::parse_keys(&parser, lines);
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

    let sec_keys_res = parser::parse_keys(&parser, sec_lines);
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

pub struct Key {
    identity: String,
    fingerprint: String,
    has_secret_key: bool,
}

impl Key {
    pub fn new(identity: String, fingerprint: String, has_secret_key: bool) -> Key {
        Key {
            identity,
            fingerprint,
            has_secret_key,
        }
    }

    pub fn get_fingerprint(&self) -> &str {
        &self.fingerprint
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
