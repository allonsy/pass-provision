use dirs;
use std::env;
use std::fs;
use std::path::PathBuf;

const PASS_DIR_VAR_NAME: &str = "PASSWORD_STORE_DIR";
const KEYS_DIR_NAME: &str = ".keys";
const PASSWORD_STORE_DEFAULT_NAME: &str = ".password-store";

pub fn get_key_ids() -> Vec<String> {
    let key_dir = get_keys_dir();
    let mut keys = Vec::new();

    let ls_dir_res = fs::read_dir(&key_dir);
    if ls_dir_res.is_err() {
        return keys;
    }

    for file in ls_dir_res.unwrap() {
        if file.is_ok() {
            let fpath = file.unwrap().path();
            let stem = fpath.file_stem();
            if stem.is_some() {
                keys.push(fpath.file_stem().unwrap().to_str().unwrap().to_string());
            }
        }
    }

    keys
}

pub fn get_keys_dir() -> PathBuf {
    let pass_dir = get_pass_dir();
    let key_dir = pass_dir.join(KEYS_DIR_NAME);
    if !key_dir.exists() {
        println!("creating dir: {}", key_dir.display());
        let err = fs::create_dir_all(&key_dir);
        if err.is_err() {
            eprintln!("Unable to create key dir");
            std::process::exit(1);
        }
    }

    key_dir
}

pub fn get_pass_dir() -> PathBuf {
    let pass_dir_env_var = env::var(PASS_DIR_VAR_NAME);

    let pass_dir = if pass_dir_env_var.is_ok() {
        PathBuf::from(pass_dir_env_var.unwrap())
    } else {
        let home_dir = dirs::home_dir();
        if home_dir.is_none() {
            eprintln!("Cannot find password store directory");
            std::process::exit(1);
        }
        home_dir.unwrap().join(PASSWORD_STORE_DEFAULT_NAME)
    };

    if !pass_dir.exists() {
        eprintln!("Password store directory doesn't exist!");
        std::process::exit(1);
    }

    pass_dir
}
