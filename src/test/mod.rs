mod sync;

use gpgme::Context;
use gpgme::KeyListMode;
use gpgme::Protocol;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

pub static mut TEST_STDIN: &[u8] = b"";

fn get_scenario_runtime_path(scenario_name: &str) -> PathBuf {
    Path::new("testing").join(scenario_name.to_string() + "_run")
}

fn clean_up_scenario(scenario_name: &str) {
    let runtime_path = get_scenario_runtime_path(scenario_name);
    fs::remove_dir_all(runtime_path).unwrap();
}

fn write_to_stdin(input: &'static str) {
    unsafe {
        TEST_STDIN = input.as_bytes();
    }
}

fn set_up(scenario_name: &str) -> Context {
    let from_path = Path::new("testing").join(scenario_name);
    let to_path = get_scenario_runtime_path(scenario_name);
    let _clean = fs::remove_dir_all(&to_path);
    let copy_status = Command::new("cp")
        .arg("-r")
        .arg(from_path.to_str().unwrap())
        .arg(to_path.to_str().unwrap())
        .status()
        .expect("Unable to create runtime testing environment");
    if !copy_status.success() {
        panic!("Unable to copy for runtime testing environment");
    }

    std::env::set_var("GNUPGHOME", to_path.join("gnupg"));
    std::env::set_var("PASSWORD_STORE_DIR", to_path.join("pass"));
    let mut context = Context::from_protocol(Protocol::OpenPgp).unwrap();
    context.set_armor(true);
    let mut key_list_mode = KeyListMode::empty();
    key_list_mode.insert(KeyListMode::LOCAL);
    key_list_mode.insert(KeyListMode::SIGS);
    context.set_key_list_mode(key_list_mode).unwrap();
    context
}
