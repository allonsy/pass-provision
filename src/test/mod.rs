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

fn is_signed_by(context: &mut Context, key_id: &str, signer_identity: &str) -> bool {
    let key = context.get_key(key_id);
    if key.is_err() {
        return false;
    }
    let key = key.unwrap();

    for user_id in key.user_ids() {
        for sig in user_id.signatures() {
            let signer_id = sig.signer_key_id();
            if signer_id.is_ok() && !sig.is_invalid() {
                let signer_id = signer_id.unwrap();
                if signer_id == signer_identity {
                    return true;
                }
            }
        }
    }
    false
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

#[test]
fn test_key_import() {
    let testing_key_id = "AA8A6BE01EB30743";
    let newkey1_id = "A849644DA452281D2EB637EA9FEBCD1F791BC6B9";
    let newkey2_id = "D54BA99B7CD92448901306F46AD31A01C5E25FA2";

    let mut context = set_up("import_keys");
    let new_key1 = context.get_key(newkey1_id);
    if new_key1.is_ok() {
        panic!("Newkey1 is already present in keyring");
    }
    let new_key2 = context.get_key(newkey2_id);
    if new_key2.is_ok() {
        panic!("Newkey2 is already present in keyring");
    }
    write_to_stdin("\n\n");
    super::check_keys_to_import(&mut context);
    let new_key1 = context.get_key(newkey1_id);
    let new_key2 = context.get_key(newkey2_id);

    if new_key1.is_err() {
        panic!("Newkey1 not imported");
    }
    if !is_signed_by(&mut context, newkey1_id, testing_key_id) {
        panic!("Newkey1 imported but it isn't trusted");
    }

    if new_key2.is_err() {
        panic!("Newkey2 not imported");
    }

    if !is_signed_by(&mut context, newkey2_id, testing_key_id) {
        panic!("Newkey2 imported but it isn't trusted");
    }

    clean_up_scenario("import_keys");
}

#[test]
fn test_key_import_no_sigs() {
    let newkey1_id = "A849644DA452281D2EB637EA9FEBCD1F791BC6B9";
    let testing_key_id = "AA8A6BE01EB30743";

    let mut context = set_up("import_keys_no_sigs");
    let new_key1 = context.get_key(newkey1_id);
    if new_key1.is_ok() {
        panic!("Newkey1 is already present in keyring");
    }
    write_to_stdin("\n");
    super::check_keys_to_import(&mut context);
    let new_key1 = context.get_key(newkey1_id);

    if new_key1.is_ok() && is_signed_by(&mut context, newkey1_id, testing_key_id) {
        panic!("Newkey1 imported but it is trusted");
    }
    clean_up_scenario("import_keys_no_sigs");
}

#[test]
fn test_key_import_new_key() {
    let newkey1_id = "A849644DA452281D2EB637EA9FEBCD1F791BC6B9";
    let testing_key_id = "AA8A6BE01EB30743";

    let mut context = set_up("import_keys_new_key");
    let new_key1 = context.get_key(newkey1_id);
    if new_key1.is_ok() {
        panic!("Newkey1 is already present in keyring");
    }
    write_to_stdin("1\n");
    super::check_keys_to_import(&mut context);
    let new_key1 = context.get_key(newkey1_id);

    if new_key1.is_ok() && !is_signed_by(&mut context, newkey1_id, testing_key_id) {
        panic!("Newkey1 imported but it is trusted");
    }
    clean_up_scenario("import_keys_new_key");
}

#[test]
fn test_key_import_fraud_id() {
    let newkey1_id = "A849644DA452281D2EB637EA9FEBCD1F791BC6B9";
    let testing_key_id = "AA8A6BE01EB30743";

    let mut context = set_up("import_keys_fraud_id");
    let new_key1 = context.get_key(newkey1_id);
    if new_key1.is_ok() {
        panic!("Newkey1 is already present in keyring");
    }
    write_to_stdin("\n");
    super::check_keys_to_import(&mut context);
    let new_key1 = context.get_key(newkey1_id);

    if new_key1.is_ok() && is_signed_by(&mut context, newkey1_id, testing_key_id) {
        panic!("Newkey1 imported but it is trusted");
    }
    clean_up_scenario("import_keys_fraud_id");
}
