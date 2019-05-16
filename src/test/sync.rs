use super::clean_up_scenario;
use super::set_up;
use super::write_to_stdin;
use gpgme::Context;
use std::path::PathBuf;
use std::process::Command;

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
    crate::check_keys_to_import(&mut context);
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
    crate::check_keys_to_import(&mut context);
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
    crate::check_keys_to_import(&mut context);
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
    crate::check_keys_to_import(&mut context);
    let new_key1 = context.get_key(newkey1_id);

    if new_key1.is_ok() && is_signed_by(&mut context, newkey1_id, testing_key_id) {
        panic!("Newkey1 imported but it is trusted");
    }
    clean_up_scenario("import_keys_fraud_id");
}

#[test]
fn test_fresh_sigs() {
    let mut context = set_up("fresh_sigs");
    crate::add_fresh_sigs(&mut context);

    for (expected_name, actual_name) in &[
        (
            "newkey1.expected",
            "A849644DA452281D2EB637EA9FEBCD1F791BC6B9.asc",
        ),
        (
            "newkey2.expected",
            "D54BA99B7CD92448901306F46AD31A01C5E25FA2.asc",
        ),
    ] {
        let actual_path = PathBuf::from("testing/fresh_sigs_run/pass/.keys").join(actual_name);
        let expected_path = PathBuf::from("testing/fresh_sigs_run").join(expected_name);
        let diff_command = Command::new("diff")
            .arg(actual_path.to_str().unwrap())
            .arg(expected_path.to_str().unwrap())
            .status()
            .expect("Expected diff command to succeed");
        if !diff_command.success() {
            panic!("Key '{}' not updated", actual_name);
        }
    }
    clean_up_scenario("fresh_sigs");
}

#[test]
fn test_write_keys() {
    let mut context = set_up("write_keys");
    crate::add_fresh_sigs(&mut context);

    let keys = crate::key::get_keys(&mut context).unwrap();
    crate::write_missing_keys(&mut context, &keys);

    let actual_key_path =
        "testing/write_keys_run/pass/.keys/A849644DA452281D2EB637EA9FEBCD1F791BC6B9.asc";
    let expected_key_path = "testing/write_keys_run/newkey1.expected";
    let diff_command = Command::new("diff")
        .arg(actual_key_path)
        .arg(expected_key_path)
        .status()
        .expect("Expected diff command to succeed");
    if !diff_command.success() {
        panic!(
            "Key: {} not written",
            "A849644DA452281D2EB637EA9FEBCD1F791BC6B9"
        );
    }

    clean_up_scenario("write_keys");
}
