use super::clean_up_scenario;
use super::get_recipients;
use super::get_scenario_runtime_path;
use super::set_up;
use std::collections::HashSet;
use std::iter::FromIterator;

#[test]
pub fn test_reencrypt_main() {
    let scenario_name = "reencrypt_main";
    let mut context = set_up(scenario_name);

    let recipients = get_recipients(&mut context, scenario_name, "test.gpg");
    if recipients.is_none() {
        panic!("Unable to decode test file");
    }

    let new_recipients = HashSet::from_iter(vec!["signer@pubkey.localhost".to_string()]);
    let gpg_path = get_scenario_runtime_path(scenario_name).join("pass");
    crate::key::gpg_id::write_gpg_ids(&gpg_path, &new_recipients);

    crate::reencrypt_cmd(&Vec::new());

    let new_recipients = get_recipients(&mut context, scenario_name, "test.gpg");
    if new_recipients.is_some() {
        panic!("Failed to reencrypt main directory");
    }
    clean_up_scenario(scenario_name);
}

#[test]
pub fn test_reencrypt_subdir() {
    let scenario_name = "reencrypt_subdir";
    let mut context = set_up(scenario_name);

    let recipients = get_recipients(&mut context, scenario_name, "test.gpg");
    if recipients.is_none() {
        panic!("Unable to decode test file");
    }
    let subdir_recipients = get_recipients(&mut context, scenario_name, "subdir/test.gpg");
    if subdir_recipients.is_none() {
        panic!("Unable to decode test subdir file");
    }

    let new_recipients = HashSet::from_iter(vec!["signer@pubkey.localhost".to_string()]);
    let gpg_path = get_scenario_runtime_path(scenario_name)
        .join("pass")
        .join("subdir");
    crate::key::gpg_id::write_gpg_ids(&gpg_path, &new_recipients);

    crate::reencrypt_cmd(&["subdir".to_string()]);

    let new_recipients = get_recipients(&mut context, scenario_name, "test.gpg");
    if new_recipients.is_none() {
        panic!("Reencrypt reencrypted main repo");
    }

    let subdir_new_recipients = get_recipients(&mut context, scenario_name, "subdir/test.gpg");
    if subdir_new_recipients.is_some() {
        panic!("Failed to reencrypt subdir");
    }
    clean_up_scenario(scenario_name);
}
