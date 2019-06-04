use super::clean_up_scenario;
use super::get_recipients;
use super::set_up;

#[test]
pub fn test_add_default_gpg() {
    let scenario_name = "add_gpg_default";
    let mut context = set_up(scenario_name);
    let test_file = "test.gpg";
    let default_key_name = "126DF511181C21E94E688C44AA8A6BE01EB30743";
    let default_key_encrypt_id = "9C722DBE12764E6A";

    let initial_recipients = get_recipients(&mut context, scenario_name, test_file);
    if initial_recipients.is_none() {
        panic!("Unable to decode test file");
    }
    let initial_recipients = initial_recipients.unwrap();

    if initial_recipients.contains(default_key_encrypt_id) {
        panic!("test file already encoded for test key")
    }
    let conf = crate::config::Config::new(default_key_name.to_string());
    let empty_gpgs = Vec::new();
    crate::add_gpgs(&empty_gpgs, &mut context, &conf);

    let final_recipients = get_recipients(&mut context, scenario_name, test_file);
    if final_recipients.is_none() {
        panic!("Unable to decode test file");
    }

    let final_recipients = final_recipients.unwrap();
    if !final_recipients.contains(default_key_encrypt_id) {
        panic!("test file wasn't reencoded!");
    }
    clean_up_scenario(scenario_name);
}

#[test]
pub fn test_add_tld_gpgs() {
    let scenario_name = "add_gpg_tld";
    let mut context = set_up(scenario_name);
    let test_file = "test.gpg";
    let default_key_name = "126DF511181C21E94E688C44AA8A6BE01EB30743";
    let new_key1 = "13F785075D7EBE21";
    let new_key2 = "BF2DF468D5540F34";

    let initial_recipients = get_recipients(&mut context, scenario_name, test_file);
    if initial_recipients.is_none() {
        panic!("Unable to decode test file");
    }
    let initial_recipients = initial_recipients.unwrap();

    if initial_recipients.contains(new_key1) {
        panic!("test file already encoded for test key1")
    }
    if initial_recipients.contains(new_key2) {
        panic!("test file already encoded for test key2")
    }

    let conf = crate::config::Config::new(default_key_name.to_string());
    let new_gpgs = vec![
        "temp1@localhost".to_string(),
        "signer@pubkey.localhost".to_string(),
    ];
    crate::add_gpgs(&new_gpgs, &mut context, &conf);

    let final_recipients = get_recipients(&mut context, scenario_name, test_file);
    if final_recipients.is_none() {
        panic!("Unable to decode test file");
    }

    let final_recipients = final_recipients.unwrap();
    if !final_recipients.contains(new_key1) {
        panic!("test file wasn't reencoded for key 1!");
    }
    if !final_recipients.contains(new_key2) {
        panic!("test file wasn't reencoded for key 2!");
    }
    clean_up_scenario(scenario_name);
}

#[test]
pub fn test_add_subdir_gpgs() {
    let scenario_name = "add_gpg_subdir";
    let mut context = set_up(scenario_name);
    let test_file = "subdir/test.gpg";
    let default_key_name = "126DF511181C21E94E688C44AA8A6BE01EB30743";
    let new_key1 = "13F785075D7EBE21";
    let new_key2 = "BF2DF468D5540F34";

    let initial_recipients = get_recipients(&mut context, scenario_name, test_file);
    if initial_recipients.is_none() {
        panic!("Unable to decode test file");
    }
    let initial_recipients = initial_recipients.unwrap();

    if initial_recipients.contains(new_key1) {
        panic!("test file already encoded for test key1")
    }
    if initial_recipients.contains(new_key2) {
        panic!("test file already encoded for test key2")
    }

    let conf = crate::config::Config::new(default_key_name.to_string());
    let new_gpgs = vec![
        "-p".to_string(),
        "subdir".to_string(),
        "temp1@localhost".to_string(),
        "signer@pubkey.localhost".to_string(),
    ];
    crate::add_gpgs(&new_gpgs, &mut context, &conf);

    let final_recipients = get_recipients(&mut context, scenario_name, test_file);
    if final_recipients.is_none() {
        panic!("Unable to decode test file");
    }

    let final_recipients = final_recipients.unwrap();
    if !final_recipients.contains(new_key1) {
        panic!("test file wasn't reencoded for key 1!");
    }
    if !final_recipients.contains(new_key2) {
        panic!("test file wasn't reencoded for key 2!");
    }
    clean_up_scenario(scenario_name);
}
