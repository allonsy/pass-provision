use super::clean_up_scenario;
use super::set_up;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::path::Path;

#[test]
fn test_all_gpgs() {
    let _ = set_up("all_gpgs");
    let all_gpgs = crate::key::gpg_id::get_all_gpgs();
    let expected_hash_set = HashSet::from_iter(vec![
        "user1".to_string(),
        "user2".to_string(),
        "user3".to_string(),
        "user4".to_string(),
        "user5".to_string(),
        "user6".to_string(),
        "user7".to_string(),
    ]);
    assert_eq!(expected_hash_set, all_gpgs);
    clean_up_scenario("all_gpgs")
}

#[test]
fn test_subdir_gpgs() {
    let _ = set_up("all_gpgs");
    let all_gpgs =
        crate::key::gpg_id::get_base_gpgs_for_dir(&Path::new("testing/all_gpgs_run/pass/subdir"));
    let expected_hash_set = HashSet::from_iter(vec!["user4".to_string(), "user5".to_string()]);
    assert_eq!(expected_hash_set, all_gpgs);
    clean_up_scenario("all_gpgs")
}

#[test]
fn test_write_gpgs() {
    let _ = set_up("all_gpgs");
    let new_hash = HashSet::from_iter(vec![
        "user1".to_string(),
        "user2".to_string(),
        "user3".to_string(),
        "user4".to_string(),
        "user5".to_string(),
        "user6".to_string(),
        "user7".to_string(),
    ]);
    let base_path = Path::new("testing/all_gpgs_run/pass");
    let old_gpgs = crate::key::gpg_id::get_base_gpgs_for_dir(&base_path);
    assert_ne!(old_gpgs, new_hash);
    crate::key::gpg_id::write_gpg_ids(&base_path, &new_hash);
    let read_gpgs = crate::key::gpg_id::get_base_gpgs_for_dir(&base_path);
    assert_eq!(read_gpgs, new_hash);
    clean_up_scenario("all_gpgs")
}
