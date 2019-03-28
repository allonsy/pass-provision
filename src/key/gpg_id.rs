use super::folder;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;

const GPG_ID_FILE_NAME: &str = ".gpg_id";

pub fn get_all_gpgs() -> HashSet<String> {
    let pass_dir = folder::get_pass_dir();

    get_gpgs_for_dir(&pass_dir)
}

pub fn get_base_gpgs_for_dir(path: &Path) -> HashSet<String> {
    parse_gpg_id_file(&path.join(GPG_ID_FILE_NAME))
}

pub fn get_base_gpgs() -> HashSet<String> {
    let pass_dir = folder::get_pass_dir();
    get_base_gpgs_for_dir(&pass_dir)
}

pub fn write_gpg_ids(path: &Path, gpg_ids: HashSet<String>) {
    if !path.exists() {
        eprintln!(
            "Unable to write gpg_id file! path: {} doesn't exist",
            path.display()
        );
        std::process::exit(1);
    }
    let gpg_id_path = path.join(GPG_ID_FILE_NAME);
    let gpg_file_res = File::create(gpg_id_path);
    if gpg_file_res.is_err() {
        eprintln!("Unable to create gpg_id file!");
        std::process::exit(1);
    }
    let mut gpg_file = gpg_file_res.unwrap();

    for gpg_id in gpg_ids {
        let write_res = writeln!(&mut gpg_file, "{}", gpg_id);
        if write_res.is_err() {
            eprintln!("Unable to write to gpg_id file");
            std::process::exit(1);
        }
    }
}

fn get_gpgs_for_dir(path: &Path) -> HashSet<String> {
    let mut gpgs = HashSet::new();
    let gpg_file = path.join(GPG_ID_FILE_NAME);
    if gpg_file.exists() {
        let dir_gpgs = parse_gpg_id_file(&gpg_file);
        union_hash_set(&mut gpgs, dir_gpgs);
    }

    let read_dir_res = path.read_dir();
    if read_dir_res.is_err() {
        return gpgs;
    }

    for file in read_dir_res.unwrap() {
        if file.is_ok() {
            let entry = file.unwrap();
            let entry_path = entry.path();
            if entry_path.is_dir() {
                let dir_gpgs = get_gpgs_for_dir(&entry_path);
                union_hash_set(&mut gpgs, dir_gpgs);
            }
        }
    }

    gpgs
}

fn parse_gpg_id_file(path: &Path) -> HashSet<String> {
    let mut gpgs = HashSet::new();
    let gpg_file = File::open(path);
    if gpg_file.is_err() {
        return gpgs;
    }

    let mut contents = String::new();
    let read_res = gpg_file.unwrap().read_to_string(&mut contents);
    if read_res.is_err() {
        return gpgs;
    }

    for line in contents.lines() {
        gpgs.insert(line.to_string());
    }

    gpgs
}

fn union_hash_set(main: &mut HashSet<String>, secondary: HashSet<String>) {
    for elem in secondary {
        main.insert(elem);
    }
}
