mod gpg_v2;
use super::Key;
use gpg_v2::ParserV2;
use std::str::Lines;

pub trait Parser {
    fn parse_key<'a>(&self, lines: Lines<'a>) -> Result<Option<(Key, Lines<'a>)>, String>;
    fn parse_sigs(&self, output: String) -> Vec<(String, String)>;
}

pub fn get_parser() -> Box<dyn Parser> {
    let gpg_version = get_gpg_version();
    if gpg_version.is_none() {
        eprintln!("Unknown GPG Version");
        return Box::new(ParserV2::new());
    }

    match gpg_version.unwrap() {
        _ => {
            Box::new(ParserV2::new())
        }
    }
}

fn get_gpg_version() -> Option<String> {
    Some("2.1.4".to_string())
}

pub fn parse_keys(parser: &Parser, lines: Lines) -> Result<Vec<Key>, String> {
    let mut keys = Vec::new();
    let mut lines = lines;

    loop {
        let key_res = parser.parse_key(lines);
        if key_res.is_err() {
            return Err(key_res.err().unwrap());
        }
        let key_opt = key_res.unwrap();
        if key_opt.is_none() {
            return Ok(keys);
        }

        let (new_key, new_lines) = key_opt.unwrap();
        if new_key.is_trusted() {
            keys.push(new_key);
        }
        lines = new_lines;
    }
}
