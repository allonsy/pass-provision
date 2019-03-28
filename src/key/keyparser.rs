use std::str::Lines;
use super::Key;

pub trait KeyParser {
    fn parse_key<'a>(&self, lines: Lines<'a>) -> Result<Option<(Key, Lines<'a>)>, String>;
}

pub fn parse_keys<P>(parser: &P, lines: Lines) -> Result<Vec<Key>, String> where P: KeyParser {
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
        keys.push(new_key);
        lines = new_lines;
    }

}

pub struct KeyParserV2 { }

impl KeyParser for KeyParserV2 {
    fn parse_key<'a>(&self, lines: Lines<'a>) -> Result<Option<(Key, Lines<'a>)>, String> {
        let mut fingerprint = String::new();
        let mut identity = String::new();
        let mut lines = lines;

        let lead_line = lines.next();
        if lead_line.is_none() {
            return Ok(None);
        }

        let fpr_line = lines.next();
        if fpr_line.is_none() {
            return Err("No fingerprint line included".to_string());
        }

        fingerprint = fpr_line.unwrap().trim().to_string();

        let ident_line = lines.next();
        if ident_line.is_none() {
            return Err("No ident line included".to_string());
        }

        for token in ident_line.unwrap().split_whitespace() {
            if token.starts_with("<") {
                let token_len = token.len();
                identity = token[1..token_len - 1].to_string();
            }
        }
        if identity.is_empty() {
            return Err(format!("No identity in ident line: {}", ident_line.unwrap()));
        }

        loop {
            let line = lines.next();
            if line.is_none() {
                break;
            }
            if line.unwrap().is_empty() {
                break;
            }
        }

        let key = Key::new(identity, fingerprint, false);
        Ok(Some((key, lines)))
    }
}