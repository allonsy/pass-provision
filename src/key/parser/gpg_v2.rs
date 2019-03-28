use super::Key;
use super::Parser;
use std::str::Lines;

pub struct ParserV2 {}

impl ParserV2 {
    pub fn new() -> ParserV2 {
        ParserV2 {}
    }
}

impl Parser for ParserV2 {
    fn parse_key<'a>(&self, lines: Lines<'a>) -> Result<Option<(Key, Lines<'a>)>, String> {
        let mut fingerprint;
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
            if token.starts_with('<') {
                let token_len = token.len();
                identity = token[1..token_len - 1].to_string();
            }
        }
        if identity.is_empty() {
            return Err(format!(
                "No identity in ident line: {}",
                ident_line.unwrap()
            ));
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
