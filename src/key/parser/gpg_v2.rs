use super::Key;
use super::Parser;
use std::str::Lines;

const UNKNOWN_STATUS: &str = "unknown";

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

        let ident_line = ident_line.unwrap();
        let mut skip = false;

        let bracket_split = ident_line.split('[').collect::<Vec<&str>>();
        if bracket_split.len() >= 2 {
            let follow = bracket_split[1];
            let trust_status_vec = follow.split(']').collect::<Vec<&str>>();
            if trust_status_vec.len() >= 1 {
                let trust_status = trust_status_vec[0].trim();
                if trust_status == UNKNOWN_STATUS {
                    skip = true;
                }
            }
        }

        for token in ident_line.split_whitespace() {
            if token.starts_with('<') {
                let token_len = token.len();
                identity = token[1..token_len - 1].to_string();
            }
        }
        if identity.is_empty() {
            return Err(format!(
                "No identity in ident line: {}",
                ident_line
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

        let key = Key::new(identity, fingerprint, false, skip);

        Ok(Some((key, lines)))
    }

    fn parse_sigs(&self, output: String) -> Vec<(String, String)> {
        let mut sigs = Vec::new();
        for line in output.lines() {
            if line.starts_with("sig") {
                let words: Vec<&str> = line.split_whitespace().collect();
                let mut fingerprint;
                if words.len() >= 2 {
                    fingerprint = words[1].to_string();
                    let identity = words[words.len() - 1];
                    let actual_identity = &identity[1..identity.len() - 1];
                    sigs.push((fingerprint, actual_identity.to_string()));
                }
            }
        }

        sigs
    }
}
