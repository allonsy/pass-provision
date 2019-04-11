use dirs;
use std::path::PathBuf;
use std::fs;
use toml::Value;
use toml::map::Map;

const CONFIG_FILE_NAME: &str = "pass-provision.conf";
const DEFAULT_KEY_KEY: &str = "default-key";

pub struct Config {
    default_key: String,
}

impl Config {
    pub fn new(def_key_fingerprint: String) -> Config {
        Config {
            default_key: def_key_fingerprint
        }
    }

    pub fn parse_config() -> Option<Config> {
        let config_location = get_config_file_location();
        if !config_location.exists() {
            eprintln!("No config file found to parse");
            return None;
        }

        let file_contents = fs::read_to_string(config_location);
        if file_contents.is_err() {
            eprintln!("Unable to read config file");
            return None;
        }

        let toml_value_res = file_contents.unwrap().parse::<Value>();
        if toml_value_res.is_err() {
            eprintln!("Unable to parse config file");
            return None;
        }

        let toml_value = toml_value_res.unwrap();
        if toml_value.is_table() {
            let toml_table = toml_value.as_table().unwrap();
            if toml_table.contains_key(DEFAULT_KEY_KEY) {
                let default_key = toml_table.get(DEFAULT_KEY_KEY).unwrap();
                if default_key.is_str() {
                    let conf = Config::new(default_key.as_str().unwrap().to_string());
                    return Some(conf);
                } else {
                    eprintln!("toml key: {} isn't a string", DEFAULT_KEY_KEY);
                }
            } else {
                eprintln!("toml doesn't have key: {}", DEFAULT_KEY_KEY);
            }
        } else {
            eprintln!("toml doesn't have any key value pairs");
        }
        None
    }

    pub fn get_default_key(&self) -> &str {
        &self.default_key
    }

    pub fn write_config(&self) {
        let config_file = get_config_file_location();
        let mut table = Map::new();
        let default_key_value = toml::Value::String(self.default_key.clone());
        table.insert(DEFAULT_KEY_KEY.to_string(), default_key_value);
        let toml = toml::Value::Table(table);

        let toml_string = toml::to_string(&toml).unwrap();
        let res = fs::write(config_file, toml_string);
        if res.is_err() {
            eprintln!("Error writing config!");
        }
    }
}



pub fn get_config_file_location() -> PathBuf {
    let config_dir_opt = dirs::config_dir();
    if config_dir_opt.is_none() {
        eprintln!("Unable to get config file location");
        std::process::exit(1);
    }
    let config_dir = config_dir_opt.unwrap();
    if !config_dir.exists() {
        let res = fs::create_dir_all(&config_dir);
        if res.is_err() {
            eprintln!("Unable to create config firectory");
            std::process::exit(1);
        }
    }

    return config_dir.join(CONFIG_FILE_NAME);
}