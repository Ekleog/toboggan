use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Read;

use rustc_serialize::json;
use serde::{de, Deserialize, Deserializer, Error};
use serde_json;

use filter::Filter;
use syscalls::Syscall;

// TODO: add syscall groups and add some default ones
// (cf. https://github.com/systemd/systemd/blob/master/src/shared/seccomp-util.c#L221 )
#[derive(RustcEncodable)]
pub struct Config {
    pub policy: Filter,
    pub filters: HashMap<Syscall, Filter>,
}

struct ConfigVisitor;

impl de::Visitor for ConfigVisitor {
    type Value = Config;

    fn visit_map<M: de::MapVisitor>(&mut self, mut v: M) -> Result<Config, M::Error> {
        let mut policy = None;
        let mut filters = None;

        while let Some(k) = v.visit_key::<String>()? {
            match k.as_ref() {
                "policy" => {
                    if policy.is_some() {
                        return Err(M::Error::duplicate_field("policy"));
                    }
                    policy = Some(v.visit_value()?);
                },
                "filters" => {
                    if filters.is_some() {
                        return Err(M::Error::duplicate_field("filters"));
                    }
                    filters = Some(v.visit_value()?);
                },
                _ => return Err(M::Error::unknown_field(&k)),
            }
        }
        v.end()?;

        let policy = match policy {
            Some(p) => p,
            None    => return Err(M::Error::missing_field("policy")),
        };
        let filters = match filters {
            Some(f) => f,
            None    => return Err(M::Error::missing_field("filters")),
        };

        Ok(Config {
            policy: policy,
            filters: filters,
        })
    }
}

impl Deserialize for Config {
    fn deserialize<D: Deserializer>(d: &mut D) -> Result<Config, D::Error> {
        d.deserialize(ConfigVisitor)
    }
}

#[derive(Debug)]
pub enum LoadError {
    IoError(io::Error),
    ParseError(serde_json::Error),
}

impl From<io::Error> for LoadError {
    fn from(err: io::Error) -> LoadError {
        LoadError::IoError(err)
    }
}

impl From<serde_json::Error> for LoadError {
    fn from(err: serde_json::Error) -> LoadError {
        LoadError::ParseError(err)
    }
}

pub fn load_file(f: &str) -> Result<Config, LoadError> {
    let mut f = File::open(f)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;

    let config: Config = serde_json::from_str(&s)?;
    println!("=====\n filter:\n{}\n=====", json::as_pretty_json(&config));

    Ok(config)
}
