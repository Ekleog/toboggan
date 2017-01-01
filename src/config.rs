/*
 * Copyright (C) 2016  Leo Gaspard
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Read;

use serde::{de, Deserialize, Deserializer, Error, Serialize, Serializer};
use serde_json;

use filter::Filter;
use syscalls::Syscall;

// TODO: add syscall groups and add some default ones
// (cf. https://github.com/systemd/systemd/blob/master/src/shared/seccomp-util.c#L221 )
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    pub policy: Filter,
    pub filters: HashMap<Syscall, Filter>,
}

impl Serialize for Config {
    fn serialize<S: Serializer>(&self, s: &mut S) -> Result<(), S::Error> {
        serialize_map!(s, {
            "policy"  => &self.policy,
            "filters" => &self.filters
        })
    }
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

    // TODO: cleanly display error
    let config: Config = serde_json::from_str(&s)?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use syscalls::Syscall;
    use filter::Filter;
    use serde_json;

    fn example_simple_config() -> Config {
        let mut filters = HashMap::new();
        filters.insert(Syscall::open, Filter::Allow);
        Config {
            policy: Filter::Kill,
            filters: filters,
        }
    }

    fn example_config() -> Config {
        let mut filters = HashMap::new();
        filters.insert(Syscall::getdents, Filter::Allow);
        filters.insert(Syscall::stat, Filter::Allow);
        filters.insert(Syscall::write, Filter::Kill);
        filters.insert(Syscall::open,
            Filter::PathIn(String::from("/home"),
                Box::new(Filter::Allow),
                Box::new(Filter::Log(Box::new(Filter::Kill)))
            )
        );
        Config {
            policy: Filter::Ask,
            filters: filters,
        }
    }

    #[test]
    fn serialize_config() {
        assert_eq!(serde_json::to_string_pretty(&example_simple_config()).unwrap(), r#"{
  "policy": "kill",
  "filters": {
    "open": "allow"
  }
}"#);
    }

    #[test]
    fn deserialize_config() {
        assert_eq!(
            serde_json::from_str::<Config>(&serde_json::to_string_pretty(&example_config()).unwrap()).unwrap(),
            example_config()
        );
    }

    #[test]
    fn config_from_file() {
        assert_eq!(load_file("tests/example_config.json").unwrap(), example_config());
    }
}
