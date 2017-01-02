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
use std::path::PathBuf;

use serde::{de, Deserialize, Deserializer, Error, Serialize, Serializer};
use serde_json;

use filter::Filter;
use syscalls;
use syscalls::Syscall;

// TODO: add some default groups (cf. https://github.com/systemd/systemd/blob/master/src/shared/seccomp-util.c#L221 )
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    pub policy: Filter,
    pub groups: HashMap<String, Vec<Syscall>>, // optional field. TODO: check name doesn't overlap with syscalls
    pub filters: HashMap<Syscall, Filter>,
}

// TODO: add relevant tests
impl Config {
    fn compute_filters(filters: HashMap<String, Filter>,
                       groups: &HashMap<String, Vec<Syscall>>,
                       oldconfigs: &Vec<Config>) -> HashMap<Syscall, Filter> {
        let mut res = HashMap::new();
        'nextfilter: for (k, v) in filters.into_iter() {
            // TODO: Handle case of syscall defined in multiple overlapping groups
            if let Some(k) = syscalls::from_str(&k) {
                res.insert(k, v);
            } else if let Some(keys) = groups.get(&k) {
                for k in keys {
                    res.insert(*k, v.clone());
                }
            } else {
                for c in oldconfigs.iter() {
                    if let Some(keys) = c.groups.get(&k) {
                        for k in keys {
                            res.insert(*k, v.clone());
                        }
                        continue 'nextfilter;
                    }
                }
                panic!("Unknown group or syscall name: {}", k);
                // TODO: Handle this cleanly
            }
        }
        res
    }

    fn new(config: ParsedConfig, oldconfigs: &Vec<Config>) -> Config {
        Config {
            policy: config.policy,
            filters: Self::compute_filters(config.filters, &config.groups, oldconfigs),
            groups: config.groups,
        }
    }
}

impl Serialize for Config {
    fn serialize<S: Serializer>(&self, s: &mut S) -> Result<(), S::Error> {
        serialize_map!(s, {
            "policy"  => &self.policy,
            "groups"  => &self.groups,
            "filters" => &self.filters
        })
    }
}

struct ParsedConfig {
    pub policy: Filter,
    pub groups: HashMap<String, Vec<Syscall>>,
    pub filters: HashMap<String, Filter>,
}

struct ConfigVisitor;

impl de::Visitor for ConfigVisitor {
    type Value = ParsedConfig;

    fn visit_map<M: de::MapVisitor>(&mut self, mut v: M) -> Result<ParsedConfig, M::Error> {
        let mut policy = None;
        let mut groups = None;
        let mut filters = None;

        while let Some(k) = v.visit_key::<String>()? {
            match k.as_ref() {
                "policy"  => get_if_unset!(v, policy, "policy"   ; Filter),
                "groups"  => get_if_unset!(v, groups, "groups"   ; HashMap<String, Vec<Syscall>>),
                "filters" => get_if_unset!(v, filters, "filters" ; HashMap<String, Filter>),
                _         => return Err(M::Error::unknown_field(&k)),
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
        let groups = match groups {
            Some(g) => g,
            None    => HashMap::new(),
        };

        Ok(ParsedConfig {
            policy: policy,
            groups: groups,
            filters: filters,
        })
    }
}

impl Deserialize for ParsedConfig {
    fn deserialize<D: Deserializer>(d: &mut D) -> Result<ParsedConfig, D::Error> {
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

// TODO: Test it
fn relocate_wrt_conffile(f: &PathBuf, c: Filter) -> Filter {
    match c {
        Filter::Allow => Filter::Allow,
        Filter::Kill  => Filter::Kill,
        Filter::Ask   => Filter::Ask,

        Filter::Eval(s)      => Filter::Eval(String::from(f.join(s).to_str().unwrap())), // TODO: handle error case
        Filter::Log(t)       => Filter::Log(Box::new(relocate_wrt_conffile(f, *t))),
        Filter::LogStr(s, t) => Filter::LogStr(s, Box::new(relocate_wrt_conffile(f, *t))),

        Filter::ArgEq(a, x, jt, jf) =>
            Filter::ArgEq(a, x, Box::new(relocate_wrt_conffile(f, *jt)),
                                Box::new(relocate_wrt_conffile(f, *jf))),

        Filter::ArgLeq(a, x, jt, jf) =>
            Filter::ArgLeq(a, x, Box::new(relocate_wrt_conffile(f, *jt)),
                                 Box::new(relocate_wrt_conffile(f, *jf))),
        Filter::ArgLe(a, x, jt, jf) =>
            Filter::ArgLe(a, x, Box::new(relocate_wrt_conffile(f, *jt)),
                                Box::new(relocate_wrt_conffile(f, *jf))),
        Filter::ArgGeq(a, x, jt, jf) =>
            Filter::ArgGeq(a, x, Box::new(relocate_wrt_conffile(f, *jt)),
                                 Box::new(relocate_wrt_conffile(f, *jf))),
        Filter::ArgGe(a, x, jt, jf) =>
            Filter::ArgGe(a, x, Box::new(relocate_wrt_conffile(f, *jt)),
                                Box::new(relocate_wrt_conffile(f, *jf))),

        Filter::ArgHasBits(a, x, jt, jf) =>
            Filter::ArgHasBits(a, x, Box::new(relocate_wrt_conffile(f, *jt)),
                                     Box::new(relocate_wrt_conffile(f, *jf))),
        Filter::ArgHasNoBits(a, x, jt, jf) =>
            Filter::ArgHasNoBits(a, x, Box::new(relocate_wrt_conffile(f, *jt)),
                                       Box::new(relocate_wrt_conffile(f, *jf))),
        Filter::ArgInBits(a, x, jt, jf) =>
            Filter::ArgInBits(a, x, Box::new(relocate_wrt_conffile(f, *jt)),
                                    Box::new(relocate_wrt_conffile(f, *jf))),

        Filter::PathIn(s, jt, jf) =>
            Filter::PathIn(s, Box::new(relocate_wrt_conffile(f, *jt)),
                              Box::new(relocate_wrt_conffile(f, *jf))),
        Filter::PathEq(s, jt, jf) =>
            Filter::PathEq(s, Box::new(relocate_wrt_conffile(f, *jt)),
                              Box::new(relocate_wrt_conffile(f, *jf))),

        Filter::RealPathIn(s, jt, jf) =>
            Filter::RealPathIn(s, Box::new(relocate_wrt_conffile(f, *jt)),
                              Box::new(relocate_wrt_conffile(f, *jf))),
        Filter::RealPathEq(s, jt, jf) =>
            Filter::RealPathEq(s, Box::new(relocate_wrt_conffile(f, *jt)),
                              Box::new(relocate_wrt_conffile(f, *jf))),
    }
}

pub fn load_file(f: &str, oldconfigs: &Vec<Config>) -> Result<Config, LoadError> {
    let mut f = PathBuf::from(f);
    let mut file = File::open(&f)?;
    let mut s = String::new();
    file.read_to_string(&mut s)?;

    let mut config: ParsedConfig = serde_json::from_str(&s)?;

    f.pop();
    config.policy = relocate_wrt_conffile(&f, config.policy);
    config.filters = config.filters.into_iter().map(|(k, v)| (k, relocate_wrt_conffile(&f, v))).collect();

    Ok(Config::new(config, oldconfigs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::ParsedConfig;
    use std::collections::HashMap;
    use filter::Filter;
    use syscalls::Syscall;
    use serde_json;

    fn example_simple_config() -> Config {
        let mut filters = HashMap::new();
        filters.insert(String::from("open"), Filter::Allow);

        let mut groups = HashMap::new();
        groups.insert(String::from("testgroup"), vec![Syscall::prlimit64, Syscall::readlinkat]);

        Config::new(ParsedConfig { policy: Filter::Kill, groups: groups, filters: filters },
                    &Vec::new())
    }

    fn example_config() -> Config {
        let mut filters = HashMap::new();
        filters.insert(String::from("allowed"), Filter::Allow);
        filters.insert(String::from("write"), Filter::Kill);
        filters.insert(String::from("open"),
            Filter::PathIn(String::from("/home"),
                Box::new(Filter::Allow),
                Box::new(Filter::Log(Box::new(Filter::Kill)))
            )
        );

        let mut groups = HashMap::new();
        groups.insert(String::from("allowed"), vec![Syscall::getdents, Syscall::stat]);

        Config::new(ParsedConfig { policy: Filter::Ask, groups: groups, filters: filters },
                    &Vec::new())
    }

    #[test]
    fn serialize_config() {
        assert_eq!(serde_json::to_string_pretty(&example_simple_config()).unwrap(), r#"{
  "policy": "kill",
  "groups": {
    "testgroup": [
      "prlimit64",
      "readlinkat"
    ]
  },
  "filters": {
    "open": "allow"
  }
}"#);
    }

    #[test]
    fn deserialize_config() {
        assert_eq!(
            Config::new(serde_json::from_str::<ParsedConfig>(
                &serde_json::to_string_pretty(&example_config()).unwrap()
            ).unwrap(), &Vec::new()),
            example_config()
        );
    }

    #[test]
    fn config_from_file() {
        assert_eq!(load_file("tests/example_config.json", &Vec::new()).unwrap(), example_config());
    }
}
