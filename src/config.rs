use std::collections::HashMap;

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
            println!("Visiting key {}", k);
            match k.as_ref() {
                "policy" => {
                    if policy.is_some() {
                        return Err(M::Error::duplicate_field("policy"));
                    }
                    policy = Some(v.visit_value()?);
                },
                "filters" => {
                    println!("About to visit!");
                    if filters.is_some() {
                        return Err(M::Error::duplicate_field("filters"));
                    }
                    filters = Some(v.visit_value()?);
                },
                _ => return Err(M::Error::unknown_field(&k)),
            }
            println!("Visited");
        }
        v.end()?;
        println!("OUT OF STUFF: policy={:?}, filters={:?}", policy, filters);

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

pub fn load_file(f: &str) -> Config {
    // TODO: fetch from config file
    let mut config = Config {
        policy: Filter::Log(Box::new(Filter::Allow)),
        filters: HashMap::new(),
    };
    config.filters.insert(Syscall::getdents,
        Filter::Log(Box::new(Filter::Kill))
    );
    config.filters.insert(Syscall::open,
        Filter::Log(
            Box::new(Filter::PathIn(String::from("/nix/store"),
                Box::new(Filter::LogStr(
                    String::from("Accessing nix store!"),
                    Box::new(Filter::ArgHasNoBits(1, 3,
                        Box::new(Filter::Allow),
                        Box::new(Filter::LogStr(
                            String::from("Trying to open file in the nix store not read-only, killing!"),
                            Box::new(Filter::Kill)
                        ))
                    ))
                )),
                Box::new(Filter::Allow)
            ))
        )
    );
    for s in &[Syscall::write, Syscall::exit, Syscall::brk, Syscall::mmap, Syscall::mprotect,
               Syscall::close, Syscall::read, Syscall::fstat] {
        config.filters.insert(*s, Filter::Allow);
    }
    for s in &[Syscall::ioctl] {
        config.filters.insert(*s, Filter::Kill);
    }

    let json = format!("{}", json::as_pretty_json(&config));
    println!("=====\nfilter:\n{}\n=====", &json);
    let conf2: Config = serde_json::from_str(&json).unwrap();
    println!("=====\nencoded-decoded filter:\n{}\n=====", json::as_pretty_json(&conf2));

    config
}
