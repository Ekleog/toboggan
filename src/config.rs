use std::collections::HashMap;

use rustc_serialize::json;

use filter::Filter;
use syscalls::Syscall;

#[derive(RustcEncodable)]
pub struct Config {
    pub policy: Filter,
    pub filters: HashMap<Syscall, Filter>,
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
    println!("=====\nfilter:\n{}\n=====", json::as_pretty_json(&config));

    config
}
