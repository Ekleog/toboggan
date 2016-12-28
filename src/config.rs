use std::collections::HashMap;

use yaml;

use filter::Filter;
use syscalls::Syscall;

pub struct Config {
    pub policy: Filter,
    pub filters: HashMap<Syscall, Filter>,
}

pub fn load_file(f: &str) -> Config {
    // TODO: fetch from config file
    let policy = Filter::Log(Box::new(Filter::Allow));
    let mut filters: HashMap<Syscall, Filter> = HashMap::new();
    filters.insert(Syscall::getdents,
        Filter::Log(Box::new(Filter::Kill))
    );
    filters.insert(Syscall::open,
        Filter::Log(
            Box::new(Filter::PathIn(String::from("/nix/store"),
                Box::new(Filter::LogStr(
                    String::from("Accessing nix store!"),
                    Box::new(Filter::Allow)
                )),
                Box::new(Filter::Allow)
            ))
        )
    );
    for s in &[Syscall::write, Syscall::exit, Syscall::brk, Syscall::mmap, Syscall::mprotect,
               Syscall::close, Syscall::read, Syscall::fstat] {
        filters.insert(*s, Filter::Allow);
    }
    for s in &[Syscall::ioctl] {
        filters.insert(*s, Filter::Kill);
    }

    Config {
        policy: policy,
        filters: filters,
    }
}
