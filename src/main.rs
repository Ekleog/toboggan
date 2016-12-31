#[macro_use] extern crate lazy_static;
extern crate libc;
extern crate regex;
extern crate serde;
extern crate serde_json;

#[macro_use] mod helpers;
mod config;
mod filter;
mod posix;
mod seccomp;
mod syscalls;

use std::collections::HashMap;

use filter::Filter;
use syscalls::Syscall;

// TODO: check things still work (or not) after switch to kernel 4.8 (cf. man 2 ptrace)

fn spawn_child(sigset: libc::sigset_t, allowed: &[Syscall], killing: &[Syscall]) {
    posix::ptraceme();

    posix::setsigmask(sigset);

    if let Err(e) = seccomp::install_filter(allowed, killing) {
        panic!("unable to install seccomp filter: {}", e);
    }

    posix::exec("tee", &["tee", "/nix/store/fubar"]);
    unreachable!();
}

fn ptrace_child(pid: libc::pid_t, filters: HashMap<Syscall, Filter>, policy: Filter) {
    posix::ptracehim(pid, |s| {
        filter::eval(&filters.get(&s.syscall).unwrap_or(&policy), &s)
    });
}

fn main() {
    if !seccomp::has_seccomp() {
        panic!("seccomp unavailable!");
    }

    if !seccomp::has_seccomp_filter() {
        panic!("seccomp filters unavailable!");
    }

    let config = config::load_file("config.json").unwrap(); // TODO: Gracefully show error
    let policy = config.policy;
    let filters = config.filters;

    let allowed: Vec<Syscall> = filters.iter()
                                       .filter(|&(_, v)| *v == Filter::Allow)
                                       .map(|(k, _)| k.clone())
                                       .collect();
    let killing: Vec<Syscall> = filters.iter()
                                       .filter(|&(_, v)| *v == Filter::Kill)
                                       .map(|(k, _)| k.clone())
                                       .collect();

    let sigset = posix::blockusr1();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        spawn_child(sigset, &allowed, &killing);
    } else {
        posix::setsigmask(sigset);
        ptrace_child(pid, filters, policy);
    }
}
