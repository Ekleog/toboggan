#[macro_use] extern crate clap;
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

use std::{env, fs};
use std::collections::HashMap;

use filter::Filter;
use syscalls::Syscall;

// TODO: check things still work (or not) after switch to kernel 4.8 (cf. man 2 ptrace)

fn spawn_child(prog: &str, args: &[&str], sigset: libc::sigset_t, allowed: &[Syscall], killing: &[Syscall]) {
    posix::ptraceme();

    posix::setsigmask(sigset);

    if let Err(e) = seccomp::install_filter(allowed, killing) {
        panic!("unable to install seccomp filter: {}", e);
    }

    posix::exec(prog, args);
    unreachable!();
}

fn ptrace_child(pid: libc::pid_t, filters: HashMap<Syscall, Filter>, policy: Filter, ask: &str) {
    posix::ptracehim(pid, |s| {
        match filter::eval(&filters.get(&s.syscall).unwrap_or(&policy), &s) {
            filter::FilterResult::Allow => posix::Action::Allow,
            filter::FilterResult::Kill  => posix::Action::Kill,
            // TODO: Allow to answer something that will last for more than a single syscall
            filter::FilterResult::Ask   => posix::call_script(ask, &s),
        }
    });
}

fn main() {
    if !seccomp::has_seccomp() {
        panic!("seccomp unavailable!");
    }

    if !seccomp::has_seccomp_filter() {
        panic!("seccomp filters unavailable!");
    }

    // Read asker script
    // TODO: gracefully fail
    let mut provided_asker = env::current_exe().unwrap();
    provided_asker.pop();
    provided_asker.push("../../asker.sh");
    provided_asker = fs::canonicalize(&provided_asker).unwrap();
    let provided_asker = String::from(provided_asker.to_str().unwrap());
    let asker_script = env::var("TOBOGGAN_ASKER").unwrap_or(provided_asker);

    let matches = clap_app!(toboggan =>
        (version: crate_version!())
        (author: crate_authors!())
        (about: "Sandboxes applications in a user-friendly way")
        (setting: clap::AppSettings::TrailingVarArg)
        (setting: clap::AppSettings::UnifiedHelpMessage)
        (usage: "toboggan -c <CONFIG> [OPTIONS] -- <PROG>...")
        (@arg CONFIG: -c --config <CONFIG> * display_order(0) "Sets the config file")
        (@arg ASKER: -a --asker default_value(&asker_script) "Asker script")
        (@arg PROG: * ... +allow_hyphen_values "Program to sandbox")
    ).get_matches();
    let config_file = matches.value_of("CONFIG").unwrap();
    let args = matches.values_of("PROG").unwrap().collect::<Vec<&str>>();
    let prog = args[0];

    let config = config::load_file(config_file).unwrap(); // TODO: Gracefully show error
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
        spawn_child(prog, &args, sigset, &allowed, &killing);
    } else {
        posix::setsigmask(sigset);
        ptrace_child(pid, filters, policy, &asker_script);
    }
}
