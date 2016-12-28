extern crate libc;

mod filter;
mod posix;
mod seccomp;
mod syscalls;

use std::collections::HashMap;

use filter::Filter;
use syscalls::Syscall;

// TODO: check things still work (or not) after switch to kernel 4.8 (cf. man 2 ptrace)

fn spawn_child(sigset: libc::sigset_t) {
    posix::ptraceme();

    posix::setsigmask(sigset);

    if let Err(e) = seccomp::install_filter(&[Syscall::write, Syscall::exit, Syscall::brk, Syscall::mmap, Syscall::mprotect, Syscall::close, Syscall::read, Syscall::fstat]) {
        panic!("unable to install seccomp filter: {}", e);
    }

    posix::exec("ls", &["ls"]);
    unreachable!();
}

fn ptrace_child(pid: libc::pid_t) {
    // TODO: Allow filtering on syscall

    let policy = Filter::Log(Box::new(Filter::Allow));
    let mut filter: HashMap<Syscall, Filter> = HashMap::new();
    filter.insert(Syscall::getdents,
        Filter::Log(Box::new(Filter::Kill))
    );
    filter.insert(Syscall::open,
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

    posix::ptracehim(pid, |s| {
        filter::eval(&filter.get(&s.syscall).unwrap_or(&policy), &s)
    });
}

fn main() {
    if !seccomp::has_seccomp() {
        panic!("seccomp unavailable!");
    }

    if !seccomp::has_seccomp_filter() {
        panic!("seccomp filters unavailable!");
    }

    let sigset = posix::blockusr1();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        spawn_child(sigset);
    } else {
        posix::setsigmask(sigset);
        ptrace_child(pid);
    }
}
