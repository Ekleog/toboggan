extern crate libc;

mod posix;
mod seccomp;
mod syscalls;

use posix::Action;
use syscalls::{Syscall};

// TODO: check things still work (or not) after switch to kernel 4.8 (cf. man 2 ptrace)

fn spawn_child(sigset: libc::sigset_t) {
    posix::ptraceme();

    posix::setsigmask(sigset);

    if let Err(e) = seccomp::install_filter(&[Syscall::write, Syscall::exit]) {
        panic!("unable to install seccomp filter: {}", e);
    }

    posix::exec("ls", &["ls"]);
    unreachable!();
}

fn ptrace_child(pid: libc::pid_t) {
    posix::ptracehim(pid, |s| {
        println!("Syscall {:?}\t({}, {}, {}, {}, {}, {})", syscalls::from(s.syscall), s.args[0], s.args[1], s.args[2], s.args[3], s.args[4], s.args[5]);
        if s.syscall == Syscall::getdents as u64 {
            Action::Kill
        } else {
            Action::Allow
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

    let sigset = posix::blockusr1();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        spawn_child(sigset);
    } else {
        posix::setsigmask(sigset);
        ptrace_child(pid);
    }
}
