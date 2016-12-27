extern crate libc;

mod posix;
mod seccomp;
mod syscalls;

use syscalls::Syscall;

// TODO: check things still work (or not) after switch to kernel 4.8 (cf. man 2 ptrace)

fn spawn_child(sigset: libc::sigset_t) {
    posix::ptraceme();

    posix::setsigmask(sigset);

    if let Err(e) = seccomp::install_filter(&[Syscall::write, Syscall::exit]) {
        panic!("unable to install seccomp filter: {}", e);
    }

    println!("about to spawn ls!");

    posix::exec("ls", &["ls"]);

    panic!("Unable to spawn ls: {}", unsafe { *libc::__errno_location() });
}

fn ptrace_child(pid: libc::pid_t) {
    posix::ptracehim(pid);

    println!("Entering infinite loop");
    loop {
        // TODO: manage multiprocess
        let status = posix::waitit();
        if posix::is_seccomp(status) {
            let syscall = posix::syscall_number(pid);
            println!("Syscall with code {}", syscall);
        } else if posix::is_exit(status) {
            println!("Exit!");
            break
        } else if posix::is_exec(status) {
            println!("Exec!");
        } else {
            println!("Out of waitit with unknown status 0x{:08x}", status);
        }
        posix::continueit(pid);
    }
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
