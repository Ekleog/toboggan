extern crate libc;

mod seccomp;
mod syscalls;

use syscalls::Syscall;

fn main() {
    println!("====================================");

    if !seccomp::has_seccomp() {
        panic!("seccomp unavailable!");
    }

    if !seccomp::has_seccomp_filter() {
        panic!("seccomp filters unavailable!");
    }

    println!("all good");

    if let Err(e) = seccomp::install_filter(&[Syscall::write]) {
        panic!("unable to install seccomp filter: {}", e);
    }

    println!("Should manage to write this");

    unsafe { libc::fork(); }
    unreachable!();
}
