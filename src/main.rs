extern crate libc;

mod bpf;
mod seccomp;

fn main() {
    println!("====================================");

    if !seccomp::has_seccomp() {
        panic!("seccomp unavailable!");
    }

    if !seccomp::has_seccomp_filter() {
        panic!("seccomp filters unavailable!");
    }

    println!("all good");

    if let Err(e) = seccomp::install_filter(bpf::Filter { }) {
        panic!("unable to install seccomp filter: {}", e);
    }

    unsafe { libc::fork(); }
    unreachable!();
}
