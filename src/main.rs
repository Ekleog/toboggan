extern crate libc;

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
}
