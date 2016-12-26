use std::{ffi, mem};
use libc::*;

pub fn exec(prog: &str) {
    let prog = ffi::CString::new(prog).unwrap();
    let argv = [0 as *const c_char];
    let envp = [0 as *const c_char];
    unsafe {
        execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }
}

extern {
    fn sigprocmask(how: c_int, set: *const sigset_t, oldset: *mut sigset_t);
}

fn usr1set() -> sigset_t {
    unsafe {
        let mut set: sigset_t = mem::uninitialized();
        sigemptyset(&mut set);
        sigaddset(&mut set, SIGUSR1);
        set
    }
}

pub fn blockusr1() -> sigset_t {
    let set = usr1set();
    unsafe {
        let mut oldset: sigset_t = mem::uninitialized();
        sigprocmask(SIG_BLOCK, &set, &mut oldset);
        oldset
    }
}

pub fn setsigmask(m: sigset_t) {
    unsafe {
        sigprocmask(SIG_SETMASK, &m, 0 as *mut sigset_t);
    }
}

fn waitforcont() {
    let set = usr1set();
    unsafe {
        let mut sig: c_int = mem::uninitialized();
        blockusr1(); // This should already have been done, but safe function...
        sigwait(&set, &mut sig);
    }
}

fn sendcont(pid: pid_t) {
    unsafe {
        kill(pid, SIGUSR1);
    }
}

pub fn ptraceme() {
    unsafe {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
    }
    waitforcont();
}

pub fn ptracehim(pid: pid_t) {
    // TODO: actually ptrace him
    sendcont(pid);
}
