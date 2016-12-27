use std::{ffi, mem};
use libc::*;

const PTRACE_EVENT_EXEC: c_int = 4;
const PTRACE_EVENT_SECCOMP: c_int = 7;
const ORIG_RAX: c_int = 120;

pub fn exec(prog: &str, argv: &[&str]) {
    let prog = ffi::CString::new(prog).unwrap();
    let mut args: Vec<*const c_char> = Vec::new();
    for arg in argv {
        args.push(ffi::CString::new(arg.clone()).unwrap().into_raw());
    }
    args.push(0 as *const c_char);

    // TODO: allow to block environment passing?
    unsafe {
        execvp(prog.as_ptr(), args.as_ptr());
    }

    panic!("Unable to exec: {}", unsafe { *__errno_location() });
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
    waitforcont();
}

pub fn waitit() -> c_int {
    unsafe {
        let mut status: c_int = mem::uninitialized();
        wait(&mut status);
        status
    }
}

pub fn continueit(pid: pid_t) {
    unsafe {
        ptrace(PTRACE_CONT, pid, 0, 0);
    }
}

pub enum Action {
    Allow,
    Kill,
}

pub fn ptracehim<F>(pid: pid_t, cb: F) where F: Fn(i64) -> Action {
    if unsafe { ptrace(PTRACE_ATTACH, pid, 0, 0) } != 0 {
        panic!("unable to ptrace child!");
    }
    waitit(); // Wait for the process to receive the SIGSTOP
    // TODO: Make sure forks are ptraced
    let options = PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC;
    if unsafe { ptrace(PTRACE_SETOPTIONS, pid, 0, options) } != 0 {
        panic!("unable to trace seccomp on child: {}", unsafe { *__errno_location() });
    }
    continueit(pid);
    sendcont(pid);

    println!("Entering infinite loop");
    loop {
        // TODO: manage multiprocess
        let status = waitit();
        if is_seccomp(status) {
            let syscall = syscall_number(pid);
            match cb(syscall) {
                Action::Allow => (),
                Action::Kill => panic!("TODO: Kill the process"),
            }
        } else if is_exit(status) {
            // Process just exited
            break
        } else if is_exec(status) {
            // Do nothing
            // TODO: is this really a good idea? what exactly is this stop supposed to be used for?
        } else {
            // TODO: do not panic in release builds
            panic!("Out of waitit with unknown status 0x{:08x}", status);
        }
        continueit(pid);
    }
}

fn syscall_number(pid: pid_t) -> i64 {
    unsafe {
        *__errno_location() = 0;
        let res = ptrace(PTRACE_PEEKUSER, pid, ORIG_RAX, 0);
        if *__errno_location() != 0 {
            panic!("Unable to peekuser: {}", *__errno_location()); // TODO: Remove this and cleanly handle error
        }
        res
    }
}

fn is_seccomp(status: c_int) -> bool {
    status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))
}

fn is_exit(status: c_int) -> bool {
    status & 0x7f == 0
}

fn is_exec(status: c_int) -> bool {
    status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))
}
