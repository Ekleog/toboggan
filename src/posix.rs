use std::{ffi, mem, str};
use libc::*;

use syscalls;
use syscalls::Syscall;

const PTRACE_EVENT_EXEC: c_int = 4;
const PTRACE_EVENT_SECCOMP: c_int = 7;

const MAX_LEN: usize = 4096;

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

fn killit(pid: pid_t) {
    unsafe {
        kill(pid, SIGSYS);
        kill(pid, SIGKILL); // In case the first one was blocked
    }
}

pub fn ptraceme() {
    waitforcont();
}

fn waitit() -> PtraceStop {
    unsafe {
        let mut status: c_int = mem::uninitialized();
        wait(&mut status);
        stop_type(status)
    }
}

fn continueit(pid: pid_t) {
    unsafe {
        ptrace(PTRACE_CONT, pid, 0, 0);
    }
}

pub enum Action {
    Allow,
    Kill,
}

enum PtraceStop {
    Exec,
    Exit,
    Seccomp,
    Unknown(c_int),
}

fn stop_type(status: c_int) -> PtraceStop {
    if status & 0x7f == 0
    || (((status & 0x7f) + 1) as i8 >> 1) > 0 {
        return PtraceStop::Exit
    }
    if (status >> 8) & 0xff != SIGTRAP {
        return PtraceStop::Unknown(status)
    }
    match status >> 16 {
        PTRACE_EVENT_SECCOMP => PtraceStop::Seccomp,
        PTRACE_EVENT_EXEC    => PtraceStop::Exec,
        _                    => PtraceStop::Unknown(status),
    }
}

pub fn ptracehim<F>(pid: pid_t, cb: F) where F: Fn(SyscallInfo) -> Action {
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

    loop {
        // TODO: manage multiprocess
        let status = waitit();
        match status {
            PtraceStop::Seccomp => {
                if let Ok(syscall) = syscall_info(pid) {
                    match cb(syscall) {
                        Action::Allow => (),
                        Action::Kill => killit(pid),
                    }
                } else {
                    killit(pid); // Kill if we can't decode the syscall
                }
            }

            PtraceStop::Exit => break, // Process just exited

            PtraceStop::Exec => (), // Do nothing
            // TODO: is this really a good idea? what exactly is this stop supposed to be used for?

            PtraceStop::Unknown(s) => panic!("Out of waitit with unknown status 0x{:08x}", s),
            // TODO: do not panic in release builds
        }
        continueit(pid);
    }
}

pub struct SyscallInfo {
    pub syscall: Syscall,
    pub args: [u64; 6],
    pub path: String,
}

impl SyscallInfo {
    fn new(pid: pid_t, syscall: Syscall, args: [u64; 6]) -> Result<SyscallInfo, PosixError> {
        let path = match syscall {
            Syscall::open     => read_str(pid, args[0], MAX_LEN)?,
            Syscall::creat    => read_str(pid, args[0], MAX_LEN)?,
            Syscall::unlink   => read_str(pid, args[0], MAX_LEN)?,
            Syscall::execve   => read_str(pid, args[0], MAX_LEN)?,
            Syscall::chdir    => read_str(pid, args[0], MAX_LEN)?,
            Syscall::mknod    => read_str(pid, args[0], MAX_LEN)?,
            Syscall::chmod    => read_str(pid, args[0], MAX_LEN)?,
            Syscall::lchown   => read_str(pid, args[0], MAX_LEN)?,
            Syscall::stat     => read_str(pid, args[0], MAX_LEN)?,
            Syscall::access   => read_str(pid, args[0], MAX_LEN)?,
            Syscall::mkdir    => read_str(pid, args[0], MAX_LEN)?,
            Syscall::rmdir    => read_str(pid, args[0], MAX_LEN)?,
            Syscall::mount    => read_str(pid, args[0], MAX_LEN)?,
            Syscall::chroot   => read_str(pid, args[0], MAX_LEN)?,
            Syscall::lstat    => read_str(pid, args[0], MAX_LEN)?,
            Syscall::readlink => read_str(pid, args[0], MAX_LEN)?,
            Syscall::uselib   => read_str(pid, args[0], MAX_LEN)?,
            Syscall::swapon   => read_str(pid, args[0], MAX_LEN)?,
            Syscall::truncate => read_str(pid, args[0], MAX_LEN)?,
            Syscall::statfs   => read_str(pid, args[0], MAX_LEN)?,
            Syscall::swapoff  => read_str(pid, args[0], MAX_LEN)?,
            Syscall::quotactl => read_str(pid, args[1], MAX_LEN)?,
            Syscall::chown    => read_str(pid, args[1], MAX_LEN)?,
            _                 => String::new(),
        };
        // TODO: set path to realpath(path)
        Ok(SyscallInfo {
            syscall: syscall,
            args: args,
            path: path,
        })
    }
}

#[repr(C)]
struct user_regs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
}

#[derive(Debug)]
pub enum PosixError {
    Utf8Error(str::Utf8Error),
    PTraceError(i32),
    TooLong,
    UnknownSyscall(u64),
}

impl From<str::Utf8Error> for PosixError {
    fn from(err: str::Utf8Error) -> PosixError {
        PosixError::Utf8Error(err)
    }
}

fn syscall_info(pid: pid_t) -> Result<SyscallInfo, PosixError> {
    let mut regs: user_regs;
    unsafe {
        regs = mem::uninitialized();
        if ptrace(PTRACE_GETREGS, pid, 0, &mut regs) != 0 {
            panic!("Unable to getregs: {}", *__errno_location()); // TODO: Remove this and cleanly handle error
        }
    }
    if let Some(sysc) = syscalls::from(regs.orig_rax) {
        SyscallInfo::new(
            pid,
            sysc,
            [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
        )
    } else {
        Err(PosixError::UnknownSyscall(regs.orig_rax))
    }
}

pub fn read_str(pid: pid_t, addr: u64, maxlen: usize) -> Result<String, PosixError> {
    let mut res = String::with_capacity(maxlen + 8);
    let mut tmp: i64;
    let mut buf: [u8; 8];
    loop {
        unsafe {
            *__errno_location() = 0;
            tmp = ptrace(PTRACE_PEEKDATA, pid, addr + (res.len() as u64), 0);
            if *__errno_location() != 0 {
                return Err(PosixError::PTraceError(*__errno_location()));
            }
            buf = mem::transmute(tmp);
        }
        let zero = buf.iter().position(|&x| x == 0);
        res.push_str(str::from_utf8(&buf[0..zero.unwrap_or(buf.len())])?);
        if res.len() > maxlen {
            return Err(PosixError::TooLong);
        }
        if zero != None {
            break;
        }
    }
    res.shrink_to_fit();
    Ok(res)
}
