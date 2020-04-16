/*
 * Copyright (C) 2016  Leo Gaspard
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::{ffi, fs, mem::{self, MaybeUninit}, path, str};
use std::io::Write;
use std::process::{Command, Stdio};

use libc::*;
#[allow(unused_imports)] // Rustc seems to wrongly detect Error as unused. TODO: remove when fixed?
use serde::{de, Deserialize, Deserializer, Error, Serialize, Serializer};
use serde_json;

use syscalls;
use syscalls::Syscall;

const PTRACE_EVENT_EXEC: c_int = 4;
const PTRACE_EVENT_SECCOMP: c_int = 7;

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
        let mut set: MaybeUninit<sigset_t> = MaybeUninit::uninit();
        sigemptyset(set.as_mut_ptr());
        sigaddset(set.as_mut_ptr(), SIGUSR1);
        set.assume_init()
    }
}

pub fn blockusr1() -> sigset_t {
    let set = usr1set();
    unsafe {
        let mut oldset: MaybeUninit<sigset_t> = MaybeUninit::uninit();
        sigprocmask(SIG_BLOCK, &set, oldset.as_mut_ptr());
        oldset.assume_init()
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
        let mut sig: MaybeUninit<c_int> = MaybeUninit::uninit();
        blockusr1(); // This should already have been done, but safe function...
        sigwait(&set, sig.as_mut_ptr());
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

pub fn waitit(pid: pid_t) -> PtraceStop {
    unsafe {
        let mut status: MaybeUninit<c_int> = MaybeUninit::uninit();
        waitpid(pid, status.as_mut_ptr(), 0);
        stop_type(status.assume_init())
    }
}

fn continueit(pid: pid_t) {
    unsafe {
        ptrace(PTRACE_CONT, pid, 0, 0);
    }
}

#[derive(Debug)]
pub enum Action {
    Allow,
    Kill,
    // TODO: Add an Ignore target
}

struct ActionVisitor;

impl de::Visitor for ActionVisitor {
    type Value = Action;

    fn visit_str<E: de::Error>(&mut self, v: &str) -> Result<Action, E> {
        match v {
            "allow" => Ok(Action::Allow),
            "kill"  => Ok(Action::Kill),
            _       => Err(E::invalid_value(&format!("Invalid value for action: {}", v))),
        }
    }
}

// TODO: replace with auto-derive when it lands on stable
impl Deserialize for Action {
    fn deserialize<D: Deserializer>(d: &mut D) -> Result<Action, D::Error> {
        d.deserialize(ActionVisitor)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PtraceStop {
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
    // Attach
    if unsafe { ptrace(PTRACE_ATTACH, pid, 0, 0) } != 0 {
        panic!("unable to ptrace child!");
    }

    // Wait for the process to receive the SIGSTOP
    waitit(pid);

    // Set ptrace options
    // TODO: Make sure forks are ptraced
    let options = PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC;
    if unsafe { ptrace(PTRACE_SETOPTIONS, pid, 0, options) } != 0 {
        panic!("unable to trace seccomp on child: {}", unsafe { *__errno_location() });
    }

    // Start the process
    continueit(pid);
    sendcont(pid);

    // Wait for execve to succeed
    loop {
        let status = waitit(pid);
        match status {
            // Skip execve's
            PtraceStop::Seccomp => {
                if let Ok(syscall) = syscall_info(pid) {
                    if syscall.syscall == Syscall::execve {
                        continueit(pid);
                        continue
                    }
                }
                panic!("Unexpected syscall before exec succeed");
            },

            // And stop skipping syscalls on exec
            PtraceStop::Exec => break,

            // Anything else is abnormal
            _ => panic!("Unknown ptrace stop before exec succeed"),
        }
    }
    continueit(pid);

    // And monitor the exec'ed process
    loop {
        // TODO: manage multiprocess
        let status = waitit(pid);
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

            PtraceStop::Unknown(s) => panic!("Out of waitit with unknown status 0x{:08x}", s),
            // TODO: do not panic in release builds
        }
        continueit(pid);
    }
}

#[derive(Debug)]
pub struct SyscallInfo {
    pub syscall: Syscall,
    pub args: [u64; 6],
    pub path: String,
    pub realpath: String,
}

// TODO: remove when auto-derive is ready?
impl Serialize for SyscallInfo {
    fn serialize<S: Serializer>(&self, s: &mut S) -> Result<(), S::Error> {
        serialize_map!(s, {
            "syscall"  => self.syscall,
            "args"     => &self.args,
            "path"     => &self.path,
            "realpath" => &self.realpath
        })
    }
}

// TODO: also handle files like "test" (neither starting with "." nor with "/")
fn canonicalize(p: &str) -> path::PathBuf {
    let mut path = path::PathBuf::new();
    path.push(p);

    let mut append = path::PathBuf::new();
    loop {
        if let Ok(res) = fs::canonicalize(&path) {
            let mut tmp = res;
            tmp.push(append);
            return tmp;
        }
        if let Some(file) = path.clone().file_name() {
            let mut tmp = path::PathBuf::new();
            tmp.push(file);
            tmp.push(append);
            append = tmp;
            path.pop();
        } else {
            return path::PathBuf::new();
        }
    }
}

impl SyscallInfo {
    fn new(pid: pid_t, syscall: Syscall, args: [u64; 6]) -> Result<SyscallInfo, PosixError> {
        let path = match syscall {
            Syscall::open     => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::creat    => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::unlink   => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::execve   => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::chdir    => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::mknod    => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::chmod    => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::lchown   => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::stat     => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::access   => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::mkdir    => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::rmdir    => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::mount    => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::chroot   => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::lstat    => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::readlink => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::uselib   => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::swapon   => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::truncate => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::statfs   => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::swapoff  => read_str(pid, args[0], PATH_MAX as usize)?,
            Syscall::quotactl => read_str(pid, args[1], PATH_MAX as usize)?,
            Syscall::chown    => read_str(pid, args[1], PATH_MAX as usize)?,
            _                 => String::new(),
        };
        // TODO: compute realpath correctly for *at syscalls, and check all syscalls in @file are covered
        // TODO: add IP/port for @network-io syscalls
        // TODO: reduce information leakage in @default (uname, sysinfo...)
        match canonicalize(&path).into_os_string().into_string() {
            Ok(realpath) =>
                Ok(SyscallInfo {
                    syscall: syscall,
                    args: args,
                    path: path,
                    realpath: realpath,
                }),
            Err(path) => Err(PosixError::InvalidUtf8(path)),
        }
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
    InvalidUtf8(ffi::OsString),
}

impl From<str::Utf8Error> for PosixError {
    fn from(err: str::Utf8Error) -> PosixError {
        PosixError::Utf8Error(err)
    }
}

fn syscall_info(pid: pid_t) -> Result<SyscallInfo, PosixError> {
    let regs: user_regs = unsafe {
        let mut regs = MaybeUninit::uninit();
        if ptrace(PTRACE_GETREGS, pid, 0, regs.as_mut_ptr()) != 0 {
            panic!("Unable to getregs: {}", *__errno_location()); // TODO: Remove this and cleanly handle error
        }
        regs.assume_init()
    };
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

#[derive(Debug)]
struct ScriptResult {
    decision: Action,
}

struct ScriptResultVisitor;

impl de::Visitor for ScriptResultVisitor {
    type Value = ScriptResult;

    fn visit_map<M: de::MapVisitor>(&mut self, mut v: M) -> Result<ScriptResult, M::Error> {
        let mut decision = None;

        while let Some(k) = v.visit_key::<String>()? {
            match k.as_ref() {
                "decision" => get_if_unset!(v, decision, "decision" ; Action),
                _          => return Err(M::Error::unknown_field(&k)),
            }
        }
        v.end()?;

        if !decision.is_some() {
            return Err(M::Error::missing_field("decision"));
        }

        Ok(ScriptResult {
            decision: decision.unwrap(),
        })
    }
}

// TODO: Remove when auto-derive lands on stable
impl Deserialize for ScriptResult {
    fn deserialize<D: Deserializer>(d: &mut D) -> Result<ScriptResult, D::Error> {
        d.deserialize(ScriptResultVisitor)
    }
}

pub fn call_script(s: &str, sys: &SyscallInfo) -> Action {
    let cmd = Command::new(s)
                      .arg(serde_json::to_string(&sys).unwrap())
                      .stderr(Stdio::inherit())
                      .output()
                      .expect(&format!("failed to execute script {}", s));
    if !cmd.status.success() {
        println_stderr!("toboggan: Script '{}' failed!", s);
        return Action::Kill
    }
    let stdout = str::from_utf8(&cmd.stdout);
    if stdout.is_err() {
        println_stderr!("toboggan: Script '{}' wrote invalid UTF-8 output!", s);
        return Action::Kill
    }
    let res = serde_json::from_str(stdout.unwrap());
    if res.is_err() {
        // TODO: cleanly display error
        println_stderr!("toboggan: Unable to parse output of script '{}' ({}):", s, res.unwrap_err());
        println_stderr!("{}", stdout.unwrap());
        return Action::Kill
    }
    let res: ScriptResult = res.unwrap();
    res.decision
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{waitforcont, sendcont, continueit, killit, canonicalize};
    use libc;
    use std::{thread, time, path};
    use serde_json;
    use syscalls::Syscall;

    // TODO: find a way to test exec
    // TODO: find a way to test ptracehim

    #[test]
    fn wait_and_cont() {
        let oldset = blockusr1();

        let pid = unsafe { libc::fork() };
        if pid == 0 {
            thread::sleep(time::Duration::from_millis(100));
            waitforcont();
            unsafe { libc::exit(0) }
        }
        sendcont(pid);
        assert_eq!(waitit(pid), PtraceStop::Exit);
        continueit(pid);

        let pid = unsafe { libc::fork() };
        if pid == 0 {
            ptraceme();
            unsafe { libc::exit(0) }
        }
        thread::sleep(time::Duration::from_millis(100));
        sendcont(pid);
        assert_eq!(waitit(pid), PtraceStop::Exit);
        continueit(pid);

        setsigmask(oldset);
    }

    #[test]
    fn test_kill() {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            loop { }
        }
        killit(pid);
        waitit(pid);
    }

    #[test]
    fn syscallinfo_serialize() {
        assert_eq!(serde_json::to_string_pretty(&SyscallInfo {
            syscall: Syscall::read,
            args: [0, 5, 32, 79, 12, 51],
            path: String::from("/foo/bar/baz"),
            realpath: String::from("/quux/baz"),
        }).unwrap(), r#"{
  "syscall": "read",
  "args": [
    0,
    5,
    32,
    79,
    12,
    51
  ],
  "path": "/foo/bar/baz",
  "realpath": "/quux/baz"
}"#);
    }

    #[test]
    fn test_canonicalize() {
        // TODO: This assumes /var/run is a symlink to /run, find a way to make this env-agnostic
        assert_eq!(canonicalize("/var/run/thisdoesnotexist/bar/baz"),
                   path::PathBuf::from("/run/thisdoesnotexist/bar/baz"));
    }

    // TODO: Find a way to test SyscallInfo::new, syscall_info, read_str
}
