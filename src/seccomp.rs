use libc::*;
use syscalls::Syscall;

const PR_GET_SECCOMP: c_int = 21;
const PR_SET_SECCOMP: c_int = 22;
const PR_SET_NO_NEW_PRIVS: c_int = 38;

const SECCOMP_MODE_FILTER: c_int = 2;

const BPF_RET: u16 = 0x06;
const BPF_JEQ: u16 = 0x15;
const BPF_LD: u16 = 0x20;

const BPF_SYSCALL_NR: u32 = 0;
const BPF_ARCH_NR: u32 = 4; // sizeof(c_int)

const ARCH_X86_64: u32 = 62 | 0x80000000 | 0x40000000;

const SECCOMP_RET_KILL: u32 = 0;
const SECCOMP_RET_TRACE: u32 = 0x7ff00000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

pub fn has_seccomp() -> bool {
    unsafe {
        prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 0
    }
}

pub fn has_seccomp_filter() -> bool {
    unsafe {
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 0, 0, 0) < 0
            && *__errno_location() == EFAULT
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct sock_filter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct sock_fprog {
    len: c_ushort,
    filter: *mut sock_filter,
}

pub fn install_filter(allowed: &[Syscall], killing: &[Syscall]) -> Result<(), &'static str> {
    let mut filter = Vec::new();
    // Validate architecture
    filter.push(sock_filter { code: BPF_LD, jt: 0, jf: 0, k: BPF_ARCH_NR });
    filter.push(sock_filter { code: BPF_JEQ, jt: 1, jf: 0, k: ARCH_X86_64 });
    filter.push(sock_filter { code: BPF_RET, jt: 0, jf: 0, k: SECCOMP_RET_KILL });
    // TODO: also handle non-x64 syscalls
    // Load syscall
    filter.push(sock_filter { code: BPF_LD, jt: 0, jf: 0, k: BPF_SYSCALL_NR });
    // Allow allowed
    for s in allowed {
        filter.push(sock_filter { code: BPF_JEQ, jt: 0, jf: 1, k: *s as u32 });
        filter.push(sock_filter { code: BPF_RET, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW });
    }
    // Kill if need be
    for s in killing {
        filter.push(sock_filter { code: BPF_JEQ, jt: 0, jf: 1, k: *s as u32 });
        filter.push(sock_filter { code: BPF_RET, jt: 0, jf: 0, k: SECCOMP_RET_KILL });
    }
    // Go through slow path otherwise
    filter.push(sock_filter { code: BPF_RET, jt: 0, jf: 0, k: SECCOMP_RET_TRACE });
    // And load this policy
    unsafe {
        let prog = sock_fprog { len: filter.len() as c_ushort, filter: filter[..].as_mut_ptr() };
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            Err("prctl(PR_SET_NO_NEW_PRIVS)")
        } else if prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0 {
            Err("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, [filter])")
        } else {
            Ok(())
        }
    }
}
