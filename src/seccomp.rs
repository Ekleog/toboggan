use bpf;

use libc::*;

const PR_GET_SECCOMP: c_int = 21;
const PR_SET_SECCOMP: c_int = 22;
const PR_SET_NO_NEW_PRIVS: c_int = 38;

const SECCOMP_MODE_FILTER: c_int = 2;

pub fn has_seccomp() -> bool {
    unsafe {
        prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 0
    }
}

pub fn has_seccomp_filter() -> bool {
    unsafe {
        let res = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 0, 0, 0) < 0
            && *__errno_location() == EFAULT;
        *__errno_location() = 0;
        res
    }
}

#[allow(dead_code, non_camel_case_types)]
struct sock_filter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[allow(dead_code, non_camel_case_types)]
struct sock_fprog {
    len: c_ushort,
    filter: *mut sock_filter,
}

pub fn install_filter(filter: bpf::Filter) -> Result<(), &'static str> {
    let mut filter = vec![sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 }];
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
