use libc::{__errno_location, c_int, EFAULT, prctl};

const PR_GET_SECCOMP: c_int = 21;
const PR_SET_SECCOMP: c_int = 22;
const SECCOMP_MODE_FILTER: c_int = 2;

pub fn has_seccomp() -> bool {
    unsafe {
        prctl(PR_GET_SECCOMP) == 0
    }
}

pub fn has_seccomp_filter() -> bool {
    unsafe {
        let res = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 0) < 0
            && *__errno_location() == EFAULT;
        *__errno_location() = 0;
        res
    }
}
