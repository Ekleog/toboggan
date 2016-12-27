// TODO: Remove dead_code
#[allow(dead_code, non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub enum Syscall {
    read = 0,
    write = 1,
    open = 2,
    close = 3,
    stat = 4,
    fstat = 5,
    lstat = 6,
    poll = 7,
    lseek = 8,
    mmap = 9,
    mprotect = 10,
    munmap = 11,
    brk = 12,
    rt_sigaction = 13,
    rt_sigprocmask = 14,
    rt_sigreturn = 15,
    ioctl = 16,
    pread64 = 17,
    pwrite64 = 18,
    readv = 19,
    writev = 20,
    access = 21,
    pipe = 22,
    select = 23,
    sched_yield = 24,
    mremap = 25,
    msync = 26,
    mincore = 27,
    madvise = 28,
    shmget = 29,
    shmat = 30,
    shmctl = 31,
    dup = 32,
    dup2 = 33,
    pause = 34,
    nanosleep = 35,
    getitimer = 36,
    alarm = 37,
    setitimer = 38,
    getpid = 39,
    sendfile = 40,
    socket = 41,
    connect = 42,
    accept = 43,
    sendto = 44,
    recvfrom = 45,
    sendmsg = 46,
    recvmsg = 47,
    shutdown = 48,
    bind = 49,
    listen = 50,
    getsockname = 51,
    getpeername = 52,
    socketpair = 53,
    setsockopt = 54,
    getsockopt = 55,
    clone = 56,
    fork = 57,
    vfork = 58,
    execve = 59,
    exit = 60,
    wait4 = 61,
    kill = 62,
    uname = 63,
    semget = 64,
    semop = 65,
    semctl = 66,
    shmdt = 67,
    msgget = 68,
    msgsnd = 69,
    msgrcv = 70,
    msgctl = 71,
    fcntl = 72,
    flock = 73,
    fsync = 74,
    fdatasync = 75,
    truncate = 76,
    ftruncate = 77,
    getdents = 78,
    getcwd = 79,
    chdir = 80,
    fchdir = 81,
    rename = 82,
    mkdir = 83,
    rmdir = 84,
    creat = 85,
    link = 86,
    unlink = 87,
    symlink = 88,
    readlink = 89,
    chmod = 90,
    fchmod = 91,
    chown = 92,
    fchown = 93,
    lchown = 94,
    umask = 95,
    gettimeofday = 96,
    getrlimit = 97,
    getrusage = 98,
    sysinfo = 99,
    times = 100,
    ptrace = 101,
    getuid = 102,
    syslog = 103,
    getgid = 104,
    setuid = 105,
    setgid = 106,
    geteuid = 107,
    getegid = 108,
    setpgid = 109,
    getppid = 110,
    getpgrp = 111,
    setsid = 112,
    setreuid = 113,
    setregid = 114,
    getgroups = 115,
    setgroups = 116,
    setresuid = 117,
    getresuid = 118,
    setresgid = 119,
    getresgid = 120,
    getpgid = 121,
    setfsuid = 122,
    setfsgid = 123,
    getsid = 124,
    capget = 125,
    capset = 126,
    rt_sigpending = 127,
    rt_sigtimedwait = 128,
    rt_sigqueueinfo = 129,
    rt_sigsuspend = 130,
    sigaltstack = 131,
    utime = 132,
    mknod = 133,
    uselib = 134,
    personality = 135,
    ustat = 136,
    statfs = 137,
    fstatfs = 138,
    sysfs = 139,
    getpriority = 140,
    setpriority = 141,
    sched_setparam = 142,
    sched_getparam = 143,
    sched_setscheduler = 144,
    sched_getscheduler = 145,
    sched_get_priority_max = 146,
    sched_get_priority_min = 147,
    sched_rr_get_interval = 148,
    mlock = 149,
    munlock = 150,
    mlockall = 151,
    munlockall = 152,
    vhangup = 153,
    modify_ldt = 154,
    pivot_root = 155,
    _sysctl = 156,
    prctl = 157,
    arch_prctl = 158,
    adjtimex = 159,
    setrlimit = 160,
    chroot = 161,
    sync = 162,
    acct = 163,
    settimeofday = 164,
    mount = 165,
    umount2 = 166,
    swapon = 167,
    swapoff = 168,
    reboot = 169,
    sethostname = 170,
    setdomainname = 171,
    iopl = 172,
    ioperm = 173,
    create_module = 174,
    init_module = 175,
    delete_module = 176,
    get_kernel_syms = 177,
    query_module = 178,
    quotactl = 179,
    nfsservctl = 180,
    getpmsg = 181,
    putpmsg = 182,
    afs_syscall = 183,
    tuxcall = 184,
    security = 185,
    gettid = 186,
    readahead = 187,
    setxattr = 188,
    lsetxattr = 189,
    fsetxattr = 190,
    getxattr = 191,
    lgetxattr = 192,
    fgetxattr = 193,
    listxattr = 194,
    llistxattr = 195,
    flistxattr = 196,
    removexattr = 197,
    lremovexattr = 198,
    fremovexattr = 199,
    tkill = 200,
    time = 201,
    futex = 202,
    sched_setaffinity = 203,
    sched_getaffinity = 204,
    set_thread_area = 205,
    io_setup = 206,
    io_destroy = 207,
    io_getevents = 208,
    io_submit = 209,
    io_cancel = 210,
    get_thread_area = 211,
    lookup_dcookie = 212,
    epoll_create = 213,
    epoll_ctl_old = 214,
    epoll_wait_old = 215,
    remap_file_pages = 216,
    getdents64 = 217,
    set_tid_address = 218,
    restart_syscall = 219,
    semtimedop = 220,
    fadvise64 = 221,
    timer_create = 222,
    timer_settime = 223,
    timer_gettime = 224,
    timer_getoverrun = 225,
    timer_delete = 226,
    clock_settime = 227,
    clock_gettime = 228,
    clock_getres = 229,
    clock_nanosleep = 230,
    exit_group = 231,
    epoll_wait = 232,
    epoll_ctl = 233,
    tgkill = 234,
    utimes = 235,
    vserver = 236,
    mbind = 237,
    set_mempolicy = 238,
    get_mempolicy = 239,
    mq_open = 240,
    mq_unlink = 241,
    mq_timedsend = 242,
    mq_timedreceive = 243,
    mq_notify = 244,
    mq_getsetattr = 245,
    kexec_load = 246,
    waitid = 247,
    add_key = 248,
    request_key = 249,
    keyctl = 250,
    ioprio_set = 251,
    ioprio_get = 252,
    inotify_init = 253,
    inotify_add_watch = 254,
    inotify_rm_watch = 255,
    migrate_pages = 256,
    openat = 257,
    mkdirat = 258,
    mknodat = 259,
    fchownat = 260,
    futimesat = 261,
    newfstatat = 262,
    unlinkat = 263,
    renameat = 264,
    linkat = 265,
    symlinkat = 266,
    readlinkat = 267,
    fchmodat = 268,
    faccessat = 269,
    pselect6 = 270,
    ppoll = 271,
    unshare = 272,
    set_robust_list = 273,
    get_robust_list = 274,
    splice = 275,
    tee = 276,
    sync_file_range = 277,
    vmsplice = 278,
    move_pages = 279,
    utimensat = 280,
    epoll_pwait = 281,
    signalfd = 282,
    timerfd_create = 283,
    eventfd = 284,
    fallocate = 285,
    timerfd_settime = 286,
    timerfd_gettime = 287,
    accept4 = 288,
    signalfd4 = 289,
    eventfd2 = 290,
    epoll_create1 = 291,
    dup3 = 292,
    pipe2 = 293,
    inotify_init1 = 294,
    preadv = 295,
    pwritev = 296,
    rt_tgsigqueueinfo = 297,
    perf_event_open = 298,
    recvmmsg = 299,
    fanotify_init = 300,
    fanotify_mark = 301,
    prlimit64 = 302,
    name_to_handle_at = 303,
    open_by_handle_at = 304,
    clock_adjtime = 305,
    syncfs = 306,
    sendmmsg = 307,
    setns = 308,
    getcpu = 309,
    process_vm_readv = 310,
    process_vm_writev = 311,
    kcmp = 312,
    finit_module = 313,
    sched_setattr = 314,
    sched_getattr = 315,
    renameat2 = 316,
    seccomp = 317,
    getrandom = 318,
    memfd_create = 319,
    kexec_file_load = 320,
    bpf = 321,
    execveat = 322,
    userfaultfd = 323,
    membarrier = 324,
    mlock2 = 325,
}

pub fn from(x: u64) -> Option<Syscall> {
    match x {
        0 => Some(Syscall::read),
        1 => Some(Syscall::write),
        2 => Some(Syscall::open),
        3 => Some(Syscall::close),
        4 => Some(Syscall::stat),
        5 => Some(Syscall::fstat),
        6 => Some(Syscall::lstat),
        7 => Some(Syscall::poll),
        8 => Some(Syscall::lseek),
        9 => Some(Syscall::mmap),
        10 => Some(Syscall::mprotect),
        11 => Some(Syscall::munmap),
        12 => Some(Syscall::brk),
        13 => Some(Syscall::rt_sigaction),
        14 => Some(Syscall::rt_sigprocmask),
        15 => Some(Syscall::rt_sigreturn),
        16 => Some(Syscall::ioctl),
        17 => Some(Syscall::pread64),
        18 => Some(Syscall::pwrite64),
        19 => Some(Syscall::readv),
        20 => Some(Syscall::writev),
        21 => Some(Syscall::access),
        22 => Some(Syscall::pipe),
        23 => Some(Syscall::select),
        24 => Some(Syscall::sched_yield),
        25 => Some(Syscall::mremap),
        26 => Some(Syscall::msync),
        27 => Some(Syscall::mincore),
        28 => Some(Syscall::madvise),
        29 => Some(Syscall::shmget),
        30 => Some(Syscall::shmat),
        31 => Some(Syscall::shmctl),
        32 => Some(Syscall::dup),
        33 => Some(Syscall::dup2),
        34 => Some(Syscall::pause),
        35 => Some(Syscall::nanosleep),
        36 => Some(Syscall::getitimer),
        37 => Some(Syscall::alarm),
        38 => Some(Syscall::setitimer),
        39 => Some(Syscall::getpid),
        40 => Some(Syscall::sendfile),
        41 => Some(Syscall::socket),
        42 => Some(Syscall::connect),
        43 => Some(Syscall::accept),
        44 => Some(Syscall::sendto),
        45 => Some(Syscall::recvfrom),
        46 => Some(Syscall::sendmsg),
        47 => Some(Syscall::recvmsg),
        48 => Some(Syscall::shutdown),
        49 => Some(Syscall::bind),
        50 => Some(Syscall::listen),
        51 => Some(Syscall::getsockname),
        52 => Some(Syscall::getpeername),
        53 => Some(Syscall::socketpair),
        54 => Some(Syscall::setsockopt),
        55 => Some(Syscall::getsockopt),
        56 => Some(Syscall::clone),
        57 => Some(Syscall::fork),
        58 => Some(Syscall::vfork),
        59 => Some(Syscall::execve),
        60 => Some(Syscall::exit),
        61 => Some(Syscall::wait4),
        62 => Some(Syscall::kill),
        63 => Some(Syscall::uname),
        64 => Some(Syscall::semget),
        65 => Some(Syscall::semop),
        66 => Some(Syscall::semctl),
        67 => Some(Syscall::shmdt),
        68 => Some(Syscall::msgget),
        69 => Some(Syscall::msgsnd),
        70 => Some(Syscall::msgrcv),
        71 => Some(Syscall::msgctl),
        72 => Some(Syscall::fcntl),
        73 => Some(Syscall::flock),
        74 => Some(Syscall::fsync),
        75 => Some(Syscall::fdatasync),
        76 => Some(Syscall::truncate),
        77 => Some(Syscall::ftruncate),
        78 => Some(Syscall::getdents),
        79 => Some(Syscall::getcwd),
        80 => Some(Syscall::chdir),
        81 => Some(Syscall::fchdir),
        82 => Some(Syscall::rename),
        83 => Some(Syscall::mkdir),
        84 => Some(Syscall::rmdir),
        85 => Some(Syscall::creat),
        86 => Some(Syscall::link),
        87 => Some(Syscall::unlink),
        88 => Some(Syscall::symlink),
        89 => Some(Syscall::readlink),
        90 => Some(Syscall::chmod),
        91 => Some(Syscall::fchmod),
        92 => Some(Syscall::chown),
        93 => Some(Syscall::fchown),
        94 => Some(Syscall::lchown),
        95 => Some(Syscall::umask),
        96 => Some(Syscall::gettimeofday),
        97 => Some(Syscall::getrlimit),
        98 => Some(Syscall::getrusage),
        99 => Some(Syscall::sysinfo),
        100 => Some(Syscall::times),
        101 => Some(Syscall::ptrace),
        102 => Some(Syscall::getuid),
        103 => Some(Syscall::syslog),
        104 => Some(Syscall::getgid),
        105 => Some(Syscall::setuid),
        106 => Some(Syscall::setgid),
        107 => Some(Syscall::geteuid),
        108 => Some(Syscall::getegid),
        109 => Some(Syscall::setpgid),
        110 => Some(Syscall::getppid),
        111 => Some(Syscall::getpgrp),
        112 => Some(Syscall::setsid),
        113 => Some(Syscall::setreuid),
        114 => Some(Syscall::setregid),
        115 => Some(Syscall::getgroups),
        116 => Some(Syscall::setgroups),
        117 => Some(Syscall::setresuid),
        118 => Some(Syscall::getresuid),
        119 => Some(Syscall::setresgid),
        120 => Some(Syscall::getresgid),
        121 => Some(Syscall::getpgid),
        122 => Some(Syscall::setfsuid),
        123 => Some(Syscall::setfsgid),
        124 => Some(Syscall::getsid),
        125 => Some(Syscall::capget),
        126 => Some(Syscall::capset),
        127 => Some(Syscall::rt_sigpending),
        128 => Some(Syscall::rt_sigtimedwait),
        129 => Some(Syscall::rt_sigqueueinfo),
        130 => Some(Syscall::rt_sigsuspend),
        131 => Some(Syscall::sigaltstack),
        132 => Some(Syscall::utime),
        133 => Some(Syscall::mknod),
        134 => Some(Syscall::uselib),
        135 => Some(Syscall::personality),
        136 => Some(Syscall::ustat),
        137 => Some(Syscall::statfs),
        138 => Some(Syscall::fstatfs),
        139 => Some(Syscall::sysfs),
        140 => Some(Syscall::getpriority),
        141 => Some(Syscall::setpriority),
        142 => Some(Syscall::sched_setparam),
        143 => Some(Syscall::sched_getparam),
        144 => Some(Syscall::sched_setscheduler),
        145 => Some(Syscall::sched_getscheduler),
        146 => Some(Syscall::sched_get_priority_max),
        147 => Some(Syscall::sched_get_priority_min),
        148 => Some(Syscall::sched_rr_get_interval),
        149 => Some(Syscall::mlock),
        150 => Some(Syscall::munlock),
        151 => Some(Syscall::mlockall),
        152 => Some(Syscall::munlockall),
        153 => Some(Syscall::vhangup),
        154 => Some(Syscall::modify_ldt),
        155 => Some(Syscall::pivot_root),
        156 => Some(Syscall::_sysctl),
        157 => Some(Syscall::prctl),
        158 => Some(Syscall::arch_prctl),
        159 => Some(Syscall::adjtimex),
        160 => Some(Syscall::setrlimit),
        161 => Some(Syscall::chroot),
        162 => Some(Syscall::sync),
        163 => Some(Syscall::acct),
        164 => Some(Syscall::settimeofday),
        165 => Some(Syscall::mount),
        166 => Some(Syscall::umount2),
        167 => Some(Syscall::swapon),
        168 => Some(Syscall::swapoff),
        169 => Some(Syscall::reboot),
        170 => Some(Syscall::sethostname),
        171 => Some(Syscall::setdomainname),
        172 => Some(Syscall::iopl),
        173 => Some(Syscall::ioperm),
        174 => Some(Syscall::create_module),
        175 => Some(Syscall::init_module),
        176 => Some(Syscall::delete_module),
        177 => Some(Syscall::get_kernel_syms),
        178 => Some(Syscall::query_module),
        179 => Some(Syscall::quotactl),
        180 => Some(Syscall::nfsservctl),
        181 => Some(Syscall::getpmsg),
        182 => Some(Syscall::putpmsg),
        183 => Some(Syscall::afs_syscall),
        184 => Some(Syscall::tuxcall),
        185 => Some(Syscall::security),
        186 => Some(Syscall::gettid),
        187 => Some(Syscall::readahead),
        188 => Some(Syscall::setxattr),
        189 => Some(Syscall::lsetxattr),
        190 => Some(Syscall::fsetxattr),
        191 => Some(Syscall::getxattr),
        192 => Some(Syscall::lgetxattr),
        193 => Some(Syscall::fgetxattr),
        194 => Some(Syscall::listxattr),
        195 => Some(Syscall::llistxattr),
        196 => Some(Syscall::flistxattr),
        197 => Some(Syscall::removexattr),
        198 => Some(Syscall::lremovexattr),
        199 => Some(Syscall::fremovexattr),
        200 => Some(Syscall::tkill),
        201 => Some(Syscall::time),
        202 => Some(Syscall::futex),
        203 => Some(Syscall::sched_setaffinity),
        204 => Some(Syscall::sched_getaffinity),
        205 => Some(Syscall::set_thread_area),
        206 => Some(Syscall::io_setup),
        207 => Some(Syscall::io_destroy),
        208 => Some(Syscall::io_getevents),
        209 => Some(Syscall::io_submit),
        210 => Some(Syscall::io_cancel),
        211 => Some(Syscall::get_thread_area),
        212 => Some(Syscall::lookup_dcookie),
        213 => Some(Syscall::epoll_create),
        214 => Some(Syscall::epoll_ctl_old),
        215 => Some(Syscall::epoll_wait_old),
        216 => Some(Syscall::remap_file_pages),
        217 => Some(Syscall::getdents64),
        218 => Some(Syscall::set_tid_address),
        219 => Some(Syscall::restart_syscall),
        220 => Some(Syscall::semtimedop),
        221 => Some(Syscall::fadvise64),
        222 => Some(Syscall::timer_create),
        223 => Some(Syscall::timer_settime),
        224 => Some(Syscall::timer_gettime),
        225 => Some(Syscall::timer_getoverrun),
        226 => Some(Syscall::timer_delete),
        227 => Some(Syscall::clock_settime),
        228 => Some(Syscall::clock_gettime),
        229 => Some(Syscall::clock_getres),
        230 => Some(Syscall::clock_nanosleep),
        231 => Some(Syscall::exit_group),
        232 => Some(Syscall::epoll_wait),
        233 => Some(Syscall::epoll_ctl),
        234 => Some(Syscall::tgkill),
        235 => Some(Syscall::utimes),
        236 => Some(Syscall::vserver),
        237 => Some(Syscall::mbind),
        238 => Some(Syscall::set_mempolicy),
        239 => Some(Syscall::get_mempolicy),
        240 => Some(Syscall::mq_open),
        241 => Some(Syscall::mq_unlink),
        242 => Some(Syscall::mq_timedsend),
        243 => Some(Syscall::mq_timedreceive),
        244 => Some(Syscall::mq_notify),
        245 => Some(Syscall::mq_getsetattr),
        246 => Some(Syscall::kexec_load),
        247 => Some(Syscall::waitid),
        248 => Some(Syscall::add_key),
        249 => Some(Syscall::request_key),
        250 => Some(Syscall::keyctl),
        251 => Some(Syscall::ioprio_set),
        252 => Some(Syscall::ioprio_get),
        253 => Some(Syscall::inotify_init),
        254 => Some(Syscall::inotify_add_watch),
        255 => Some(Syscall::inotify_rm_watch),
        256 => Some(Syscall::migrate_pages),
        257 => Some(Syscall::openat),
        258 => Some(Syscall::mkdirat),
        259 => Some(Syscall::mknodat),
        260 => Some(Syscall::fchownat),
        261 => Some(Syscall::futimesat),
        262 => Some(Syscall::newfstatat),
        263 => Some(Syscall::unlinkat),
        264 => Some(Syscall::renameat),
        265 => Some(Syscall::linkat),
        266 => Some(Syscall::symlinkat),
        267 => Some(Syscall::readlinkat),
        268 => Some(Syscall::fchmodat),
        269 => Some(Syscall::faccessat),
        270 => Some(Syscall::pselect6),
        271 => Some(Syscall::ppoll),
        272 => Some(Syscall::unshare),
        273 => Some(Syscall::set_robust_list),
        274 => Some(Syscall::get_robust_list),
        275 => Some(Syscall::splice),
        276 => Some(Syscall::tee),
        277 => Some(Syscall::sync_file_range),
        278 => Some(Syscall::vmsplice),
        279 => Some(Syscall::move_pages),
        280 => Some(Syscall::utimensat),
        281 => Some(Syscall::epoll_pwait),
        282 => Some(Syscall::signalfd),
        283 => Some(Syscall::timerfd_create),
        284 => Some(Syscall::eventfd),
        285 => Some(Syscall::fallocate),
        286 => Some(Syscall::timerfd_settime),
        287 => Some(Syscall::timerfd_gettime),
        288 => Some(Syscall::accept4),
        289 => Some(Syscall::signalfd4),
        290 => Some(Syscall::eventfd2),
        291 => Some(Syscall::epoll_create1),
        292 => Some(Syscall::dup3),
        293 => Some(Syscall::pipe2),
        294 => Some(Syscall::inotify_init1),
        295 => Some(Syscall::preadv),
        296 => Some(Syscall::pwritev),
        297 => Some(Syscall::rt_tgsigqueueinfo),
        298 => Some(Syscall::perf_event_open),
        299 => Some(Syscall::recvmmsg),
        300 => Some(Syscall::fanotify_init),
        301 => Some(Syscall::fanotify_mark),
        302 => Some(Syscall::prlimit64),
        303 => Some(Syscall::name_to_handle_at),
        304 => Some(Syscall::open_by_handle_at),
        305 => Some(Syscall::clock_adjtime),
        306 => Some(Syscall::syncfs),
        307 => Some(Syscall::sendmmsg),
        308 => Some(Syscall::setns),
        309 => Some(Syscall::getcpu),
        310 => Some(Syscall::process_vm_readv),
        311 => Some(Syscall::process_vm_writev),
        312 => Some(Syscall::kcmp),
        313 => Some(Syscall::finit_module),
        314 => Some(Syscall::sched_setattr),
        315 => Some(Syscall::sched_getattr),
        316 => Some(Syscall::renameat2),
        317 => Some(Syscall::seccomp),
        318 => Some(Syscall::getrandom),
        319 => Some(Syscall::memfd_create),
        320 => Some(Syscall::kexec_file_load),
        321 => Some(Syscall::bpf),
        322 => Some(Syscall::execveat),
        323 => Some(Syscall::userfaultfd),
        324 => Some(Syscall::membarrier),
        325 => Some(Syscall::mlock2),
        _ => None,
    }
}
