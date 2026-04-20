#![no_main]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(unused))]
#![reexport_test_harness_main = "unit_test_main"]
#[cfg(test)]
extern crate core;

extern crate libc;
use libc::{STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};

extern crate buffer;
use buffer::Buffer;

use core::iter;
mod misc;
mod config;
mod fdprint;
#[cfg(test)]
mod unitests;

use misc::*;
use config::load_config;

static DUMPCORE_CONFIG: &str = "/etc/dumpcore/config";

struct CorePidFile {
    fd: libc::c_int,
    err: libc::c_int,
}

struct Core {
    pid: libc::pid_t,
    ns_pid: libc::pid_t,
    term_sig: libc::c_int,
    proc_pid_fd: libc::c_int,
    proc_pid_ns_mnt: CorePidFile,
    proc_pid_environ: CorePidFile,
    exe: *const libc::c_char,
    proc_exe: Buffer,
}

/// Duplicates the passed file handle until it is not one of the stdio handles.
/// Returns -1 in case of error. errno is no reliable, unfortunately
fn no_stdio_fd(fd: libc::c_int) -> libc::c_int {
    let mut fd = fd;
    let mut close_fd : [ libc::c_int; 3 ] = [ -1, -1, -1 ];
    let mut close_pos = 0;
    'outer: loop {
        for t in [ STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO ] {
            if fd == t {
                close_fd[close_pos] = fd;
                close_pos += 1;
                fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 1) };
                if fd != -1 { continue 'outer; }
            }
        }
        break;
    }
    for t in close_fd {
        if t != -1 { unsafe { libc::close(t) }; }
    }
    fd
}

fn redirect_fd(dst: libc::c_int, prefix: &[u8], suffix: &str) -> Buffer {
    assert!(prefix.len() > 0);
    let mut name = Buffer::new();
    name.reserve(prefix.len() + suffix.len() + 1);
    name.bytecpy(prefix);
    name[prefix.len() .. prefix.len() + suffix.len()].copy_from_slice(suffix.as_bytes());
    name[prefix.len() + suffix.len()] = 0;
    let fd = unsafe {
        libc::open(name.c_str(), libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT, 0o640)
    };
    if fd == -1 { return Buffer::new(); }
    unsafe {
        libc::dup2(fd, dst);
        if fd != dst { libc::close(fd); }
    }
    name
}

impl Core {
    fn open_pid(&mut self, pid_arg: *const libc::c_char) {
        let pid_arg = slice_from_c_str(pid_arg);
        let mut path = [0u8; 6 + 10 + 1];
        path[..6].copy_from_slice(b"/proc/");
        // FIXME panics if pid_arg is too long
        path[6..6 + pid_arg.len()].copy_from_slice(pid_arg);
        path[6 + pid_arg.len()] = 0;
        unsafe {
            // avoid using the stdin/stdout/stderr file handles
            self.proc_pid_fd = no_stdio_fd(libc::open(c_str_of(&path), libc::O_PATH | libc::O_CLOEXEC, 0));
        }
    }

    fn open_pid_files(&mut self) {
        self.proc_pid_ns_mnt.fd = no_stdio_fd(unsafe {
            libc::openat(self.proc_pid_fd, libc_str!("ns/mnt"),
                         libc::O_RDONLY | libc::O_CLOEXEC)
        });
        self.proc_pid_ns_mnt.err = if self.proc_pid_ns_mnt.fd == -1 {
            errno_n()
        } else { 0 };
        self.proc_pid_environ.fd = no_stdio_fd(unsafe {
            libc::openat(self.proc_pid_fd, libc_str!("environ"),
                         libc::O_RDONLY | libc::O_CLOEXEC)
        });
        self.proc_pid_environ.err = if self.proc_pid_ns_mnt.fd == -1 {
            errno_n()
        } else { 0 };
    }

}

impl Drop for Core {
    fn drop(&mut self) {
        unsafe {
            if self.proc_pid_fd != -1 { libc::close(self.proc_pid_fd); }
            if self.proc_pid_environ.fd != -1 { libc::close(self.proc_pid_environ.fd); }
            if self.proc_pid_ns_mnt.fd != -1 { libc::close(self.proc_pid_ns_mnt.fd); }
        }
    }
}

fn errno_n() -> libc::c_int { unsafe { *libc::__errno_location() } }
fn errno_s() -> *const libc::c_char {
    let ret = unsafe { libc::strerror(errno_n()) };
    if ret.is_null() {
        static NO_ERROR_TEXT : [libc::c_char; 1] = [ 0 ];
        NO_ERROR_TEXT.as_ptr()
    } else {
        ret
    }
}

fn read_symlink(dirfd: libc::c_int, name: *const libc::c_char) -> Buffer {
    use core::ops::IndexMut;
    let mut b = Buffer::new();
    let mut size = libc::PATH_MAX as usize / 4;
    let ret = loop {
        b.reserve(size);
        let s = b.index_mut(..);
        let ret = unsafe { libc::readlinkat(dirfd, name, c_str_of_mut(s), s.len()) };
        if ret == -1 { return Buffer::new(); }
        if ret as usize == s.len() {
            size += libc::PATH_MAX as usize / 8;
        } else {
            break ret as usize;
        }
    };
    b[..][ret] = 0;
    b.realloc(ret);
    b
}

fn read_file(dirfd: libc::c_int, name: *const libc::c_char) -> Buffer {
    let mut b = Buffer::new();
    let fd = unsafe { libc::openat(dirfd, name, libc::O_RDONLY, 0) };
    if fd == -1 { return b; }
    let mut size : usize = 384;
    let mut total : usize = 0;
    loop {
        b.reserve(size);
        let s = &mut b[total..size];
        let ret = unsafe { libc::read(fd, s.as_mut_ptr() as *mut libc::c_void, s.len()) };
        if ret < 0 { return Buffer::new(); }
        if ret == 0 { break; }
        total += ret as usize;
        size += 64;
    }
    b[..][total] = b'\0';
    b.realloc(total);
    b
}

fn write_file(dirfd: libc::c_int, name: *const libc::c_char, b: &[u8]) -> libc::c_int {
    let fd = unsafe { libc::openat(dirfd, name, libc::O_WRONLY, 0) };
    if fd == -1 {
        return -errno_n();
    }
    let ret: libc::c_int =
        if unsafe { libc::write(fd, b.as_ptr() as *const libc::c_void, b.len()) } == -1 {
            -errno_n()
        } else {
            0
        };
    unsafe { libc::close(fd) };
    ret
}

fn mkdir_p(path: *const libc::c_char, mode: u32) -> libc::c_int {
    let mut ret = unsafe { libc::mkdir(path, mode) };
    let errno = errno_n();
    if ret == 0 || errno == libc::EEXIST { return 0; }
    if errno != libc::ENOENT { return -1; }

    let mut dirfd = libc::AT_FDCWD;
    for c in slice_from_c_str(path).split(|c| *c == b'/') {
        if c.len() == 0 {
            if dirfd == libc::AT_FDCWD {
                // absolute path (first empty subslice)
                ret = unsafe { libc::open(libc_str!("/"), libc::O_PATH, 0) };
                if ret == -1 { break; }
                dirfd = ret;
            }
            continue;
        }
        let mut e = Buffer::new();
        e.bytecpy(c);
        ret = unsafe { libc::mkdirat(dirfd, e.c_str(), mode) };
        if ret == -1 && errno_n() != libc::EEXIST { break; }
        ret = unsafe { libc::openat(dirfd, e.c_str(), libc::O_PATH, 0) };
        if ret == -1 { break; }
        if dirfd != libc::AT_FDCWD { unsafe { libc::close(dirfd) }; }
        dirfd = ret;
    }
    if dirfd != libc::AT_FDCWD { unsafe { libc::close(dirfd) }; }
    ret
}

fn do_install(argv0: *const libc::c_char, arg: *const libc::c_char) -> i32 {
    let mut exe = read_symlink(libc::AT_FDCWD, libc_str!("/proc/self/exe"));
    if exe.is_empty() {
        fdprint!(STDERR_FILENO, "Cannot read /proc/self/exe (", errno_s(),
                 "), falling back to ", argv0, "\n");
        exe.bytecpy(slice_from_c_str(argv0));
    }
    let mut absexe = Buffer::new();
    absexe.reserve(libc::PATH_MAX as usize);
    if unsafe { libc::realpath(exe.c_str(), absexe.as_mut_ptr()) }.is_null() {
        fdprint!(STDERR_FILENO, "Cannot use ",
                 unsafe { exe.c_str() },
                 ": ", errno_s(), "\n");
        return 1;
    }
    absexe.realloc(absexe.bytez().len());
    let config_file = match option_env!("DUMPCORE_CONFIG") {
        None => DUMPCORE_CONFIG,
        Some(e) => e,
    };
    fdprint!(STDOUT_FILENO, "Config file: ", config_file, b"\n");
    let config = load_config(config_file);
    fdprint!(STDOUT_FILENO, "Executable file: ", absexe[..], "\n");
    if !config.core_dir.is_null() && unsafe { *config.core_dir } != 0 {
        if unsafe { libc::chdir(config.core_dir) } == 0 {
            fdprint!(STDOUT_FILENO, "Core dir: ", config.core_dir, "\n");
        } else {
            let mut fail = 0;
            let errno = errno_n();
            // If core_dir does not exist, create it (recursively) and set the permissions
            if errno == libc::ENOENT {
                if mkdir_p(config.core_dir, 0o750) != 0 && errno_n() != libc::EEXIST {
                    fdprint!(STDERR_FILENO, "mkdir ", config.core_dir, ": ", errno_s(), "\n");
                    fail += 1;
                }
            } else {
                fdprint!(STDERR_FILENO, config.core_dir, ": ", errno_s(), "\n");
                fail += 1;
            }
            if fail > 0 {
                fdprint!(STDERR_FILENO, "The crash reports may be lost!\n");
            } else {
                let pw = unsafe { libc::getpwnam(config.core_user) };
                let gr = unsafe { libc::getgrnam(config.core_group) };
                let uid : libc::uid_t = if pw.is_null() {
                    u32::MAX
                } else {
                    unsafe { pw.read().pw_uid }
                };
                let gid : libc::uid_t = if !gr.is_null() {
                    unsafe { gr.read().gr_gid }
                } else {
                    if pw.is_null() { u32::MAX } else { unsafe { pw.read().pw_gid } }
                };
                if unsafe { libc::chown(config.core_dir, uid, gid) } == -1 {
                    fdprint!(STDERR_FILENO, "chown ",
                             config.core_user, "[", uid, "]:",
                             config.core_group, "[", gid, "] ",
                             config.core_dir, ": ", errno_s(), "\n");
                }
            }
        }
    }
    // man 5 core
    // XXX kernels before 5.3 split the command into argument after
    // XXX expanding the pattern, breaking names with spaces. Especially
    // XXX badly with multiple spaces, which collapse. The processing
    // XXX of such path names (required if exe symlink is gone) involves
    // XXX a search for the files.
    static CORE_PATTERN : &[u8] = b"/proc/sys/kernel/core_pattern\0";
    static CORE_PIPE_LIMIT: &[u8] = b"/proc/sys/kernel/core_pipe_limit\0";
    static PATTERN: &[u8] = b" %P %p %s %E";
    let mut s = Buffer::new();
    s.reserve(1 + absexe[..].len() + PATTERN.len());
    use iter::{zip,chain};
    for (a, b) in zip(&mut s[..], chain(b"|", &absexe[..]).chain(PATTERN)) {
        *a = *b;
    }
    fdprint!(STDOUT_FILENO, "echo '", s[..], "' >",
             CORE_PATTERN[..CORE_PATTERN.len() - 1], "\n");
    let mut ret = 0;
    let err = write_file(libc::AT_FDCWD, CORE_PATTERN.as_ptr() as *const libc::c_char, &s[..]);
    if err < 0 {
        fdprint!(STDERR_FILENO, CORE_PATTERN, ": ", unsafe { libc::strerror(-err) }, "\n");
        ret |= 1;
    }
    let limit = if unsafe { *arg } == 0 {
        b"100"
    } else {
        slice_from_c_str(if unsafe { *arg } == b'=' as libc::c_char { unsafe { arg.add(1) } }
                         else { arg })
    };
    let err = write_file(libc::AT_FDCWD, CORE_PIPE_LIMIT.as_ptr() as *const libc::c_char, limit);
    if err < 0 {
        fdprint!(STDERR_FILENO, CORE_PIPE_LIMIT, ": ", unsafe { libc::strerror(-err) }, "\n");
        ret |= 1;
    }
    ret
}

fn dump_proc(proc_pid_fd: libc::c_int) {
    fdprint!(STDOUT_FILENO, "PROC:\n");
    let proc_root = read_symlink(proc_pid_fd, libc_str!("root"));
    fdprint!(STDOUT_FILENO, " root -> ", proc_root[..], "\n");
    let proc_cwd = read_symlink(proc_pid_fd, libc_str!("cwd"));
    fdprint!(STDOUT_FILENO, " cwd -> ", proc_cwd[..], "\n");
    let dfd = unsafe {
        libc::openat(proc_pid_fd, libc_str!("fd"), libc::O_DIRECTORY | libc::O_RDONLY)
    };
    if dfd != -1 {
        let dir = unsafe { libc::fdopendir(dfd) };
        if !dir.is_null() {
            loop {
                let ent = unsafe { libc::readdir(dir) };
                if ent.is_null() { break; }
                let ent = unsafe { ent.read() };
                if ent.d_name[0] == '.' as libc::c_char { continue; }
                let t = read_symlink(dfd, ent.d_name.as_ptr());
                fdprint!(STDOUT_FILENO, " fd/", ent.d_name.as_ptr(), " -> ", t.bytez(), "\n");
            }
        }
        unsafe { libc::closedir(dir) };
    }

    fdprint!(STDOUT_FILENO, "PROC_END\n\n");
}

fn dump_proc_environ(_core_pid: libc::pid_t, proc_pid_environ_fd: libc::c_int) {
    fdprint!(STDOUT_FILENO, "ENVIRONMENT:\n");
    let mut b = Buffer::new();
    const BUFSIZ : libc::size_t = 1024;
    b.reserve(BUFSIZ);
    loop {
        let rd = unsafe { libc::read(proc_pid_environ_fd, b.as_mut_ptr(), BUFSIZ) };
        if rd < 0 {
            fdprint!(STDERR_FILENO, "/proc/<pid>/environ: ", errno_s(), "\n");
            break;
        }
        if rd == 0 { break; }
        for ch in &b[.. rd as usize] {
            let ch = match ch {
                0 => b"\n".as_slice(),
                b'\t' => br"\t",
                b'\r' => br"\r",
                b'\n' => br"\n",
                b'\x07' => br"\a",
                b'\x08' => br"\b",
                b'\x0c' => br"\f",
                b'\\' => br"\\",
                _ => &[*ch]
            };
            fdprint!(STDOUT_FILENO, ch);
        }
    }
    fdprint!(STDOUT_FILENO, "ENVIRONMENT_END\n\n");
}

fn copy_core(core_in: libc::c_int, core_out: libc::c_int) {
    let mut fs: core::mem::MaybeUninit<libc::statfs> = core::mem::MaybeUninit::uninit();
    let ret = unsafe { libc::fstatfs(core_out, fs.as_mut_ptr() as *mut libc::statfs) };
    let block_size = if ret == -1 {
        16 * libc::__fsword_t::from(libc::BUFSIZ)
    } else {
        64 * unsafe { fs.assume_init_ref() }.f_bsize
    };
    let mut done: i64 = 0;
    let mut b = Buffer::new();
    b.reserve(block_size as usize);
    loop {
        let mut ret = unsafe { libc::read(core_in, b.as_mut_ptr(), block_size as usize) };
        if ret == 0 { break; }
        let errno = errno_n();
        if libc::EINTR == errno { continue };
        if ret == -1 {
            fdprint!(STDERR_FILENO, "core: read: ", unsafe { libc::strerror(errno) }, "\n");
            break;
        }
        done += ret as i64;
        let mut p = unsafe { b.as_ptr() };
        while ret > 0 {
            let wr = unsafe { libc::write(core_out, p, ret as usize) };
            if wr == -1 {
                fdprint!(STDERR_FILENO, "core: write: ", errno_s(), "\n");
                return;
            }
            ret -= wr;
            p = unsafe { p.add(wr as usize) };
            fdprint!(STDERR_FILENO, "core: saved ", done, "\n");
        }
    }
}

fn log_wait_status(label: *const libc::c_char, status: libc::c_int)
{
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) != 0 {
        fdprint!(STDERR_FILENO, label, ": finished with ", libc::WEXITSTATUS(status), "\n");
    } else if libc::WIFSIGNALED(status) {
        fdprint!(STDERR_FILENO, label, ": killed (",
                 unsafe { libc::strsignal(libc::WTERMSIG(status)) },
                 ")\n");
    }
}

static GDB_CMD : &'static str = r#"
set print pretty on
set pagination off
set confirm off
set prompt
set editing off
set verbose off
set interactive-mode off
printf "Threads:\n"
info threads
printf "Stack:\n"
info locals
info stack
printf "Environment:\n"
set $i=0
while environ[$i]
 if $i == 0
  printf "\n"
 end
 printf "%s\n", environ[$i++]
end
quit
"#;
fn run_gdb(gdb: *const libc::c_char, exe: *const libc::c_char, core_file: &[u8], core: &Core) -> libc::c_int {

    unsafe {
        use libc::{setns,close,dup2,pipe,write,fork,access,execlp,waitpid,exit,strerror};
        let mut fd : [libc::c_int; 2] = [ -1, -1 ];
        let ret = pipe(fd.as_mut_ptr());
        if ret == -1 {
            fdprint!(STDERR_FILENO, "pipe (gdb): ", errno_s(), "\n");
            return -1;
        }
        let pid = fork();
        if pid == -1 {
            fdprint!(STDERR_FILENO, "fork (gdb): ", errno_s(), "\n");
            return -1;
        }
        if pid == 0 {
            close(fd[1]);
            dup2(fd[0], STDIN_FILENO);
            if fd[0] != STDIN_FILENO { libc::close(fd[0]); }
            if core.proc_pid_ns_mnt.fd == -1 {
                fdprint!(STDERR_FILENO, "gdb: /proc/", core.pid, "/ns/mnt: ",
                    strerror(core.proc_pid_ns_mnt.err), "\n");
            } else if setns(core.proc_pid_ns_mnt.fd, libc::CLONE_NEWNS) == -1 {
                fdprint!(STDERR_FILENO, "gdb (setns): /proc/", core.pid, "/ns/mnt: ",
                errno_s(), "\n");
            }
            if !exe.is_null() && access(exe, libc::R_OK) != 0 {
                fdprint!(STDERR_FILENO, "GDB: ", exe, ": ", errno_s(), "\n");
            }
            dup2(STDOUT_FILENO, STDERR_FILENO);
            execlp(gdb, libc_str!("gdb"), libc_str!("-q"), libc_str!("--nh"),
                   libc_str!("--nx"), libc_str!("-ex"), libc_str!("set prompt"),
                   if exe.is_null() { libc_str!("/dev/null") } else { exe },
                   core_file.as_ptr(), core::ptr::null::<libc::c_char>());
            fdprint!(STDERR_FILENO, "exec ", gdb, ": ", errno_s(), "\n");
            exit(2);
        }
        close(fd[0]);
        if write(fd[1], GDB_CMD.as_ptr() as *const libc::c_void, GDB_CMD.len()) == -1 {
            fdprint!(STDERR_FILENO, "write (gdb cmd): ", errno_s(), "\n");
        }
        close(fd[1]);
        let mut status : libc::c_int = 0;
        if waitpid(pid, &raw mut status, 0) == -1 {
            fdprint!(STDERR_FILENO, "wait (gdb): ", errno_s(), "\n");
        }
        status
    }
}

fn trace_pid(core: &Core) {
    use iter::{zip, chain};
    let mut proc_pid_fd = core.proc_pid_fd;
    if proc_pid_fd == -1 { return; }
    fdprint!(STDOUT_FILENO, "PID_TRACE:\n");
    loop {
        let b = read_file(proc_pid_fd, libc_str!("stat"));
        if b.is_empty() { break; }
        let mut i = b[..].split(|c| *c == b')');
        _ = i.next();
        let Some(r) = i.next() else { break };
        let mut i = r[1..].split(|c| *c == b' ');
        _ = i.next();
        let Some(r) = i.next() else { break };
        let mut i = r.split(|c| *c == b' ');
        let Some(stat_ppid) = i.next() else { break };
        let mut proc_path : [u8; 4 /* ../ */ + 16 /* pid */] = [ 0; 20 ];
        for (a, b) in zip(&mut proc_path[0..3 + stat_ppid.len() + 1], chain(b"../", stat_ppid).chain(b"\0")) {
            *a = *b;
        }
        let fd = unsafe { libc::openat(proc_pid_fd, proc_path.as_ptr() as *const libc::c_char, libc::O_PATH, 0) };
        if fd == -1 {
            fdprint!(STDERR_FILENO, "trace_pid: ",
                     proc_path.as_ptr() as *const libc::c_char, errno_s(), "\n");
            break;
        }
        if proc_pid_fd != core.proc_pid_fd { unsafe { libc::close(proc_pid_fd); } }
        proc_pid_fd = fd;
        fdprint!(STDOUT_FILENO, "pid: ", proc_path[3 .. 3 + stat_ppid.len()], "\n");
        let b = read_file(proc_pid_fd, libc_str!("cmdline"));
        if !b.is_empty() { fdprint!(STDOUT_FILENO, "cmdline: ", b[..], "\n"); }
        let b = read_symlink(proc_pid_fd, libc_str!("exe"));
        if !b.is_empty() { fdprint!(STDOUT_FILENO, "exe: ", b[..], "\n"); }
        let b = read_symlink(proc_pid_fd, libc_str!("cwd"));
        if !b.is_empty() { fdprint!(STDOUT_FILENO, "cwd: ", b[..], "\n"); }
        let b = read_symlink(proc_pid_fd, libc_str!("root"));
        if !b.is_empty() { fdprint!(STDOUT_FILENO, "root: ", b[..], "\n"); }
        if stat_ppid == b"1" { break; } // init(1)
    }
    if proc_pid_fd != core.proc_pid_fd { unsafe { libc::close(proc_pid_fd); } }
    fdprint!(STDOUT_FILENO, "PID_TRACE_END\n\n");
}

// The core dump handling program is executed with these arguments:
//
//  /../dumpcore <core-pid> <core-pidns-pid> <uid> <signal> <exe-path-/-!>
//
#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const libc::c_char) -> i32 {
#[cfg(test)]
    { unit_test_main(); return 0; }

    if argc == 2 && slice_from_c_str(unsafe {*argv.add(1)}).starts_with(b"--install") {
        return do_install(unsafe { *argv }, unsafe { (*argv.add(1)).add(9) });
    }
    let mut core = Core {
        pid: -1,
        ns_pid: -1,
        term_sig: -1,
        proc_pid_fd: -1,
        proc_pid_ns_mnt: CorePidFile { fd: -1, err: -1 },
        proc_pid_environ: CorePidFile { fd: -1, err: -1 },
        exe: core::ptr::null(),
        proc_exe: Buffer::new(),
    };
    if argc > 1 {
        let pid = unsafe {*argv.add(1)};
        // Open /proc/<pid>/... (and read) as soon as possible,
        // while they still contain the process information
        core.open_pid(pid);
        core.open_pid_files();
        core.pid = misc::c_char_to_long(pid, 10) as libc::pid_t;
    }
    if argc > 2 {
        let ns_pid = unsafe {*argv.add(2)};
        core.ns_pid = misc::c_char_to_long(ns_pid, 10) as libc::pid_t;
    }
    if argc > 3 {
        let ns_pid = unsafe {*argv.add(3)};
        core.term_sig = misc::c_char_to_long(ns_pid, 10) as libc::c_int;
    }
    if argc > 4 {
        core.exe = unsafe {*argv.add(4)};
    }

    // Compile-time environment variable DUMPCORE_CONFIG can be used
    // to set the path to the configuration file.
    let config = load_config(match option_env!("DUMPCORE_CONFIG") {
        None => DUMPCORE_CONFIG,
        Some(e) => e,
    });

    let mut core_file = {
        let mut b = Buffer::new();
        static CORE_XXX: &[u8] = b"/core-XXXXXX\0";
        let core_dir = slice_from_c_str(config.core_dir);
        b.reserve(core_dir.len() + CORE_XXX.len());
        b[..core_dir.len()].copy_from_slice(core_dir);
        b[core_dir.len()..].copy_from_slice(CORE_XXX);
        b
    };
    let core_fd = no_stdio_fd(unsafe { libc::mkstemp(core_file.c_str_mut()) });

    redirect_fd(STDERR_FILENO, core_file.bytez(), ".log");
    redirect_fd(STDOUT_FILENO, core_file.bytez(), ".txt");

    if core_fd == -1 {
        fdprint!(STDERR_FILENO, core_file[..], ": tmp core file: open failed\n");
    }
    if core.proc_pid_fd != -1 {
        core.proc_exe = read_symlink(core.proc_pid_fd, libc_str!("exe"));
        if core.proc_exe.is_empty() {
            fdprint!(STDERR_FILENO, "/proc/<pid>/exe: readlinkat failed (", errno_s(), ")\n");
        }
    }

    fdprint!(STDOUT_FILENO, "CORE-OF: ",
             if !core.proc_exe.is_empty() {
                 c_str_of(&core.proc_exe[..])
             } else {
                 core.exe
             }, "\n\n");
    fdprint!(STDOUT_FILENO, "DUMPCORE_ARGS:\n");
    for i in 1 .. argc as usize {
        fdprint!(STDOUT_FILENO, " ", unsafe {*argv.add(i)}, "\n");
    }
    fdprint!(STDOUT_FILENO, "DUMPCORE_ARGS_END\n\n");

    if core.pid != -1 {
        dump_proc(core.proc_pid_fd);
        dump_proc_environ(core.pid, core.proc_pid_environ.fd);
        trace_pid(&core);
    }
    copy_core(STDIN_FILENO, core_fd);
    unsafe { libc::close(core_fd); }
    if core.pid != -1 {
        let mut status: libc::c_int = -1;
        if !core.proc_exe.is_empty() {
            fdprint!(STDOUT_FILENO, "GDB:\n");
            status = run_gdb(config.gdb, unsafe { core.proc_exe.c_str() }, &core_file[..], &core);
            fdprint!(STDOUT_FILENO, "\nGDB_END\n\n");
            log_wait_status(config.gdb, status);
        }
        if !core.exe.is_null() && (!libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0) {
            if core.proc_exe.is_empty() {
                fdprint!(STDERR_FILENO, "GDB: no /proc/self/exe\n");
            }
            let exe = slice_from_c_str(core.exe);
            let mut b = Buffer::new();
            b.reserve(exe.len() + 1);
            for (a, b) in iter::zip(b[..].iter_mut(), exe)  {
                *a = if *b == b'!' { b'/' } else { *b }
            }
            fdprint!(STDOUT_FILENO, "GDB2:\n");
            let status = run_gdb(config.gdb, unsafe { core.proc_exe.c_str() }, &core_file[..], &core);
            fdprint!(STDOUT_FILENO, "\nGDB2_END\n\n");
            log_wait_status(config.gdb, status);
        }
    }

    if config.core_autoclean {
        fdprint!(STDOUT_FILENO, "CORE-AUTOCLEAN: Y\n");
    }
    fdprint!(STDOUT_FILENO, "end\n");
    if config.core_autoclean {
        unsafe { libc::unlink(core_file.c_str()); }
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn my_panic(info: &core::panic::PanicInfo) -> ! {
    fdprint!(STDERR_FILENO, b"=== Panic ===\n");
    if let Some(msg) = info.message().as_str() {
        fdprint!(STDERR_FILENO, msg, b"\n");
    }
    if let Some(loc) = info.location() {
        fdprint!(STDERR_FILENO, loc.file().as_bytes(), b":", loc.line(), b"\n");
    }
    unsafe { libc::raise(libc::SIGKILL); }
    loop {}
}

