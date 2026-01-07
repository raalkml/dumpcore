#![no_main]
//#![allow(unused_imports)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(unused))]
#![reexport_test_harness_main = "unit_test_main"]
#[cfg(test)]
extern crate core;

extern crate libc;
use libc::{STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
//use core::{mem, slice, ptr};
use core::iter;
mod misc;
mod config;

use misc::*;
use config::*;

static DUMPCORE_CONFIG: &str = "/etc/dumpcore/config";

fn do_install(_argc: i32, _argv: *const *const i8) ->i32 {
    unimplemented!("dumpcore --install");
}

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
fn no_stdio_fd(fd: libc::c_int) -> libc::c_int {
    let mut fd = fd;
    let mut close_fd : [ libc::c_int; 3 ] = [ -1, -1, -1 ];
    let mut close_pos = 0;
    for t in [ STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO ] {
        if fd == t {
            close_fd[close_pos] = fd;
            close_pos += 1;
            fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 1) };
        }
    }
    for t in close_fd {
        if t != -1 { unsafe { libc::close(t) }; }
    }
    fd
}

fn redirect_fd(dst: libc::c_int, prefix: &[u8], suffix: &'static str) -> Buffer {
    assert!(prefix.len() > 0);
    let mut name = Buffer::new();
    name.reserve(prefix.len() + suffix.len() + 1);
    let pfxlen = prefix.len() - 1;
    name[..pfxlen].copy_from_slice(&prefix[..pfxlen]);
    name[pfxlen..pfxlen + suffix.len()].copy_from_slice(suffix.as_bytes());
    name[pfxlen + suffix.len()] = 0;
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
    fn open_pid(&mut self, pid_arg: *const i8) {
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
        fdprint!(STDOUT_FILENO, b"proc_pid_fd: ", path, b" -> ", self.proc_pid_fd, b"\n");
    }

    fn open_pid_files(&mut self) {
        self.proc_pid_ns_mnt.fd = no_stdio_fd(unsafe {
            libc::openat(self.proc_pid_fd, libc_str!("ns/mnt"),
                         libc::O_RDONLY | libc::O_CLOEXEC)
        });
        self.proc_pid_ns_mnt.err = if self.proc_pid_ns_mnt.fd == -1 {
            unsafe { *libc::__errno_location() }
        } else { 0 };
        self.proc_pid_environ.fd = no_stdio_fd(unsafe {
            libc::openat(self.proc_pid_fd, libc_str!("environ"),
                         libc::O_RDONLY | libc::O_CLOEXEC)
        });
        self.proc_pid_environ.err = if self.proc_pid_ns_mnt.fd == -1 {
            unsafe { *libc::__errno_location() }
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

fn errno_s() -> *const libc::c_char {
    let ret = unsafe { libc::strerror(*libc::__errno_location()) };
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
                if ent.d_name[0] == '.' as i8 { continue; }
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
        let errno = unsafe { *libc::__errno_location() };
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
                let errno = unsafe { *libc::__errno_location() };
                fdprint!(STDERR_FILENO, "core: write: ", unsafe { libc::strerror(errno) }, "\n");
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

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const i8) -> i32 {
#[cfg(test)]
    { unit_test_main(); return 0; }

    if argc == 2 && slice_from_c_str(unsafe {*argv.add(1)}) == b"--install" {
        return do_install(argc, argv);
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
    fdprint!(STDOUT_FILENO, "core pid: ", core.pid, "\n");
    fdprint!(STDOUT_FILENO, "core ns pid: ", core.ns_pid, "\n");
    fdprint!(STDOUT_FILENO, "core termination signal: ", core.term_sig, "\n");
    fdprint!(STDOUT_FILENO, "core exe: ", core.exe, "\n");

    // Compile-time environment variable DUMPCORE_CONFIG can be used
    // to set the path to the configuration file.
    let config = load_config(match option_env!("DUMPCORE_CONFIG") {
        None => DUMPCORE_CONFIG,
        Some(e) => e,
    });
    fdprint!(STDOUT_FILENO, "core dir: ", config.core_dir, "\n");
    fdprint!(STDOUT_FILENO, "core user: ", config.core_user, "\n");
    fdprint!(STDOUT_FILENO, "core group: ", config.core_group, "\n");
    fdprint!(STDOUT_FILENO, "core autoclean: ", if config.core_autoclean { "yes" } else { "no" }, "\n");
    fdprint!(STDOUT_FILENO, "GDB path: ", config.gdb, "\n");

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
    if core_fd == -1 {
        fdprint!(STDERR_FILENO, core_file[..], ": tmp core file: open failed\n");
    }

    let tty = unsafe { libc::open(libc_str!("/dev/tty"), libc::O_WRONLY, 0) };

    let dump_errors = redirect_fd(STDERR_FILENO, &core_file[..], ".log");
    let dump_txt = redirect_fd(STDOUT_FILENO, &core_file[..], ".txt");
    fdprint!(STDERR_FILENO, "dumpcore started\n");
    fdprint!(tty, "err file: ", dump_errors.bytez(), "\n");
    fdprint!(tty, "out file: ", dump_txt.bytez(), "\n");

    if core.proc_pid_fd != -1 {
        core.proc_exe = read_symlink(core.proc_pid_fd, libc_str!("exe"));
        if core.proc_exe[..].len() == 0 {
            fdprint!(tty, "/proc/<pid>/exe: readlinkat failed (", errno_s(), ")\n");
        } else {
            fdprint!(tty, "/proc/<pid>/exe: ", &core.proc_exe[..], "\n");
        }
    }

    fdprint!(STDOUT_FILENO, "CORE-OF: ",
             if core.proc_exe[..].len() > 0 {
                 c_str_of(&core.proc_exe[..])
             } else {
                 core.exe
             }, "\n\n");
    fdprint!(STDOUT_FILENO, "DUMPCORE_ARGS:\n");
    for i in 1usize .. argc as usize {
        fdprint!(STDOUT_FILENO, " ", unsafe {*argv.add(i)}, "\n");
    }
    fdprint!(STDOUT_FILENO, "DUMPCORE_ARGS_END\n\n");

    if core.pid != -1 {
        dump_proc(core.proc_pid_fd);
        dump_proc_environ(core.pid, core.proc_pid_environ.fd);
        // trace_pid();
    }
    copy_core(STDIN_FILENO, core_fd);
    unsafe { libc::close(core_fd); }
    if core.pid != -1 {
        let mut status: libc::c_int = -1;
        if core.proc_exe[..].len() != 0 {
            fdprint!(STDOUT_FILENO, "GDB:\n");
            status = run_gdb(config.gdb, unsafe { core.proc_exe.c_str() }, &core_file[..], &core);
            fdprint!(STDOUT_FILENO, "\nGDB_END\n\n");
            log_wait_status(config.gdb, status);
        }
        if !core.exe.is_null() && (!libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0) {
            if core.proc_exe[..].len() == 0 {
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

#[cfg(test)]
mod dumpcores {
    use super::*;

    #[test]
    fn verify_std() {
        let a = vec!{1, 2, 3};
        assert_eq!(a, &[1,2,3]);
    }

    #[test]
    fn verify_misc() {
        fdprint!(STDOUT_FILENO, b"Test STDOUT\n");
        misc::error(b"Test", b"error(prefix, text)");
        let mut b = misc::Buffer::new();
        b.reserve(1024);
        let s = &mut b[..];
        assert!(s.len() == 1024);
        let s = &b[..];
        assert!(s.len() == 1024);
        let mut b = [ 0u8; 10 ];
        let s = misc::u32toa(1234, &mut b);
        assert!(s == b"1234");
        let mut pat: [ u8; 6 ] = [ b's', b'l', b'i', b'c', b'e', 0 ];
        let s = misc::slice_from_c_str(pat.as_mut_ptr());
        assert!(s == b"slice");
    }

    #[test]
    fn verify_config() {
        let config = parse_config(b"");
        assert!(slice_from_c_str(config.core_dir) == b"/var/dumpcore");
        assert!(slice_from_c_str(config.core_user) == b"root");
        assert!(slice_from_c_str(config.core_group) == b"root");
        assert!(config.core_autoclean == false);
        assert!(slice_from_c_str(config.gdb ) == b"/usr/bin/gdb");

        let config = parse_config(b"CORE_DIR=/var/lib/dumpcore\n");
        assert!(slice_from_c_str(config.core_dir) == b"/var/lib/dumpcore");

        let config = parse_config(b"CORE_AUTOCLEAN\n");
        assert!(config.core_autoclean == true);
        let config = parse_config(b"CORE_AUTOCLEAN=1\n");
        assert!(config.core_autoclean == true);
        let config = parse_config(b"CORE_AUTOCLEAN=Y\n");
        assert!(config.core_autoclean == true);

        let config = parse_config(b"# commented out CORE_DIR=/var/lib/dumpcore\n");
        assert!(slice_from_c_str(config.core_dir) != b"/var/lib/dumpcore");

        let config = parse_config(b"# leading spaces\n  CORE_USER=nobody\n");
        assert!(slice_from_c_str(config.core_user) == b"nobody");
        let config = parse_config(b"# spaces after key\nCORE_USER =nobody\n");
        assert!(slice_from_c_str(config.core_user) == b"nobody");

        dump_syntax();
    }

    //
    // An example of how to implement interpolated formatting without std
    //
    #[test]
    fn dosomething() {
        struct Aaa { i: isize }
        impl Aaa {
            fn aaa(&self) -> isize { return self.i }
        }
        impl core::fmt::Display for Aaa {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "Aaa{{i:{}}}", self.i)
            }
        }
        let aaa = &Aaa{ i: 90 };
        struct FdWriter {
            fd : libc::c_int,
            c : u32
        }
        impl core::fmt::Write for FdWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                fdprint!(self.fd, "\"", s, "\"\n");
                self.c += 1;
                Ok(())
            }
        }
        struct Writer {}
        impl Writer {
            fn write_fmt(&mut self, args: core::fmt::Arguments<'_>) -> Result<(), core::fmt::Error> {
                if let Some(a) = args.as_str() {
                    fdprint!(STDERR_FILENO, "'", a, "'");
                    return Ok(());
                }
                let mut wr = FdWriter { fd: STDERR_FILENO, c:0 };
                let _ = core::fmt::write(&mut wr, args);
                Err(core::fmt::Error)
            }
        }
        let constant = 123456789;
        let mut o = Writer {};
        let _ = write!(o, "Begin {} end", "CONST");
        let _ = write!(o, "begin {} {constant} {} end {}.", "CONST", aaa.aaa(), 2);

        fdprint!(STDERR_FILENO, "\n");
    }

}

