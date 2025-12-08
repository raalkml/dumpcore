#![no_main]
#![allow(unused_imports)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, allow(unused))]
#![reexport_test_harness_main = "unit_test_main"]
#[cfg(test)]
extern crate core;

extern crate libc;
use libc::{STDOUT_FILENO, STDERR_FILENO};
use core::{mem, slice, ptr};
mod misc;
use misc::{error, slice_from_c_str, u32toa, Buffer};

fn do_install(_argc: i32, _argv: *const *const i8) ->i32 {
    error(b"dumpcore", b"--install not implemented");
    0
}

struct Core {
    pid: libc::pid_t,
    ns_pid: libc::pid_t,
    term_sig: libc::c_int,
}

fn open_pid(_pid: *const i8) {}
fn open_pid_files() {}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const i8) -> i32 {
#[cfg(test)]
    { unit_test_main(); return 0 }

    if argc == 2 && slice_from_c_str(unsafe {*argv.add(1) as *mut u8}) == b"--install" {
        return do_install(argc, argv);
    }
    let mut core = Core {
        pid: libc::pid_t::from(-1),
        ns_pid: libc::pid_t::from(-1),
        term_sig: libc::c_int::from(-1),
    };
    if argc > 1 {
        let pid = unsafe {*argv.add(1) as *const libc::c_char};
        open_pid(pid);
        open_pid_files();
        core.pid = misc::c_char_to_long(pid, 10) as libc::pid_t;
    }
    if argc > 2 {
        let ns_pid = unsafe {*argv.add(2) as *const libc::c_char};
        core.ns_pid = misc::c_char_to_long(ns_pid, 10) as libc::pid_t;
    }
    if argc > 3 {
        let ns_pid = unsafe {*argv.add(3) as *const libc::c_char};
        core.term_sig = misc::c_char_to_long(ns_pid, 10) as libc::c_int;
    }
    let mut buf = [ 0u8; 20 ];
    fdprint!(STDOUT_FILENO, b"core pid: ", u32toa(core.pid as u32, &mut buf), b"\n");
    fdprint!(STDOUT_FILENO, b"core ns pid: ", u32toa(core.ns_pid as u32, &mut buf), b"\n");
    fdprint!(STDOUT_FILENO, b"core termination signal: ", u32toa(core.term_sig as u32, &mut buf), b"\n");
    fdprint!(STDOUT_FILENO, b"dumpcore: unimplemented\n");
    0
}

#[cfg(not(test))]
#[panic_handler]
fn my_panic(info: &core::panic::PanicInfo) -> ! {
    fdprint!(STDERR_FILENO, b"=== Panic ===\n");
    if let Some(loc) = info.location() {
        let mut line = [ 0u8; 10 ];
        fdprint!(STDERR_FILENO,
            loc.file().as_bytes(),
            b":", u32toa(loc.line(), &mut line), b"\n");
    }
    unsafe { libc::raise(libc::SIGKILL); }
    loop {}
}

#[cfg(test)]
mod unit_tests {
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
        let mut b = [ 0u8; 10 ];
        let s = misc::u32toa(1234, &mut b);
        assert!(s == b"1234");
        let mut pat: [ u8; 6 ] = [ b's', b'l', b'i', b'c', b'e', 0 ];
        let s = misc::slice_from_c_str(pat.as_mut_ptr());
        assert!(s == b"slice");
    }
}

