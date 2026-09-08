use super::*;
use Buffer;

#[test]
fn verify_utoa() {
    let mut b = [ 0u8; 10 ];
    let s = misc::u32toa(1234, &mut b);
    assert!(s == b"1234");
}

#[test]
fn verify_misc() {
    fdprint!(STDOUT_FILENO, b"Test STDOUT\n");
    fdprint!(STDERR_FILENO, b"Test", b"error(prefix, text)");
    let mut pat: [ u8; 6 ] = [ b's', b'l', b'i', b'c', b'e', 0 ];
    let s = misc::slice_from_c_str(pat.as_mut_ptr());
    assert!(s == b"slice");
}

#[test]
fn verify_config() {
    use config::{parse_config, dump_syntax};
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

#[test]
fn check_redirect_fd() {
    extern crate libc;
    use libc::{STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
    let core_file = Buffer::from_str("__redirect_fd_test__\0discard");
    let fd = unsafe {
        libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_WRONLY)
    };
    assert!(fd != -1);
    let fname = redirect_fd(fd, core_file.bytez(), ".tmp");
    assert!(&fname[..25] == b"__redirect_fd_test__.tmp\0");
    let ret = unsafe { libc::unlink(fname.c_str()) };
    assert!(ret == 0);
    unsafe { libc::close(fd) };
}

