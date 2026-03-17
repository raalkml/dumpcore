use super::*;
use Buffer;

#[test]
fn verify_std() {
    let a = vec!{1, 2, 3};
    assert_eq!(a, &[1,2,3]);
}

#[test]
fn verify_buffer() {
    let mut b = Buffer::new();
    assert!(b.is_empty());
    assert!(b.realloc_size(0) == size_of::<usize>());
    assert!(b.realloc_size(1) == size_of::<usize>());
    assert!(b.realloc_size(size_of::<usize>()) == 2 * size_of::<usize>());
    b.reserve(1024);
    let s = &mut b[..];
    assert!(s.len() == 1024);
    let s = &b[..];
    assert!(s.len() == 1024);
    b.bytecpy(b"ABC");
    assert!(&b[0..3] == b"ABC");
    b.strcpy("ABC");
    assert!(&b[0..4] == b"ABC\0");

    let b = Buffer::from_str("ABC");
    assert!(b.size() >= 4);
    assert!(b.as_bytes() == b"ABC\0");
    assert!(b.bytez() == b"ABC");
}

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


