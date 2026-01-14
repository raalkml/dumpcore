#![macro_use]

extern crate libc;
use misc::{u64toa, u32toa};

#[cold]
pub fn fdput_c_str(fd: i32, arg: *const libc::c_char) {
    if !arg.is_null() {
        unsafe {
            libc::write(fd, arg as *const libc::c_void, libc::strlen(arg));
        }
    }
}

pub fn fdput_bytes(fd: i32, arg: &[u8]) {
    unsafe {
        libc::write(fd, arg.as_ptr() as *const libc::c_void, arg.len());
    }
}

pub fn fdput_c_chars(fd: i32, arg: &[libc::c_char]) {
    unsafe {
        libc::write(fd, arg.as_ptr() as *const libc::c_void, arg.len());
    }
}

pub trait FdPuts { fn fdputs(self, fd: i32); }

impl FdPuts for &str {
    fn fdputs(self, fd: i32) { fdput_bytes(fd, self.as_bytes()) }
}
impl FdPuts for &[u8] {
    fn fdputs(self, fd: i32) { fdput_bytes(fd, self) }
}
impl FdPuts for &[libc::c_char] {
    fn fdputs(self, fd: i32) { fdput_c_chars(fd, self) }
}
impl FdPuts for *const libc::c_char {
    fn fdputs(self, fd: i32) {
        if self.is_null() {
            fdput_bytes(fd, b"(null)")
        } else {
            fdput_c_str(fd, self)
        }
    }
}
impl FdPuts for i32 {
    fn fdputs(self, fd: i32) {
        let v;
        if self < 0 {
            v = -self;
            fdput_bytes(fd, b"-");
        } else {
            v = self;
        }
        fdput_bytes(fd, u32toa(v as u32, &mut [ 0u8; 10 ]))
    }
}
impl FdPuts for u32 {
    fn fdputs(self, fd: i32) {
        fdput_bytes(fd, u32toa(self, &mut [ 0u8; 10 ]))
    }
}
impl FdPuts for i64 {
    fn fdputs(self, fd: i32) {
        let v;
        if self < 0 {
            v = -self;
            fdput_bytes(fd, b"-");
        } else {
            v = self;
        }
        fdput_bytes(fd, u64toa(v as u64, &mut [ 0u8; 24 ]))
    }
}
impl FdPuts for u64 {
    fn fdputs(self, fd: i32) {
        fdput_bytes(fd, u64toa(self, &mut [ 0u8; 24 ]))
    }
}
impl FdPuts for isize {
    fn fdputs(self, fd: i32) {
        let v;
        if self < 0 {
            v = -self;
            fdput_bytes(fd, b"-");
        } else {
            v = self;
        }
        fdput_bytes(fd, u64toa(v as u64, &mut [ 0u8; 24 ]))
    }
}
impl FdPuts for usize {
    fn fdputs(self, fd: i32) {
        let mut buf = [ 0u8; 20 ];
        static HEX: &[u8; 16] = b"0123456789abcdef";
        let mut u = self;
        let mut i = 19;
        loop {
            buf[i] = HEX[u & 0x0F];
            u >>= 4;
            if u == 0 || i == 0 { break; }
            i -= 1;
        }
        fdput_bytes(fd, b"0x");
        fdput_bytes(fd, &buf[i..])
    }
}
impl FdPuts for u8 {
    fn fdputs(self, fd: i32) { fdput_bytes(fd, &[ self ]) }
}
impl FdPuts for i8 {
    fn fdputs(self, fd: i32) { fdput_bytes(fd, &[ self as u8 ]) }
}

#[macro_export]
macro_rules! fdprint {
    ($fd:expr, $s:expr) => ( ($s).fdputs($fd) );
    ($fd:expr, $s:expr, $($es:expr),+) => (
        ($s).fdputs($fd);
        fdprint!($fd, $($es),+)
    )
}
