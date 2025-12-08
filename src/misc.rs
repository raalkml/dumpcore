#![allow(unused_imports)]
#![allow(dead_code)]

#![macro_use]

extern crate libc;
use libc::{STDOUT_FILENO, STDERR_FILENO};
use core::{mem, slice, ptr};

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

#[macro_export]
macro_rules! fdprint {
    ($fd:expr, $s:expr) => ( $crate::misc::fdput_bytes($fd, $s) );
    ($fd:expr, $s:expr, $($es:expr),+) => (
        $crate::misc::fdput_bytes($fd, $s);
        fdprint!($fd, $($es),+)
    )
}

pub fn error(message: &[u8], arg: &[u8]) {
    fdprint!(STDERR_FILENO, message, b": ", arg, b"\n");
}

pub fn slice_from_c_str<'a, T>(c: *mut T) -> &'a [u8] {
    unsafe {
        slice::from_raw_parts_mut(c as *mut u8, libc::strlen(c as *const libc::c_char))
    }
}

pub struct Buffer {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Buffer {
    pub fn new() -> Self { Buffer { ptr: ptr::null_mut(), len: 0 } }
    pub fn reserve(&mut self, space: usize) {
        if self.len < space {
            let ptr = unsafe { libc::realloc(self.ptr, space) };
            if ptr.is_null() { panic!("Out of memory") }
            self.ptr = ptr;
            self.len = space;
        }
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe { libc::free(self.ptr) }
    }
}
impl core::ops::Index<core::ops::RangeFull> for Buffer {
    type Output = [u8];
    fn index(&self, _index: core::ops::RangeFull) -> &Self::Output { unimplemented!() }
}
impl core::ops::IndexMut<core::ops::RangeFull> for Buffer {
    fn index_mut(&mut self, _index: core::ops::RangeFull) -> &mut Self::Output {
        unsafe {
            core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len)
        }
    }
}

pub fn u32toa(u: u32, s: &mut [u8]) -> &mut [u8] {
    assert!(s.len() >= 10);
    const DEC : &[u8; 10] = b"0123456789";
    let mut pos = s.len();
    let mut u = u;
    for e in s.into_iter().rev() {
        pos -= 1;
        *e = DEC[(u % 10) as usize];
        u /= 10;
        if u == 0 { break }
    }
    //assert!(pos < s.len());
    //&mut s[pos ..]
    unsafe { s.get_unchecked_mut(pos ..) }
}

pub fn c_char_to_long(p: *const libc::c_char, base: libc::c_int) -> libc::c_long {
    if p.is_null() { 0 }
    else {
        unsafe {
            libc::strtol(p, ptr::null_mut(), base)
        }
    }
}

