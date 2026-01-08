#![allow(unused_imports)]
#![allow(dead_code)]

#![macro_use]

extern crate libc;
use libc::{STDOUT_FILENO, STDERR_FILENO};
use core::{mem, slice, ptr};

#[macro_export]
macro_rules! libc_str {
    () => (b"\0".as_ptr() as *const libc::c_char);
    ($($es:expr),+) => ( concat!($($es),+, "\0").as_ptr() as *const libc::c_char );
}

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

pub fn error(message: &[u8], arg: &[u8]) {
    fdprint!(STDERR_FILENO, message, b": ", arg, b"\n");
}

pub fn slice_from_c_str<'a, T>(c: *const T) -> &'a [u8] {
    unsafe {
        slice::from_raw_parts(c as *const u8, libc::strlen(c as *const libc::c_char))
    }
}

pub fn slice_from_c_str_mut<'a, T>(c: *mut T) -> &'a [u8] {
    unsafe {
        slice::from_raw_parts_mut(c as *mut u8, libc::strlen(c as *const libc::c_char))
    }
}

pub fn c_str_of<'a>(s: &'a [u8]) -> *const libc::c_char {
    s.as_ptr() as *const libc::c_char
}

pub fn c_str_of_mut<'a>(s: &'a mut [u8]) -> *mut libc::c_char {
    s.as_mut_ptr() as *mut libc::c_char
}

pub struct Buffer {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Buffer {
    pub fn new() -> Self { Buffer { ptr: ptr::null_mut(), len: 0 } }
    pub fn from_str(src: &str) -> Self {
        let mut b = Buffer { ptr: ptr::null_mut(), len: 0 };
        b.strcpy(src);
        b
    }
    pub fn realloc(&mut self, space: usize) {
        let ptr = unsafe { libc::realloc(self.ptr, space) };
        if ptr.is_null() { panic!("Out of memory") }
        self.ptr = ptr;
        self.len = space;
    }
    pub fn reserve(&mut self, space: usize) {
        if self.len < space { self.realloc(space); }
    }
    pub fn strcpy(&mut self, src: &str) {
        self.reserve(src.len() + 1);
        let s = unsafe {
            core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len)
        };
        s[0..src.len()].copy_from_slice(src.as_bytes());
        s[src.len()] = 0;
    }
    pub unsafe fn c_str(&self) -> *const libc::c_char { self.ptr as *const libc::c_char }
    pub unsafe fn c_str_mut(&mut self) -> *mut libc::c_char { self.ptr as *mut libc::c_char }
    pub fn bytez(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self.ptr as *const u8, libc::strnlen(self.c_str(), self.len))
        }
    }
    pub unsafe fn as_ptr<T>(&mut self) -> *const T { self.ptr as *const T }
    pub unsafe fn as_mut_ptr<T>(&mut self) -> *mut T { self.ptr as *mut T }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe { libc::free(self.ptr) }
    }
}
impl core::ops::Index<core::ops::RangeFull> for Buffer {
    type Output = [u8];
    fn index(&self, _index: core::ops::RangeFull) -> &Self::Output {
        unsafe {
            core::slice::from_raw_parts(self.ptr as *const u8, self.len)
        }
    }
}
impl core::ops::IndexMut<core::ops::RangeFull> for Buffer {
    fn index_mut(&mut self, _index: core::ops::RangeFull) -> &mut Self::Output {
        unsafe {
            core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len)
        }
    }
}
impl core::ops::Index<core::ops::RangeFrom<usize>> for Buffer {
    type Output = [u8];
    fn index(&self, index: core::ops::RangeFrom<usize>) -> &Self::Output {
        let start = if index.start < self.len { index.start } else { self.len };
        unsafe {
            core::slice::from_raw_parts((self.ptr as *const u8).add(start), self.len - start)
        }
    }
}
impl core::ops::IndexMut<core::ops::RangeFrom<usize>> for Buffer {
    fn index_mut(&mut self, index: core::ops::RangeFrom<usize>) -> &mut Self::Output {
        let start = if index.start < self.len { index.start } else { self.len };
        unsafe {
            core::slice::from_raw_parts_mut((self.ptr as *mut u8).add(start), self.len - start)
        }
    }
}
impl core::ops::Index<core::ops::RangeTo<usize>> for Buffer {
    type Output = [u8];
    fn index(&self, index: core::ops::RangeTo<usize>) -> &Self::Output {
        let end = if index.end < self.len { index.end } else { self.len };
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, end) }
    }
}
impl core::ops::IndexMut<core::ops::RangeTo<usize>> for Buffer {
    fn index_mut(&mut self, index: core::ops::RangeTo<usize>) -> &mut Self::Output {
        let end = if index.end < self.len { index.end } else { self.len };
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u8, end) }
    }
}
impl core::ops::Index<core::ops::Range<usize>> for Buffer {
    type Output = [u8];
    fn index(&self, index: core::ops::Range<usize>) -> &Self::Output {
        let start = if index.start < self.len { index.start } else { self.len };
        let mut end = if index.end < self.len { index.end } else { self.len };
        if end < start { end = start; }
        unsafe {
            core::slice::from_raw_parts((self.ptr as *const u8).add(start), end - start)
        }
    }
}
impl core::ops::IndexMut<core::ops::Range<usize>> for Buffer {
    fn index_mut(&mut self, index: core::ops::Range<usize>) -> &mut Self::Output {
        let start = if index.start < self.len { index.start } else { self.len };
        let mut end = if index.end < self.len { index.end } else { self.len };
        if end < start { end = start; }
        unsafe {
            core::slice::from_raw_parts_mut((self.ptr as *mut u8).add(start), end - start)
        }
    }
}
impl core::ops::Index<usize> for Buffer {
    type Output = u8;
    fn index(&self, index: usize) -> &Self::Output {
        if index < self.len { unsafe { &*(self.ptr as *const u8).add(index)} }
        else { panic!("index out-of-bounds") }
    }
}

impl core::ops::IndexMut<usize> for Buffer {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if index < self.len { unsafe { &mut *(self.ptr as *mut u8).add(index)} }
        else { panic!("index out-of-bounds") }
    }
}

pub fn u64toa(u: u64, s: &mut [u8]) -> &mut [u8] {
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

pub fn u32toa(u: u32, s: &mut [u8]) -> &mut [u8] { u64toa(u as u64, s) }

pub fn c_char_to_long(p: *const libc::c_char, base: libc::c_int) -> libc::c_long {
    if p.is_null() { 0 }
    else {
        unsafe {
            libc::strtol(p, ptr::null_mut(), base)
        }
    }
}


