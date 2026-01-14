#![allow(unused_imports)]
#![allow(dead_code)]
#![macro_use]

use core::{mem, slice, ptr};

#[macro_export]
macro_rules! libc_str {
    () => (b"\0".as_ptr() as *const libc::c_char);
    ($($es:expr),+) => ( concat!($($es),+, "\0").as_ptr() as *const libc::c_char );
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


