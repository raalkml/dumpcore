use core::{ptr, slice};

pub struct Buffer {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Buffer {
    #![allow(unused)]

    pub fn new() -> Self { Buffer { ptr: ptr::null_mut(), len: 0 } }
    pub fn from_str(src: &str) -> Self {
        let mut b = Self::new();
        b.strcpy(src);
        b
    }

    pub fn realloc_size(&mut self, space: usize) -> usize {
        // Ensure there is aligned space for at least one byte at the end
        // of the allocated block: for NUL terminator.
        let size = (space + size_of::<usize>()).wrapping_div(size_of::<usize>()) * size_of::<usize>();
        let ptr = unsafe { libc::realloc(self.ptr, size) };
        if ptr.is_null() { panic!("Out of memory") }
        self.ptr = ptr;
        self.len = space;
        size
    }
    pub fn realloc(&mut self, space: usize) { self.realloc_size(space); }
    pub fn reserve(&mut self, space: usize) {
        if self.len < space { self.realloc(space); }
    }
    pub fn is_empty(&self) -> bool { self.len == 0 }
    pub fn size(&self) -> usize { self.len }
    pub fn bytecpy(&mut self, src: &[u8]) {
        self.reserve(src.len());
        self.as_bytes_mut()[0..src.len()].copy_from_slice(src);
    }
    pub fn strcpy(&mut self, src: &str) {
        let src = src.as_bytes();
        self.reserve(src.len() + 1);
        let b = self.as_bytes_mut();
        b[0..src.len()].copy_from_slice(src);
        b[src.len()] = 0;
    }
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
    }
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
    }
    pub fn bytez(&self) -> &[u8] {
        unsafe {
            let len = libc::strnlen(self.c_str(), self.len);
            slice::from_raw_parts(self.ptr as *const u8, len)
        }
    }
    pub unsafe fn c_str(&self) -> *const libc::c_char { self.ptr as *const libc::c_char }
    pub unsafe fn c_str_mut(&mut self) -> *mut libc::c_char { self.ptr as *mut libc::c_char }
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

