
//use super::*;
use Buffer;

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

