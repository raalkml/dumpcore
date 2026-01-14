extern crate libc;
use libc::STDERR_FILENO;
use misc::*;
use buffer::*;

pub struct Config {
    pub core_dir: *const libc::c_char,
    pub core_user: *const libc::c_char,
    pub core_group: *const libc::c_char,
    pub core_autoclean: bool,
    pub gdb: *const libc::c_char,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            core_dir: libc_str!("/var/dumpcore"),
            core_user: libc_str!("root"),
            core_group: libc_str!("root"),
            core_autoclean: false,
            gdb: libc_str!("/usr/bin/gdb"),
        }
    }
}

struct Prefix {
    part: &'static [u8],
    next: &'static Prefix,
    down: &'static Prefix,
}

#[cfg(test)]
fn dump_prefix_tree(pos: &'static Prefix, depth: isize, list: bool) {
    for _ in 0..depth { fdprint!(STDERR_FILENO, " "); }
    if core::ptr::eq(pos.down, &BOTTOM) {
        fdprint!(STDERR_FILENO, "...", pos.part, "\n");
    } else {
        fdprint!(STDERR_FILENO, pos.part, "{\n");
        dump_prefix_tree(pos.down, depth + 1, true);
        for _ in 0..depth { fdprint!(STDERR_FILENO, " "); }
        fdprint!(STDERR_FILENO, "}\n");
    }
    if list {
        let mut pos = pos.next;
        while !core::ptr::eq(pos, &BOTTOM) {
            dump_prefix_tree(pos, depth, false);
            pos = pos.next;
        }
    }
}
#[cfg(test)]
pub fn dump_syntax() {
    dump_prefix_tree(&CORE_, 0, true);
}


struct Parser {
    prefix: &'static Prefix,
    off: usize,
    state: i32,
    value: Buffer,
    value_len: usize,
}

static BOTTOM    : Prefix = Prefix { part: b"#", next: &BOTTOM, down: &BOTTOM };
static GDB       : Prefix = Prefix { part: b"GDB", next: &BOTTOM, down: &BOTTOM };
static AUTOCLEAN : Prefix = Prefix { part: b"AUTOCLEAN", next: &BOTTOM, down: &BOTTOM };
static GROUP     : Prefix = Prefix { part: b"GROUP", next: &AUTOCLEAN, down: &BOTTOM };
static USER      : Prefix = Prefix { part: b"USER", next: &GROUP, down: &BOTTOM };
static DIR       : Prefix = Prefix { part: b"DIR", next: &USER, down: &BOTTOM };
static CORE_     : Prefix = Prefix { part: b"CORE_", next: &GDB, down: &DIR };

impl Parser {
    const TEXT : i32     = 0;
    const COMMENT: i32   = 1;
    const KEY: i32       = 2;
    const VALUE: i32     = 3;
    const FAIL: i32      = 4;
    const KEY_SPACE: i32 = 5;
    fn reset(&mut self) {
        self.prefix = &CORE_;
        self.off = 0;
    }
    fn fail(&mut self) {
        self.reset();
        self.state = Self::FAIL;
    }
    fn value_append(&mut self, ch: u8) {
        self.value.reserve(self.value_len + 1);
        self.value[..][self.value_len] = ch;
        self.value_len += 1;
    }
    fn dup_value(&mut self) -> *mut libc::c_char {
        unsafe { libc::strndup(self.value.c_str(), self.value_len) }
    }
}

pub fn load_config(file_name: &'static str) -> Config {
    let config_file = Buffer::from_str(file_name);
    let fd = unsafe { libc::open(config_file.c_str(), libc::O_RDONLY | libc::O_NOCTTY, 0) };
    if fd != -1 {
        let mut configuration = Buffer::new();
        let mut ret = -1;
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st ) } == 0 {
            let file_size = st.st_size as usize;
            configuration.reserve(file_size);
            ret = unsafe { libc::read(fd, configuration[..].as_mut_ptr() as *mut libc::c_void, file_size) };
        }
        unsafe { libc::close(fd); }
        if ret >= 0 {
            return parse_config(&configuration[..]);
        }
    } else {
        let errno = unsafe { libc::__errno_location().read() };
        fdprint!(STDERR_FILENO, file_name, ": ", unsafe { libc::strerror(errno) }, "\n" );
    }
    Config::default()
}

pub fn parse_config(configuration: &[u8]) -> Config {
    assert!(!core::ptr::eq(&CORE_, &BOTTOM));
    assert!(core::ptr::eq(GDB.next, &BOTTOM));

    let mut config = Config::default();
    let mut parser = Parser {
        prefix: &CORE_,
        off: 0,
        state: Parser::TEXT,
        value: Buffer::new(),
        value_len: 0,
    };
    for ch in configuration {
        if parser.state == Parser::COMMENT || parser.state == Parser::FAIL {
            if *ch == b'\n' { parser.state = Parser::TEXT; }
            continue;
        }
        if parser.state == Parser::KEY_SPACE {
            if b' ' == *ch || b'\t' == *ch { continue; }
            if b'=' == *ch || b'\n' == *ch { parser.state = Parser::KEY; }
            else { parser.fail(); continue; }
        }
        if parser.state == Parser::VALUE {
            if *ch == b'\n' {
                // VALUE: (collected)
                if core::ptr::eq(parser.prefix, &DIR) {
                    config.core_dir = parser.dup_value();
                } else if core::ptr::eq(parser.prefix, &USER) {
                    config.core_user = parser.dup_value();
                } else if core::ptr::eq(parser.prefix, &GROUP) {
                    config.core_group = parser.dup_value();
                } else if core::ptr::eq(parser.prefix, &AUTOCLEAN) {
                    let value = &parser.value[..][..parser.value_len];
                    config.core_autoclean =
                        value == b"1" || value == b"Y" || value == b"y" || value == b"t" ||
                        value == b"YES" || value == b"Yes" || value == b"yes" ||
                        value == b"TRUE" || value == b"True" || value == b"true";
                } else if core::ptr::eq(parser.prefix, &GDB) {
                    config.gdb = parser.dup_value();
                }
                parser.value_len = 0;
                parser.state = Parser::TEXT;
                parser.reset();
            } else {
                parser.value_append(*ch);
            }
            continue;
        }
        if *ch == b'#' {
            parser.state = Parser::COMMENT;
            continue;
        }
        if parser.state == Parser::TEXT {
            if b' ' == *ch || b'\t' == *ch || b'\n' == *ch { continue; }
            parser.state = Parser::KEY;
        }
        if parser.state == Parser::KEY {
            if b' ' == *ch || b'\t' == *ch {
                parser.state = Parser::KEY_SPACE;
                continue;
            }
            if b'=' == *ch || b'\n' == *ch {
                if parser.off != parser.prefix.part.len() {
                    parser.fail();
                    continue;
                }
                if b'=' == *ch {
                    parser.state = Parser::VALUE;
                } else {
                    // VALUE: TRUE
                    if core::ptr::eq(parser.prefix, &AUTOCLEAN) {
                        config.core_autoclean = true;
                    }
                    parser.state = Parser::TEXT;
                    parser.reset();
                }
                continue;
            }
            if parser.off == parser.prefix.part.len() {
                if core::ptr::eq(parser.prefix.down, &BOTTOM) {
                    parser.fail();
                    continue;
                }
                parser.prefix = parser.prefix.down;
                parser.off = 0;
            }
            if *ch == parser.prefix.part[parser.off] {
                parser.state = Parser::KEY;
                parser.off += 1;
                continue;
            }
            if parser.off > 0 {
                parser.fail();
                continue;
            }
            parser.off = 0;
            while !core::ptr::eq(parser.prefix, &BOTTOM) {
                if *ch == parser.prefix.part[parser.off] { break; }
                parser.prefix = parser.prefix.next;
            }
            if core::ptr::eq(parser.prefix, &BOTTOM) {
                parser.fail();
                continue;
            }
            parser.state = Parser::KEY;
            parser.off += 1;
        }
    }
    config
}
