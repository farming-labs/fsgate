//! Bounded inspection of native x86_64 ELF images, without executing them.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

const HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const MAX_PROGRAM_HEADERS: u16 = 1024;
const MAX_INTERPRETER_SIZE: u64 = 4096;

/// The loader pathname declared by an image, if it has one. This is not
/// authorization to open or execute that pathname.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Image {
    pub(crate) interpreter: Option<PathBuf>,
}

/// Inspects the held file. File-kind and privilege checks belong to the
/// launcher; this is not a complete validation of loadable ELF segments.
pub(crate) fn inspect(image: &File) -> io::Result<Image> {
    let not_elf = || {
        invalid("is not an ELF executable (scripts are not supported); pass a static native binary")
    };
    let mut header = [0u8; HEADER_SIZE];
    image.read_exact_at(&mut header, 0).map_err(|_| not_elf())?;
    if header[..4] != *b"\x7fELF" {
        return Err(not_elf());
    }
    if header[4] != 2 || header[5] != 1 || u16_at(&header, 18) != 62 {
        return Err(invalid(
            "is not a 64-bit x86_64 ELF; the interception profile supports native x86_64 only",
        ));
    }
    if !matches!(u16_at(&header, 16), 2 | 3) {
        return Err(not_elf());
    }
    if header[6] != 1 || u32_at(&header, 20) != 1 || u16_at(&header, 52) != HEADER_SIZE as u16 {
        return Err(invalid(
            "has an unsupported ELF header version or size; pass a native ELF executable",
        ));
    }
    let offset = u64_at(&header, 32);
    let entry_size = u16_at(&header, 54);
    let entries = u16_at(&header, 56);
    if entry_size != PROGRAM_HEADER_SIZE as u16 || entries == 0 || entries > MAX_PROGRAM_HEADERS {
        return Err(invalid(
            "has an unsupported program header table; pass an ELF with 1 to 1024 native program headers",
        ));
    }
    let file_size = image.metadata()?.len();
    let table_size = PROGRAM_HEADER_SIZE * usize::from(entries);
    let truncated_table =
        || invalid("has a truncated program header table; pass a complete ELF executable");
    if !within_file(offset, table_size as u64, file_size) {
        return Err(truncated_table());
    }
    let mut table = vec![0u8; table_size];
    image
        .read_exact_at(&mut table, offset)
        .map_err(|_| truncated_table())?;
    let mut interpreter = None;
    for entry in table.chunks_exact(PROGRAM_HEADER_SIZE) {
        if u32_at(entry, 0) != 3 {
            continue;
        }
        if interpreter.is_some() {
            return Err(invalid(
                "has multiple ELF interpreters; pass an image with at most one PT_INTERP entry",
            ));
        }
        let offset = u64_at(entry, 8);
        let size = u64_at(entry, 32);
        if !(2..=MAX_INTERPRETER_SIZE).contains(&size) {
            return Err(invalid(
                "has an invalid ELF interpreter length; use a pathname of at most 4096 bytes including its NUL terminator",
            ));
        }
        let truncated_interpreter =
            || invalid("has a truncated ELF interpreter; pass a complete ELF executable");
        if !within_file(offset, size, file_size) {
            return Err(truncated_interpreter());
        }
        let mut path = vec![0u8; size as usize];
        image
            .read_exact_at(&mut path, offset)
            .map_err(|_| truncated_interpreter())?;
        if path.pop() != Some(0) || path.contains(&0) || path.first() != Some(&b'/') {
            return Err(invalid(
                "has an invalid ELF interpreter pathname; use one absolute pathname with a final NUL and no embedded NUL",
            ));
        }
        interpreter = Some(PathBuf::from(OsString::from_vec(path)));
    }
    Ok(Image { interpreter })
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn within_file(offset: u64, size: u64, file_size: u64) -> bool {
    offset.checked_add(size).is_some_and(|end| end <= file_size)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed-size ELF field"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed-size ELF field"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;

    fn put16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Only the headers inspected here are modeled; these bytes are never
    /// executed and do not stand in for the launcher's Linux runtime tests.
    fn fixture(interpreters: &[&[u8]]) -> Vec<u8> {
        let entries = interpreters.len() + 1;
        let mut bytes = vec![0u8; HEADER_SIZE + PROGRAM_HEADER_SIZE * entries];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        put16(&mut bytes, 16, 2);
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        put64(&mut bytes, 32, HEADER_SIZE as u64);
        put16(&mut bytes, 52, HEADER_SIZE as u16);
        put16(&mut bytes, 54, PROGRAM_HEADER_SIZE as u16);
        put16(&mut bytes, 56, entries as u16);
        for (index, interpreter) in interpreters.iter().enumerate() {
            let entry = HEADER_SIZE + index * PROGRAM_HEADER_SIZE;
            let offset = bytes.len() as u64;
            put32(&mut bytes, entry, 3);
            put64(&mut bytes, entry + 8, offset);
            put64(&mut bytes, entry + 32, interpreter.len() as u64);
            bytes.extend_from_slice(interpreter);
        }
        put32(
            &mut bytes,
            HEADER_SIZE + interpreters.len() * PROGRAM_HEADER_SIZE,
            1,
        );
        bytes
    }

    fn inspect_bytes(bytes: &[u8]) -> io::Result<Image> {
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        inspect(&file)
    }

    fn refused(bytes: &[u8], message: &str) {
        let error = inspect_bytes(bytes).expect_err("invalid ELF must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains(message), "{error}");
    }

    #[test]
    fn distinguishes_static_executables_and_static_pie_from_dynamic_images() {
        let mut bytes = fixture(&[]);
        assert_eq!(inspect_bytes(&bytes).unwrap().interpreter, None);
        put16(&mut bytes, 16, 3);
        assert_eq!(inspect_bytes(&bytes).unwrap().interpreter, None);
        let mut bytes = fixture(&[b"/lib64/ld-linux-x86-64.so.2\0"]);
        for kind in [2, 3] {
            put16(&mut bytes, 16, kind);
            assert_eq!(
                inspect_bytes(&bytes).unwrap().interpreter,
                Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
            );
        }
    }

    #[test]
    fn preserves_interpreter_path_bytes() {
        let bytes = fixture(&[b"/runtime/\xff/loader\0"]);
        let path = inspect_bytes(&bytes).unwrap().interpreter.unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"/runtime/\xff/loader");
    }

    #[test]
    fn refuses_non_native_images_and_non_executables() {
        refused(b"#!/bin/sh\n", "not an ELF executable");
        for (at, value) in [(0, 0), (4, 1), (5, 2), (18, 40), (16, 1)] {
            let mut bytes = fixture(&[]);
            bytes[at] = value;
            assert_eq!(
                inspect_bytes(&bytes).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn refuses_unknown_versions_and_header_sizes() {
        for (at, value) in [(6, 0), (20, 2), (52, 0)] {
            let mut bytes = fixture(&[]);
            bytes[at] = value;
            refused(&bytes, "header version or size");
        }
    }

    #[test]
    fn bounds_the_program_header_table() {
        for count in [0, 1025, u16::MAX] {
            let mut bytes = fixture(&[]);
            put16(&mut bytes, 56, count);
            refused(&bytes, "unsupported program header table");
        }
        let mut bytes = fixture(&[]);
        put16(&mut bytes, 54, 55);
        refused(&bytes, "unsupported program header table");
        for offset in [65, u64::MAX] {
            let mut bytes = fixture(&[]);
            put64(&mut bytes, 32, offset);
            refused(&bytes, "truncated program header table");
        }
        let mut bytes = fixture(&[]);
        bytes.pop();
        refused(&bytes, "truncated program header table");
    }

    #[test]
    fn refuses_duplicate_or_invalid_interpreter_paths() {
        refused(
            &fixture(&[b"/first\0", b"/second\0"]),
            "multiple ELF interpreters",
        );
        for path in [b"relative\0".as_slice(), b"/no-nul", b"/one\0two\0"] {
            refused(&fixture(&[path]), "interpreter pathname");
        }
        for path in [b"".as_slice(), b"\0"] {
            refused(&fixture(&[path]), "interpreter length");
        }
    }

    #[test]
    fn bounds_interpreter_reads_before_allocating() {
        for size in [0, 1, MAX_INTERPRETER_SIZE + 1, u64::MAX] {
            let mut bytes = fixture(&[b"/loader\0"]);
            put64(&mut bytes, HEADER_SIZE + 32, size);
            refused(&bytes, "interpreter length");
        }
        for offset in [u64::MAX, 1_000_000] {
            let mut bytes = fixture(&[b"/loader\0"]);
            put64(&mut bytes, HEADER_SIZE + 8, offset);
            refused(&bytes, "truncated ELF interpreter");
        }
        let mut bytes = fixture(&[b"/loader\0"]);
        bytes.pop();
        refused(&bytes, "truncated ELF interpreter");
    }

    #[test]
    fn accepts_the_maximum_interpreter_length() {
        let mut path = vec![b'a'; MAX_INTERPRETER_SIZE as usize];
        path[0] = b'/';
        *path.last_mut().unwrap() = 0;
        let parsed = inspect_bytes(&fixture(&[&path]))
            .unwrap()
            .interpreter
            .unwrap();
        assert_eq!(parsed.as_os_str().as_bytes(), &path[..path.len() - 1]);
    }
}
