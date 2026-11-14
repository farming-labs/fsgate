//! The access list macOS keeps beside a file's mode bits, read for
//! [`check_socket_path`](super::check_socket_path). Neither `std`, `rustix`,
//! nor `libc` wraps it.
//!
//! # Safety contract
//!
//! `acl_get_link_np` reads a NUL-terminated path that outlives the call and
//! returns a list this module owns. [`List`] holds it and passes it to
//! `acl_free` exactly once, when dropped. `acl_get_entry`,
//! `acl_get_tag_type`, and `acl_get_permset_mask_np` read that list and
//! write only the out-parameter they are given, a local that outlives the
//! call. An entry they return points into the list and is used only while
//! the [`List`] is alive. Nothing else in the broker binary uses `unsafe`
//! on macOS.

#![allow(unsafe_code)]

use std::ffi::{CString, c_char, c_int, c_void};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

// From `<sys/acl.h>`.
const ACL_TYPE_EXTENDED: c_int = 0x100;
const ACL_FIRST_ENTRY: c_int = 0;
const ACL_NEXT_ENTRY: c_int = -1;
const ACL_EXTENDED_ALLOW: c_int = 1;
const ACL_ADD_FILE: u64 = 1 << 2;
const ACL_DELETE: u64 = 1 << 4;
const ACL_ADD_SUBDIRECTORY: u64 = 1 << 5;
const ACL_DELETE_CHILD: u64 = 1 << 6;
const ACL_WRITE_SECURITY: u64 = 1 << 12;
const ACL_CHANGE_OWNER: u64 = 1 << 13;

/// Rights that let their holder put another entry where one was: add or
/// delete an entry, delete or rename the directory, or change its access
/// list, mode, or owner.
const CHANGES_ENTRIES: u64 = ACL_ADD_FILE
    | ACL_DELETE
    | ACL_ADD_SUBDIRECTORY
    | ACL_DELETE_CHILD
    | ACL_WRITE_SECURITY
    | ACL_CHANGE_OWNER;

unsafe extern "C" {
    fn acl_get_link_np(path: *const c_char, kind: c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
    fn acl_free(object: *mut c_void) -> c_int;
}

/// A list `acl_get_link_np` returned, freed when dropped.
struct List(*mut c_void);

impl Drop for List {
    fn drop(&mut self) {
        // SAFETY: the list came from `acl_get_link_np`, and only this drop
        // frees it. See the module contract.
        unsafe { acl_free(self.0) };
    }
}

/// Whether `path`'s access list has an entry that allows anyone, whoever it
/// names, a right that could change the directory's entries. Entries that
/// deny never do. Symlinks are not followed.
pub(super) fn lets_anyone_change_entries(path: &Path) -> io::Result<bool> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `path` is NUL-terminated and outlives the call. See the module
    // contract.
    let list = unsafe { acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED) };
    if list.is_null() {
        let err = io::Error::last_os_error();
        // `ENOENT` for a file that exists means it has no access list.
        return match err.raw_os_error() {
            Some(code) if code == rustix::io::Errno::NOENT.raw_os_error() => Ok(false),
            _ => Err(err),
        };
    }
    let list = List(list);
    let mut which = ACL_FIRST_ENTRY;
    loop {
        let mut entry = ptr::null_mut();
        // SAFETY: `list` is alive and `entry` is a local. See the module
        // contract. It fails past the last entry.
        if unsafe { acl_get_entry(list.0, which, &mut entry) } != 0 {
            return Ok(false);
        }
        which = ACL_NEXT_ENTRY;
        let (mut tag, mut mask) = (0, 0);
        // SAFETY: `entry` points into `list`, which is alive, and `tag` and
        // `mask` are locals. See the module contract.
        let read = unsafe {
            acl_get_tag_type(entry, &mut tag) == 0 && acl_get_permset_mask_np(entry, &mut mask) == 0
        };
        if !read {
            return Err(io::Error::last_os_error());
        }
        if tag == ACL_EXTENDED_ALLOW && mask & CHANGES_ENTRIES != 0 {
            return Ok(true);
        }
    }
}
